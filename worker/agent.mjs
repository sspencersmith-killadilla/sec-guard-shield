#!/usr/bin/env node
/**
 * GovShield scanner worker.
 *
 * Long-polls the GovShield control plane for queued assessments, runs the real
 * open-source scanners inside this container, and posts normalised findings
 * back. The control plane performs KEV/EPSS/NVD correlation and control
 * mapping; this agent is responsible only for execution and normalisation.
 */
import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { normalise } from "./normalize.mjs";

const BASE = (process.env.GOVSHIELD_URL ?? "").replace(/\/$/, "");
const KEY = process.env.GOVSHIELD_WORKER_KEY ?? "";
const POLL_MS = Number(process.env.GOVSHIELD_POLL_MS ?? 5000);
const VERSION = "1.0.0";

if (!BASE || !KEY) {
  console.error("GOVSHIELD_URL and GOVSHIELD_WORKER_KEY are required.");
  process.exit(1);
}

let shuttingDown = false;
process.on("SIGTERM", () => {
  shuttingDown = true;
});
process.on("SIGINT", () => {
  shuttingDown = true;
});

/* ------------------------------ control plane ----------------------------- */

async function post(path, body) {
  const res = await fetch(`${BASE}/api/public/hooks/worker/${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", "x-govshield-worker-key": KEY },
    body: JSON.stringify(body ?? {}),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${path} failed [${res.status}]: ${text}`);
  return text ? JSON.parse(text) : {};
}

const progress = (scanId, stage, message, pct) =>
  post("progress", { scanId, stage, message, progress: pct }).catch((err) =>
    console.error("progress failed:", err.message),
  );

/* -------------------------------- processes ------------------------------- */

/** Runs a command, capturing stdout. Never throws on a non-zero exit: most
 *  scanners use exit codes to signal "findings present". */
function run(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, {
      cwd: opts.cwd,
      env: { ...process.env, ...(opts.env ?? {}) },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), opts.timeoutMs ?? 15 * 60_000);
    child.stdout.on("data", (d) => {
      stdout += d;
    });
    child.stderr.on("data", (d) => {
      stderr += d;
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve({ code: -1, stdout: "", stderr: err.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

async function toolVersion(cmd, args) {
  const { stdout, stderr } = await run(cmd, args, { timeoutMs: 30_000 });
  const line = (stdout || stderr).split("\n").find((l) => l.trim()) ?? "";
  return line.trim().slice(0, 60);
}

async function readJson(path) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return null;
  }
}

/* -------------------------------- pipelines -------------------------------- */

async function cloneRepo(url, dir, scanId) {
  await progress(scanId, "Fetching source", `Shallow clone of ${url}`, 10);
  const { code, stderr } = await run("git", ["clone", "--depth", "1", url, dir], {
    timeoutMs: 5 * 60_000,
  });
  if (code !== 0) throw new Error(`git clone failed: ${stderr.slice(0, 400)}`);
}

async function runSast(job, dir) {
  const findings = [];
  const versions = {};
  const wants = (m) => job.modules.includes(m);

  await cloneRepo(job.targetValue, dir, job.id);

  if (wants("secrets")) {
    await progress(job.id, "Secret detection", "gitleaks scanning working tree and history", 25);
    versions.gitleaks = await toolVersion("gitleaks", ["version"]);
    const out = join(dir, "..", "gitleaks.json");
    await run("gitleaks", ["detect", "--source", dir, "--report-format", "json", "--report-path", out, "--exit-code", "0"], {
      timeoutMs: 10 * 60_000,
    });
    findings.push(...normalise.gitleaks(await readJson(out), dir));
  }

  if (wants("owasp")) {
    await progress(job.id, "Static analysis", "semgrep OWASP Top 10 + security-audit rulesets", 45);
    versions.semgrep = await toolVersion("semgrep", ["--version"]);
    const { stdout } = await run(
      "semgrep",
      ["scan", "--config", "p/owasp-top-ten", "--config", "p/security-audit", "--json", "--quiet", "--metrics", "off", dir],
      { timeoutMs: 20 * 60_000 },
    );
    findings.push(...normalise.semgrep(safeParse(stdout), dir));
  }

  if (wants("deps") || wants("kev")) {
    await progress(job.id, "Dependency analysis", "trivy filesystem SCA against the lockfiles", 65);
    versions.trivy = await toolVersion("trivy", ["--version"]);
    const out = join(dir, "..", "trivy-fs.json");
    await run("trivy", ["fs", "--scanners", "vuln", "--format", "json", "--output", out, "--quiet", dir], {
      timeoutMs: 15 * 60_000,
    });
    findings.push(...normalise.trivy(await readJson(out), dir));
  }

  if (wants("misconfig")) {
    await progress(job.id, "Configuration review", "checkov policy pack over repo IaC", 80);
    versions.checkov = await toolVersion("checkov", ["--version"]);
    const { stdout } = await run("checkov", ["-d", dir, "-o", "json", "--compact", "--quiet"], {
      timeoutMs: 15 * 60_000,
    });
    findings.push(...normalise.checkov(safeParse(stdout), dir));
  }

  return { findings, versions };
}

async function runIac(job, dir) {
  const findings = [];
  const versions = {};
  await cloneRepo(job.targetValue, dir, job.id);

  await progress(job.id, "Policy evaluation", "checkov across Terraform/CloudFormation/Kubernetes", 35);
  versions.checkov = await toolVersion("checkov", ["--version"]);
  const { stdout } = await run("checkov", ["-d", dir, "-o", "json", "--compact", "--quiet"], {
    timeoutMs: 15 * 60_000,
  });
  findings.push(...normalise.checkov(safeParse(stdout), dir));

  await progress(job.id, "Misconfiguration scan", "trivy config rules", 70);
  versions.trivy = await toolVersion("trivy", ["--version"]);
  const out = join(dir, "..", "trivy-config.json");
  await run("trivy", ["config", "--format", "json", "--output", out, "--quiet", dir], {
    timeoutMs: 10 * 60_000,
  });
  findings.push(...normalise.trivyConfig(await readJson(out), dir));

  return { findings, versions };
}

async function runSbom(job, dir) {
  const findings = [];
  const versions = {};

  await progress(job.id, "Generating SBOM", `syft inventory of ${job.targetValue}`, 25);
  versions.syft = await toolVersion("syft", ["version"]);
  const sbomPath = join(dir, "sbom.spdx.json");
  await run("syft", [job.targetValue, "-o", `spdx-json=${sbomPath}`, "-q"], { timeoutMs: 15 * 60_000 });
  const sbom = await readJson(sbomPath);
  const components = sbom?.packages?.length ?? 0;

  await progress(job.id, "Image vulnerability scan", `trivy over ${components} components`, 60);
  versions.trivy = await toolVersion("trivy", ["--version"]);
  const out = join(dir, "trivy-image.json");
  const { code, stderr } = await run(
    "trivy",
    ["image", "--scanners", "vuln", "--format", "json", "--output", out, "--quiet", job.targetValue],
    { timeoutMs: 20 * 60_000 },
  );
  if (code !== 0 && !(await readJson(out))) {
    throw new Error(`trivy image failed: ${stderr.slice(0, 400)}`);
  }
  findings.push(...normalise.trivy(await readJson(out), job.targetValue));
  findings.push(...normalise.sbomInventory(sbom, job.targetValue));

  return { findings, versions };
}

async function runDast(job, dir) {
  const findings = [];
  const versions = {};

  await progress(job.id, "Transport inspection", "TLS and security header baseline", 20);
  findings.push(...(await normalise.httpBaseline(job.targetValue)));

  await progress(job.id, "Active web scan", "nuclei templates (OWASP, exposures, CVEs)", 50);
  versions.nuclei = await toolVersion("nuclei", ["-version"]);
  const out = join(dir, "nuclei.jsonl");
  await run(
    "nuclei",
    [
      "-target", job.targetValue,
      "-jsonl-export", out,
      "-severity", "low,medium,high,critical",
      "-rate-limit", "20",
      "-timeout", "10",
      "-silent",
      "-disable-update-check",
    ],
    { timeoutMs: 25 * 60_000 },
  );
  const jsonl = await readFile(out, "utf8").catch(() => "");
  findings.push(...normalise.nuclei(jsonl, job.targetValue));

  return { findings, versions };
}

function safeParse(text) {
  try {
    return JSON.parse(text);
  } catch {
    const start = text.indexOf("{");
    if (start >= 0) {
      try {
        return JSON.parse(text.slice(start));
      } catch {
        return null;
      }
    }
    return null;
  }
}

const PIPELINES = { sast: runSast, iac: runIac, sbom: runSbom, dast: runDast };

/* ---------------------------------- loop ---------------------------------- */

async function execute(job) {
  console.log(`[${job.id}] ${job.targetType} → ${job.targetValue}`);
  const work = await mkdtemp(join(tmpdir(), "govshield-"));
  const dir = join(work, "target");
  try {
    const pipeline = PIPELINES[job.targetType];
    if (!pipeline) throw new Error(`Unsupported target type: ${job.targetType}`);

    await progress(job.id, "Preparing workspace", "Isolated scratch directory created", 5);
    const { findings, versions } = await pipeline(job, dir);

    await progress(job.id, "Correlating", `${findings.length} raw findings sent for enrichment`, 95);
    const res = await post("result", {
      scanId: job.id,
      ok: true,
      findings,
      toolVersions: versions,
    });
    console.log(`[${job.id}] complete · ${res.findings} findings · posture ${res.posture}%`);
  } catch (err) {
    console.error(`[${job.id}] failed:`, err.message);
    await post("result", { scanId: job.id, ok: false, error: err.message }).catch(() => {});
  } finally {
    await rm(work, { recursive: true, force: true }).catch(() => {});
  }
}

async function main() {
  console.log(`GovShield worker ${VERSION} polling ${BASE} every ${POLL_MS}ms`);
  while (!shuttingDown) {
    try {
      const { job } = await post("claim", { version: VERSION });
      if (job) {
        await execute(job);
        continue;
      }
    } catch (err) {
      console.error("claim failed:", err.message);
    }
    await new Promise((r) => setTimeout(r, POLL_MS));
  }
  console.log("Shutting down.");
}

main();
