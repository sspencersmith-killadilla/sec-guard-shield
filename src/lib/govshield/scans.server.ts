/**
 * Server-only scan orchestration: worker authentication, finding normalisation,
 * threat-intelligence enrichment and posture scoring.
 *
 * Never import this from client-reachable module scope.
 */
import { createHash, randomBytes } from "crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";

type Admin = SupabaseClient<Database>;

export type Severity = "Critical" | "High" | "Medium" | "Low";
export type ModuleKey = "owasp" | "misconfig" | "secrets" | "kev" | "deps";
export type TargetType = "dast" | "sast" | "sbom" | "iac";

/** Raw finding as posted by a scanner worker, before enrichment. */
export interface WorkerFinding {
  tool: string;
  ruleId?: string | null;
  title: string;
  severity: Severity;
  module: ModuleKey;
  location: string;
  description: string;
  remediation: string;
  remediationCode?: string | null;
  verification?: string[];
  cve?: string | null;
  cvss31?: number | null;
  cvssVector?: string | null;
  raw?: Record<string, unknown>;
}

const SEVERITY_WEIGHT: Record<Severity, number> = { Critical: 10, High: 6, Medium: 3, Low: 1 };
const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low"];

/** NIST SP 800-53 Rev.5 controls implicated by each finding class. */
const MODULE_CONTROLS: Record<ModuleKey, string[]> = {
  owasp: ["SI-10", "SI-11", "AC-3", "SC-8"],
  misconfig: ["CM-6", "CM-7", "SC-7", "AC-3"],
  secrets: ["IA-5", "SC-12", "SC-28", "AU-9"],
  deps: ["SI-2", "RA-5", "SA-11", "CM-8"],
  kev: ["SI-2", "RA-5", "SI-3"],
};

/** Privacy Framework 1.0 mapping for finding classes that can expose PII. */
const PRIVACY_RULES: { match: RegExp; impact: string; category: string }[] = [
  {
    match: /(ssn|social.security|passport|driver.?s? licen|date.of.birth|dob\b)/i,
    impact: "May expose direct identifiers (SSN, passport, licence) held by the system.",
    category: "CT.DM-P — Data Processing Management",
  },
  {
    match: /(pii|personal data|personally identifiable|gdpr|privacy act)/i,
    impact: "Handles personally identifiable information without adequate safeguards.",
    category: "CT.DP-P — Disassociated Processing",
  },
  {
    match: /(sql.?injection|nosql.?injection|idor|broken access|mass assignment|path traversal)/i,
    impact: "Could allow bulk retrieval of records about individuals.",
    category: "CT.DM-P — Data Processing Management",
  },
  {
    match: /(log|audit).{0,20}(password|token|secret|credential)/i,
    impact: "Sensitive values written to logs create a secondary, weakly controlled data store.",
    category: "CM.AW-P — Data Processing Awareness",
  },
];

/** Crypto-relevant findings carry a FIPS 140-3 validation implication. */
const FIPS_PATTERN =
  /(md5|sha-?1\b|rc4|des\b|3des|ecb mode|tls ?1\.[01]|ssl ?v?[23]|weak cipher|insecure random|math\.random|hardcoded key|self-?signed)/i;

/* --------------------------- worker authentication ------------------------ */

export function hashWorkerKey(secret: string) {
  return createHash("sha256").update(secret).digest("hex");
}

export function mintWorkerKey(workerId: string) {
  const secret = randomBytes(32).toString("base64url");
  return { presented: `${workerId}.${secret}`, hash: hashWorkerKey(secret) };
}

export interface AuthedWorker {
  id: string;
  name: string;
  capabilities: string[];
}

/** Verifies the `x-govshield-worker-key` header. Returns null when invalid. */
export async function authenticateWorker(
  admin: Admin,
  header: string | null,
): Promise<AuthedWorker | null> {
  if (!header) return null;
  const sep = header.indexOf(".");
  if (sep <= 0) return null;
  const workerId = header.slice(0, sep);
  const secret = header.slice(sep + 1);
  if (!secret) return null;

  const { data } = await admin
    .from("scan_workers")
    .select("id, name, capabilities, key_hash, revoked_at")
    .eq("id", workerId)
    .maybeSingle();
  if (!data || data.revoked_at) return null;

  const presented = Buffer.from(hashWorkerKey(secret));
  const stored = Buffer.from(data.key_hash);
  if (presented.length !== stored.length) return null;
  let diff = 0;
  for (let i = 0; i < presented.length; i += 1) diff |= presented[i]! ^ stored[i]!;
  if (diff !== 0) return null;

  await admin
    .from("scan_workers")
    .update({ last_seen_at: new Date().toISOString(), status: "online" })
    .eq("id", workerId);

  return { id: data.id, name: data.name, capabilities: data.capabilities ?? [] };
}

/* ------------------------------- enrichment ------------------------------- */

function normaliseCve(value: string | null | undefined): string | null {
  if (!value) return null;
  const match = /CVE-\d{4}-\d{4,7}/i.exec(value);
  return match ? match[0].toUpperCase() : null;
}

/** Upgrades a CVSS v3.1 base score to an approximate v4.0 equivalent. */
function approximateCvss40(cvss31: number, kev: boolean, epss: number) {
  if (!cvss31) return 0;
  const threatBump = kev ? 0.6 : epss > 0.5 ? 0.4 : epss > 0.1 ? 0.2 : 0;
  return Math.min(10, Math.round((cvss31 + threatBump) * 10) / 10);
}

function severityFromScore(score: number): Severity {
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

export interface EnrichedFinding extends Record<string, unknown> {
  scan_id: string;
  ordinal: number;
  ref: string;
  title: string;
  severity: Severity;
  module: ModuleKey;
  target_type: string;
  tool: string;
  rule_id: string | null;
  cve: string | null;
  kev: boolean;
  kev_due_date: string | null;
  epss: number;
  cvss31: number;
  cvss40: number;
  cvss_vector: string | null;
  nist_controls: string[];
  fedramp_baseline: string;
  fips1403: boolean;
  privacy_impact: string | null;
  privacy_category: string | null;
  location: string;
  description: string;
  remediation: string;
  remediation_code: string | null;
  verification: string[];
  raw: Record<string, unknown>;
}

/**
 * Correlates raw scanner output against the ingested CISA KEV, FIRST EPSS and
 * NIST NVD datasets, then attaches control and privacy crosswalks.
 */
export async function enrichFindings(
  admin: Admin,
  scanId: string,
  targetType: string,
  findings: WorkerFinding[],
): Promise<EnrichedFinding[]> {
  const cves = Array.from(
    new Set(findings.map((f) => normaliseCve(f.cve)).filter((c): c is string => Boolean(c))),
  );

  const [kevRes, epssRes, nvdRes] = await Promise.all([
    cves.length
      ? admin.from("kev_entries").select("cve_id, due_date, known_ransomware").in("cve_id", cves)
      : Promise.resolve({ data: [] as { cve_id: string; due_date: string | null; known_ransomware: string | null }[] }),
    cves.length
      ? admin.from("epss_scores").select("cve_id, epss").in("cve_id", cves)
      : Promise.resolve({ data: [] as { cve_id: string; epss: number }[] }),
    cves.length
      ? admin.from("nvd_cves").select("cve_id, cvss_score, cvss_vector, cwe").in("cve_id", cves)
      : Promise.resolve({ data: [] as { cve_id: string; cvss_score: number | null; cvss_vector: string | null; cwe: string | null }[] }),
  ]);

  const kevMap = new Map((kevRes.data ?? []).map((r) => [r.cve_id, r]));
  const epssMap = new Map((epssRes.data ?? []).map((r) => [r.cve_id, Number(r.epss)]));
  const nvdMap = new Map((nvdRes.data ?? []).map((r) => [r.cve_id, r]));

  const rows = findings.map((f, index) => {
    const cve = normaliseCve(f.cve);
    const kevEntry = cve ? kevMap.get(cve) : undefined;
    const kev = Boolean(kevEntry);
    const epss = (cve ? epssMap.get(cve) : 0) ?? 0;
    const nvd = cve ? nvdMap.get(cve) : undefined;

    const cvss31 = Number(f.cvss31 ?? nvd?.cvss_score ?? 0) || 0;
    const cvss40 = approximateCvss40(cvss31, kev, epss);

    // A KEV listing overrides scanner severity: actively exploited is Critical.
    // Otherwise a published CVSS base score outranks the scanner's own label.
    const severity: Severity = kev
      ? "Critical"
      : cvss31 > 0
        ? severityFromScore(cvss31)
        : SEVERITIES.includes(f.severity)
          ? f.severity
          : "Medium";

    const module: ModuleKey = kev ? "kev" : f.module;
    const controls = new Set(MODULE_CONTROLS[module] ?? []);
    if (kev) MODULE_CONTROLS.deps.forEach((c) => controls.add(c));

    const haystack = `${f.title} ${f.description} ${f.ruleId ?? ""} ${f.location}`;
    const privacy = PRIVACY_RULES.find((p) => p.match.test(haystack));
    const fips = FIPS_PATTERN.test(haystack);
    if (fips) controls.add("SC-13");
    if (privacy) controls.add("PT-2");

    const verification = f.verification?.length
      ? f.verification
      : [
          "Re-run the GovShield assessment against the same target revision.",
          "Confirm the finding no longer appears in the generated OSCAL results.",
        ];

    return {
      scan_id: scanId,
      ordinal: index + 1,
      ref: `GS-${String(index + 1).padStart(4, "0")}`,
      title: f.title.slice(0, 300),
      severity,
      module,
      target_type: targetType,
      tool: f.tool,
      rule_id: f.ruleId ?? null,
      cve,
      kev,
      kev_due_date: kevEntry?.due_date ?? null,
      epss: Math.round(epss * 100000) / 100000,
      cvss31,
      cvss40,
      cvss_vector: f.cvssVector ?? nvd?.cvss_vector ?? null,
      nist_controls: Array.from(controls),
      // Exploited-in-the-wild and crypto failures are tracked at the High baseline.
      fedramp_baseline: kev || severity === "Critical" || fips ? "High" : "Moderate",
      fips1403: fips,
      privacy_impact: privacy?.impact ?? null,
      privacy_category: privacy?.category ?? null,
      location: f.location.slice(0, 500),
      description: f.description.slice(0, 4000),
      remediation: f.remediation.slice(0, 4000),
      remediation_code: f.remediationCode ?? null,
      verification,
      raw: {
        ...(f.raw ?? {}),
        ...(kevEntry?.known_ransomware ? { known_ransomware: kevEntry.known_ransomware } : {}),
        ...(nvd?.cwe ? { cwe: nvd.cwe } : {}),
      },
    } satisfies EnrichedFinding;
  });

  // Highest risk first so GS-0001 is always the most urgent item.
  rows.sort(
    (a, b) =>
      SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity] ||
      b.epss - a.epss ||
      b.cvss31 - a.cvss31,
  );
  return rows.map((row, index) => ({
    ...row,
    ordinal: index + 1,
    ref: `GS-${String(index + 1).padStart(4, "0")}`,
  }));
}

export function computePosture(rows: { severity: Severity }[]) {
  const penalty = rows.reduce((sum, r) => sum + (SEVERITY_WEIGHT[r.severity] ?? 0), 0);
  return Math.max(0, 100 - penalty);
}

export async function appendScanEvent(
  admin: Admin,
  scanId: string,
  stage: string,
  message: string | null,
  progress: number | null,
) {
  await admin.from("scan_events").insert({ scan_id: scanId, stage, message, progress });
}

/** System-actor audit entry (workers have no Supabase user session). */
export async function appendSystemAudit(
  admin: Admin,
  action: string,
  target: string,
  details: Record<string, unknown>,
) {
  await admin.rpc("append_audit_system", {
    _actor: "scan-worker@govshield.system",
    _action: action.slice(0, 120),
    _target: target.slice(0, 200),
    _details: details as never,
  });
}
