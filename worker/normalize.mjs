/**
 * Maps each scanner's native output into the GovShield worker finding shape.
 * Threat correlation (KEV/EPSS/NVD) and control mapping happen server-side.
 */

const rel = (path, root) => (typeof path === "string" ? path.replace(`${root}/`, "").replace(root, "") : "");

function sev(value, fallback = "Medium") {
  const v = String(value ?? "").toUpperCase();
  if (v.startsWith("CRIT")) return "Critical";
  if (v.startsWith("HIGH") || v === "ERROR") return "High";
  if (v.startsWith("MED") || v === "WARNING" || v === "MODERATE") return "Medium";
  if (v.startsWith("LOW") || v === "INFO" || v === "UNKNOWN" || v === "NEGLIGIBLE") return "Low";
  return fallback;
}

export const normalise = {
  gitleaks(report, root) {
    if (!Array.isArray(report)) return [];
    return report.map((r) => ({
      tool: "gitleaks",
      ruleId: r.RuleID ?? null,
      title: `Hardcoded secret: ${r.Description ?? r.RuleID}`,
      severity: "Critical",
      module: "secrets",
      location: `${rel(r.File, root)}:${r.StartLine ?? 0}${r.Commit ? ` @ ${String(r.Commit).slice(0, 8)}` : ""}`,
      description:
        `${r.Description ?? "A credential-shaped value was committed to the repository."} ` +
        `Match entropy ${Number(r.Entropy ?? 0).toFixed(2)}. Any secret in version control must be treated as compromised.`,
      remediation:
        "Revoke and rotate the credential at its source of issue, purge it from history, and move the value into a managed secret store referenced at runtime.",
      remediationCode:
        `# Rotate first, then purge from history\n` +
        `git filter-repo --path ${rel(r.File, root)} --invert-paths\n` +
        `# Reference the rotated value at runtime instead\n` +
        `export API_TOKEN="$(vault kv get -field=token secret/app)"`,
      verification: [
        "Confirm the old credential is rejected by the issuing system.",
        "Re-run the assessment and confirm zero gitleaks findings.",
        "Confirm the secret store audit log records the new value.",
      ],
      raw: { rule: r.RuleID, file: rel(r.File, root), line: r.StartLine, author: r.Author },
    }));
  },

  semgrep(report, root) {
    const results = report?.results ?? [];
    return results.map((r) => {
      const meta = r.extra?.metadata ?? {};
      const owasp = [].concat(meta.owasp ?? []).join(", ");
      const cwe = [].concat(meta.cwe ?? []).join(", ");
      return {
        tool: "semgrep",
        ruleId: r.check_id ?? null,
        title: (meta.shortDescription ?? r.extra?.message ?? r.check_id ?? "Code weakness").slice(0, 200),
        severity: sev(meta.impact ?? r.extra?.severity),
        module: "owasp",
        location: `${rel(r.path, root)}:${r.start?.line ?? 0}`,
        description:
          `${r.extra?.message ?? ""}\n\n` +
          (owasp ? `OWASP: ${owasp}\n` : "") +
          (cwe ? `CWE: ${cwe}\n` : "") +
          (r.extra?.lines ? `Offending code: ${String(r.extra.lines).trim().slice(0, 300)}` : ""),
        remediation:
          meta.fix_regex?.replacement ??
          r.extra?.fix ??
          "Apply the secure pattern recommended by the rule: validate and encode untrusted input at the boundary and use parameterised platform APIs.",
        remediationCode: r.extra?.fix ?? null,
        verification: [
          `Re-run: semgrep --config ${r.check_id?.split(".")[0] ?? "p/owasp-top-ten"} ${rel(r.path, root)}`,
          "Add a regression test covering the untrusted input path.",
        ],
        raw: { cwe, owasp, confidence: meta.confidence, references: meta.references?.slice(0, 3) },
      };
    });
  },

  trivy(report, root) {
    const out = [];
    for (const result of report?.Results ?? []) {
      for (const v of result.Vulnerabilities ?? []) {
        const cvss = v.CVSS ?? {};
        const source = cvss.nvd ?? cvss.redhat ?? Object.values(cvss)[0] ?? {};
        out.push({
          tool: "trivy",
          ruleId: v.VulnerabilityID ?? null,
          title: `${v.PkgName} ${v.InstalledVersion}: ${v.Title ?? v.VulnerabilityID}`.slice(0, 200),
          severity: sev(v.Severity),
          module: "deps",
          location: `${rel(result.Target, root)} → ${v.PkgName}@${v.InstalledVersion}`,
          description: (v.Description ?? "Vulnerable dependency detected.").slice(0, 2000),
          remediation: v.FixedVersion
            ? `Upgrade ${v.PkgName} to ${v.FixedVersion} or later.`
            : `No fixed version is published yet. Apply the vendor mitigation, restrict exposure of the affected code path, and track ${v.VulnerabilityID} for a patch.`,
          remediationCode: v.FixedVersion ? `${v.PkgName}>=${v.FixedVersion}` : null,
          cve: v.VulnerabilityID?.startsWith("CVE-") ? v.VulnerabilityID : null,
          cvss31: source.V3Score ?? null,
          cvssVector: source.V3Vector ?? null,
          verification: [
            `Confirm the resolved version: trivy fs --scanners vuln ${rel(result.Target, root) || "."}`,
            "Run the dependency test suite against the upgraded package.",
          ],
          raw: { pkg: v.PkgName, installed: v.InstalledVersion, fixed: v.FixedVersion, status: v.Status },
        });
      }
    }
    return out;
  },

  trivyConfig(report, root) {
    const out = [];
    for (const result of report?.Results ?? []) {
      for (const m of result.Misconfigurations ?? []) {
        out.push({
          tool: "trivy-config",
          ruleId: m.ID ?? null,
          title: (m.Title ?? m.ID ?? "Insecure configuration").slice(0, 200),
          severity: sev(m.Severity),
          module: "misconfig",
          location: `${rel(result.Target, root)}${m.CauseMetadata?.StartLine ? `:${m.CauseMetadata.StartLine}` : ""}`,
          description: `${m.Description ?? ""}\n\n${m.Message ?? ""}`.trim().slice(0, 2000),
          remediation: m.Resolution ?? "Apply the hardened configuration described by the policy.",
          remediationCode: null,
          verification: [`Re-run: trivy config ${rel(result.Target, root) || "."}`],
          raw: { id: m.ID, namespace: m.Namespace, references: m.References?.slice(0, 3) },
        });
      }
    }
    return out;
  },

  checkov(report, root) {
    const runs = Array.isArray(report) ? report : [report];
    const out = [];
    for (const run of runs) {
      for (const c of run?.results?.failed_checks ?? []) {
        out.push({
          tool: "checkov",
          ruleId: c.check_id ?? null,
          title: (c.check_name ?? c.check_id ?? "Policy violation").slice(0, 200),
          severity: sev(c.severity, "Medium"),
          module: "misconfig",
          location: `${rel(c.file_path, root)}:${c.file_line_range?.[0] ?? 0} (${c.resource ?? "resource"})`,
          description:
            `${c.check_name ?? ""} failed for ${c.resource ?? "the resource"}. ` +
            `Infrastructure defined as code inherits this weakness into every environment it provisions.`,
          remediation:
            c.guideline ??
            "Update the resource definition so the control is satisfied before the plan is applied.",
          remediationCode: (c.code_block ?? [])
            .slice(0, 12)
            .map((line) => (Array.isArray(line) ? `${line[0]}  ${String(line[1]).replace(/\n$/, "")}` : String(line)))
            .join("\n") || null,
          verification: [
            `Re-run: checkov -f ${rel(c.file_path, root)} --check ${c.check_id}`,
            "Confirm the plan output no longer provisions the insecure setting.",
          ],
          raw: { check_id: c.check_id, resource: c.resource, guideline: c.guideline },
        });
      }
    }
    return out;
  },

  sbomInventory(sbom, target) {
    const packages = sbom?.packages ?? [];
    if (!packages.length) return [];
    const unpinned = packages.filter((p) => !p.versionInfo).length;
    if (!unpinned) return [];
    return [
      {
        tool: "syft",
        ruleId: "SBOM-UNPINNED",
        title: `${unpinned} SBOM components without a resolved version`,
        severity: "Low",
        module: "deps",
        location: target,
        description:
          `The generated SPDX inventory lists ${packages.length} components, of which ${unpinned} carry no resolved version. ` +
          `Components without versions cannot be matched against vulnerability feeds, creating blind spots in continuous monitoring.`,
        remediation:
          "Pin every dependency to an explicit version and regenerate the SBOM so each component can be correlated against NVD and KEV.",
        remediationCode: null,
        verification: ["Regenerate the SBOM and confirm every package carries versionInfo."],
        raw: { components: packages.length, unpinned },
      },
    ];
  },

  nuclei(jsonl, target) {
    return jsonl
      .split("\n")
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean)
      .map((r) => {
        const info = r.info ?? {};
        const cve = (info.classification?.["cve-id"] ?? [])[0] ?? null;
        return {
          tool: "nuclei",
          ruleId: r["template-id"] ?? null,
          title: (info.name ?? r["template-id"] ?? "Web exposure").slice(0, 200),
          severity: sev(info.severity),
          module: cve ? "deps" : "owasp",
          location: r["matched-at"] ?? target,
          description:
            `${info.description ?? "Detected by an active nuclei template."}\n\n` +
            (r["extracted-results"]?.length ? `Evidence: ${r["extracted-results"].slice(0, 3).join(", ")}` : ""),
          remediation:
            info.remediation ??
            "Remove or restrict the exposed surface, then patch the underlying component to a supported release.",
          remediationCode: null,
          cve: cve ? String(cve).toUpperCase() : null,
          cvss31: info.classification?.["cvss-score"] ?? null,
          cvssVector: info.classification?.["cvss-metrics"] ?? null,
          verification: [
            `Re-run: nuclei -target ${target} -id ${r["template-id"]}`,
            "Confirm the endpoint returns the hardened response from an external network position.",
          ],
          raw: { template: r["template-id"], tags: info.tags, reference: info.reference?.slice(0, 3) },
        };
      });
  },

  /** Transport and header baseline — no external tool required. */
  async httpBaseline(target) {
    const out = [];
    const url = new URL(target);

    if (url.protocol !== "https:") {
      out.push({
        tool: "govshield-transport",
        ruleId: "TRANSPORT-PLAINTEXT",
        title: "Application served over plaintext HTTP",
        severity: "High",
        module: "owasp",
        location: target,
        description:
          "The target responds over HTTP. Session material and submitted records traverse the network in cleartext and can be read or modified in transit.",
        remediation:
          "Terminate TLS 1.2+ with a FIPS 140-3 validated module, redirect all HTTP to HTTPS, and enable HSTS.",
        remediationCode: "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;",
        verification: ["curl -I http://host → expect 301 to https", "Confirm TLS 1.2+ only via testssl.sh"],
        raw: {},
      });
    }

    let res;
    try {
      res = await fetch(target, { redirect: "follow", signal: AbortSignal.timeout(20_000) });
    } catch (err) {
      out.push({
        tool: "govshield-transport",
        ruleId: "TRANSPORT-UNREACHABLE",
        title: "Target did not respond to the baseline request",
        severity: "Low",
        module: "misconfig",
        location: target,
        description: `The baseline HTTP request failed: ${err.message}. Active testing may be incomplete.`,
        remediation: "Confirm the target is reachable from the assessment network and that the worker egress IP is allow-listed.",
        remediationCode: null,
        verification: ["Re-run the assessment once reachability is confirmed."],
        raw: {},
      });
      return out;
    }

    const required = {
      "strict-transport-security": {
        title: "HTTP Strict Transport Security not enforced",
        severity: "Medium",
        fix: 'Strict-Transport-Security: max-age=31536000; includeSubDomains',
        why: "Without HSTS a downgrade to plaintext remains possible on the first request of each session.",
      },
      "content-security-policy": {
        title: "No Content Security Policy",
        severity: "Medium",
        fix: "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
        why: "A CSP is the primary containment control for injected script in a compromised page.",
      },
      "x-content-type-options": {
        title: "MIME sniffing not disabled",
        severity: "Low",
        fix: "X-Content-Type-Options: nosniff",
        why: "Browsers may reinterpret a response body as script when the declared type is ignored.",
      },
      "referrer-policy": {
        title: "No referrer policy declared",
        severity: "Low",
        fix: "Referrer-Policy: strict-origin-when-cross-origin",
        why: "Full URLs — which can carry record identifiers about individuals — leak to third-party origins.",
      },
    };

    for (const [header, meta] of Object.entries(required)) {
      if (!res.headers.get(header)) {
        out.push({
          tool: "govshield-transport",
          ruleId: `HEADER-${header.toUpperCase()}`,
          title: meta.title,
          severity: meta.severity,
          module: "misconfig",
          location: `${target} (response headers)`,
          description: `${meta.why} The response omitted the \`${header}\` header.`,
          remediation: `Emit the header on every response from the edge or application tier.`,
          remediationCode: meta.fix,
          verification: [`curl -sI ${target} | grep -i ${header}`],
          raw: { status: res.status },
        });
      }
    }

    const server = res.headers.get("server");
    if (server && /\d/.test(server)) {
      out.push({
        tool: "govshield-transport",
        ruleId: "HEADER-SERVER-VERSION",
        title: `Server banner discloses version: ${server}`,
        severity: "Low",
        module: "misconfig",
        location: `${target} (Server header)`,
        description:
          "The response advertises the exact server build, letting an attacker match the target to published exploits without probing.",
        remediation: "Suppress or genericise the Server header at the edge.",
        remediationCode: "server_tokens off;",
        verification: [`curl -sI ${target} | grep -i '^server'`],
        raw: { server },
      });
    }

    return out;
  },
};
