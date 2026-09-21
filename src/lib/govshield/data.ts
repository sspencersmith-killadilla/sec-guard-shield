import type {
  ControlCoverage,
  Finding,
  ModuleKey,
  ScannerPlugin,
  Severity,
  TargetType,
  ThreatFeed,
} from "./types";

export const TARGET_TYPES: { id: TargetType; label: string; engine: string; placeholder: string }[] = [
  { id: "dast", label: "Web Application URL", engine: "DAST", placeholder: "https://portal.agency.gov" },
  { id: "sast", label: "Git Repository", engine: "SAST / SCA", placeholder: "git@github.com:agency/portal.git" },
  { id: "sbom", label: "Container Registry / SBOM", engine: "Syft + Trivy", placeholder: "registry.agency.gov/portal:2.14.0" },
  { id: "iac", label: "Cloud Infrastructure", engine: "IaC / Terraform", placeholder: "s3://agency-iac/terraform/prod" },
];

export const TEST_MODULES: { id: ModuleKey; label: string; detail: string }[] = [
  { id: "owasp", label: "OWASP Top 10 (2021)", detail: "Injection, broken access control, SSRF" },
  { id: "misconfig", label: "Security Misconfigurations", detail: "Headers, TLS, IAM, storage exposure" },
  { id: "secrets", label: "Secret & Credential Leaks", detail: "Entropy + provider pattern matching" },
  { id: "kev", label: "Zero-Day / CISA KEV Matching", detail: "Live correlation against KEV catalog" },
  { id: "deps", label: "Dependency Vulnerabilities", detail: "SCA across SBOM components" },
];

export const SCAN_STAGES = [
  "Ingesting latest threat feeds...",
  "Parsing AST / target surface...",
  "Evaluating against NIST controls...",
  "Generating OSCAL report...",
];

export const INITIAL_FEEDS: ThreatFeed[] = [
  { id: "kev", name: "CISA KEV Catalog", source: "cisa.gov/kev", records: 1284, lastSynced: 0, status: "operational", latencyMs: 412 },
  { id: "nvd", name: "NIST NVD (API 2.0)", source: "services.nvd.nist.gov", records: 271934, lastSynced: 0, status: "operational", latencyMs: 908 },
  { id: "mitre", name: "MITRE ATT&CK & CAPEC", source: "attack.mitre.org", records: 1642, lastSynced: 0, status: "operational", latencyMs: 356 },
  { id: "epss", name: "FIRST EPSS Model", source: "api.first.org/epss", records: 248117, lastSynced: 0, status: "operational", latencyMs: 522 },
];

export const INITIAL_PLUGINS: ScannerPlugin[] = [
  { id: "dast-core", name: "DAST Probe Engine", signature: "2026.09.21-1148", coverage: "OWASP A01–A10", active: true },
  { id: "sast-ast", name: "AST Taint Analyzer", signature: "2026.09.20-0932", coverage: "CWE Top 25", active: true },
  { id: "sca-sbom", name: "SBOM Correlator", signature: "2026.09.21-0410", coverage: "CPE / PURL match", active: true },
  { id: "kev-match", name: "KEV Zero-Day Matcher", signature: "2026.09.21-1148", coverage: "CISA KEV + EPSS", active: true },
  { id: "iac-policy", name: "IaC Policy Evaluator", signature: "2026.09.19-2202", coverage: "NIST 800-53 / CIS", active: true },
  { id: "crypto-fips", name: "FIPS 140-3 Validator", signature: "2026.09.18-1500", coverage: "Approved algorithms", active: true },
];

export const FINDINGS: Finding[] = [
  {
    id: "GS-0001",
    title: "Unauthenticated remote code execution in reporting service",
    severity: "Critical",
    module: "kev",
    target: "dast",
    epss: 0.9412,
    cvss31: 9.8,
    cvss40: 9.6,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cve: "CVE-2026-21847",
    kev: true,
    nistControls: ["SI-2", "RA-5", "SI-3"],
    fedrampBaseline: "High",
    fips1403: false,
    privacyImpact: "Full datastore access enables mass PII exfiltration (Privacy Act violation risk)",
    privacyCategory: "CT.DM-P — Data Processing Management",
    location: "POST /api/v2/reports/render",
    description:
      "The reporting renderer deserializes untrusted template payloads. The underlying library version is listed in the CISA KEV catalog with confirmed in-the-wild exploitation.",
    remediation:
      "Upgrade the rendering library to a patched release and disable dynamic template deserialization for external callers.",
    remediationCode: `# package upgrade + hardening
- "report-render": "4.2.1"
+ "report-render": "4.6.3"

renderer.configure({
  allowDynamicTemplates: false,
  sandbox: "strict",
});`,
    verification: [
      "Re-run the DAST module against /api/v2/reports/render",
      "Confirm the patched version in the generated SBOM",
      "Validate KEV matcher returns zero hits for the component",
    ],
  },
  {
    id: "GS-0002",
    title: "Hardcoded cloud access key committed to repository history",
    severity: "Critical",
    module: "secrets",
    target: "sast",
    epss: 0.6123,
    cvss31: 9.1,
    cvss40: 9.0,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    cve: null,
    kev: false,
    nistControls: ["IA-5", "SC-28", "AC-6"],
    fedrampBaseline: "High",
    fips1403: false,
    privacyImpact: "Key grants read access to buckets holding citizen case records",
    privacyCategory: "CT.PO-P — Data Protection Policies",
    location: "infra/deploy/publish.sh:42 (commit 8f2c1ad)",
    description:
      "A long-lived static access key is present in tracked source and in git history, bypassing the agency's short-lived credential policy.",
    remediation: "Revoke the key, purge it from history, and move to workload identity federation with 1-hour credentials.",
    remediationCode: `- export AWS_ACCESS_KEY_ID="AKIA...REDACTED"
- export AWS_SECRET_ACCESS_KEY="wJalr...REDACTED"
+ # OIDC workload identity — no static secrets
+ aws sts assume-role-with-web-identity \\
+   --role-arn "$DEPLOY_ROLE_ARN" \\
+   --web-identity-token "$OIDC_TOKEN" \\
+   --duration-seconds 3600`,
    verification: [
      "Confirm the key is revoked in the cloud IAM console",
      "Re-run the secrets module with full history depth",
      "Verify deploy pipeline succeeds using federated credentials",
    ],
  },
  {
    id: "GS-0003",
    title: "SQL injection in citizen record lookup",
    severity: "Critical",
    module: "owasp",
    target: "sast",
    epss: 0.4471,
    cvss31: 9.3,
    cvss40: 9.2,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L",
    cve: null,
    kev: false,
    nistControls: ["SI-10", "SI-2", "AC-3"],
    fedrampBaseline: "High",
    fips1403: false,
    privacyImpact: "Potential PII leakage — SSN and address fields reachable via injected predicate",
    privacyCategory: "CT.DP-P — Disassociated Processing",
    location: "src/services/records.ts:118",
    description:
      "User-controlled query parameters are concatenated into a SQL statement, allowing predicate injection against the citizen records table.",
    remediation: "Replace string concatenation with parameterized queries and enforce an allow-list on sortable columns.",
    remediationCode: `- const rows = await db.query(
-   \`SELECT * FROM citizens WHERE last_name = '\${q}' ORDER BY \${sort}\`
- );
+ const SORTS = { name: "last_name", filed: "filed_at" } as const;
+ const rows = await db.query(
+   \`SELECT * FROM citizens WHERE last_name = $1 ORDER BY \${SORTS[sort] ?? "filed_at"}\`,
+   [q],
+ );`,
    verification: [
      "Run the OWASP injection suite against /records/search",
      "Add a regression test with a quote-escaping payload",
      "Confirm database audit log shows no anomalous predicates",
    ],
  },
  {
    id: "GS-0004",
    title: "Non-FIPS-validated cipher suite negotiated on public endpoint",
    severity: "High",
    module: "misconfig",
    target: "dast",
    epss: 0.1042,
    cvss31: 7.4,
    cvss40: 7.1,
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
    cve: null,
    kev: false,
    nistControls: ["SC-13", "SC-8", "SC-7"],
    fedrampBaseline: "High",
    fips1403: true,
    privacyImpact: "Transport of PII over a non-approved cipher suite",
    privacyCategory: "PR.DS-P — Data Security",
    location: "edge-lb.agency.gov:443",
    description:
      "The load balancer accepts CHACHA20-POLY1305, which is outside the FIPS 140-3 approved algorithm list for this boundary.",
    remediation: "Restrict the TLS policy to FIPS 140-3 approved suites and disable TLS 1.1/1.2 legacy fallbacks.",
    remediationCode: `resource "aws_lb_listener" "https" {
-  ssl_policy = "ELBSecurityPolicy-2016-08"
+  ssl_policy = "ELBSecurityPolicy-TLS13-1-2-FIPS-2023-04"
}`,
    verification: [
      "Run a TLS handshake probe and confirm only approved suites are offered",
      "Confirm the FIPS 140-3 validator plugin reports PASS",
      "Record the change in the SSP control implementation for SC-13",
    ],
  },
  {
    id: "GS-0005",
    title: "Broken object-level authorization on case attachments",
    severity: "High",
    module: "owasp",
    target: "dast",
    epss: 0.2217,
    cvss31: 8.1,
    cvss40: 8.0,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    cve: null,
    kev: false,
    nistControls: ["AC-3", "AC-4", "AU-2"],
    fedrampBaseline: "Moderate",
    fips1403: false,
    privacyImpact: "Cross-tenant PII exposure — attachments readable by unrelated case officers",
    privacyCategory: "CT.DM-P — Data Processing Management",
    location: "GET /api/v2/cases/{caseId}/attachments/{id}",
    description:
      "The attachment handler validates authentication but not ownership, so any authenticated user can enumerate attachment IDs.",
    remediation: "Enforce an ownership predicate in the data layer and return 404 for unauthorized identifiers.",
    remediationCode: `const file = await db.attachment.findFirst({
  where: {
    id: params.id,
+   case: { assignedOfficeId: session.officeId },
  },
});
if (!file) return notFound();`,
    verification: [
      "Attempt cross-tenant retrieval with a second test account",
      "Confirm audit log records denied attempts (AU-2)",
      "Add an authorization integration test to CI",
    ],
  },
  {
    id: "GS-0006",
    title: "Vulnerable transitive dependency with known exploit activity",
    severity: "High",
    module: "deps",
    target: "sbom",
    epss: 0.7788,
    cvss31: 8.6,
    cvss40: 8.4,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
    cve: "CVE-2026-10233",
    kev: true,
    nistControls: ["SI-2", "RA-5", "CM-8"],
    fedrampBaseline: "High",
    fips1403: false,
    privacyImpact: null,
    privacyCategory: null,
    location: "portal:2.14.0 → xml-stream@3.1.0 (transitive)",
    description:
      "SBOM correlation matched a transitive XML parser affected by an entity-expansion RCE chain now present in the KEV catalog.",
    remediation: "Pin the direct parent to a release that resolves the patched parser, then rebuild and re-sign the image.",
    remediationCode: `# resolutions in package.json
"overrides": {
  "xml-stream": "3.4.2"
}

# rebuild + regenerate SBOM
syft packages registry.agency.gov/portal:2.14.1 -o cyclonedx-json > sbom.json`,
    verification: [
      "Regenerate the SBOM and confirm xml-stream >= 3.4.2",
      "Re-run Trivy against the rebuilt image",
      "Confirm zero KEV matches for the image digest",
    ],
  },
  {
    id: "GS-0007",
    title: "Public storage bucket exposes archived case exports",
    severity: "Critical",
    module: "misconfig",
    target: "iac",
    epss: 0.3345,
    cvss31: 9.1,
    cvss40: 8.9,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    cve: null,
    kev: false,
    nistControls: ["AC-3", "SC-7", "MP-6"],
    fedrampBaseline: "High",
    fips1403: false,
    privacyImpact: "Unauthorized data transfer — exports contain names, DOB and benefit determinations",
    privacyCategory: "CT.PO-P — Data Protection Policies",
    location: "terraform/storage.tf:27 (agency-case-exports)",
    description:
      "The bucket policy grants s3:GetObject to a wildcard principal and public access block is disabled.",
    remediation: "Remove the wildcard grant, enable the public access block, and require TLS-only access.",
    remediationCode: `resource "aws_s3_bucket_public_access_block" "exports" {
  bucket                  = aws_s3_bucket.exports.id
-  block_public_acls       = false
+  block_public_acls       = true
+  block_public_policy     = true
+  ignore_public_acls      = true
+  restrict_public_buckets = true
}`,
    verification: [
      "Re-run the IaC policy evaluator on the plan output",
      "Confirm anonymous GET returns 403",
      "Review access logs for prior anonymous reads",
    ],
  },
  {
    id: "GS-0008",
    title: "Missing security headers on authenticated portal responses",
    severity: "Medium",
    module: "misconfig",
    target: "dast",
    epss: 0.0214,
    cvss31: 5.3,
    cvss40: 5.1,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N",
    cve: null,
    kev: false,
    nistControls: ["SC-7", "SI-10"],
    fedrampBaseline: "Moderate",
    fips1403: false,
    privacyImpact: null,
    privacyCategory: null,
    location: "https://portal.agency.gov/*",
    description:
      "Responses omit Content-Security-Policy, X-Content-Type-Options and Strict-Transport-Security preload directives.",
    remediation: "Apply a strict header policy at the edge for all authenticated routes.",
    remediationCode: `add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'none'" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;`,
    verification: [
      "Re-run the misconfiguration module and confirm all headers present",
      "Validate CSP does not break portal functionality in staging",
    ],
  },
  {
    id: "GS-0009",
    title: "Session tokens retained beyond approved retention window",
    severity: "Medium",
    module: "misconfig",
    target: "iac",
    epss: 0.0087,
    cvss31: 4.9,
    cvss40: 4.7,
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N",
    cve: null,
    kev: false,
    nistControls: ["AU-11", "SI-12", "AC-12"],
    fedrampBaseline: "Moderate",
    fips1403: false,
    privacyImpact: "Data retention risk — identifiers held 400 days past the documented schedule",
    privacyCategory: "CT.DM-P — Data Processing Management",
    location: "terraform/sessions.tf:14",
    description: "Session table TTL is unset, so identity-linked records persist indefinitely.",
    remediation: "Set a TTL matching the approved records schedule and document the retention control.",
    remediationCode: `resource "aws_dynamodb_table" "sessions" {
+  ttl {
+    attribute_name = "expires_at"
+    enabled        = true
+  }
}`,
    verification: [
      "Confirm TTL attribute is populated on new sessions",
      "Verify records older than the window are purged",
    ],
  },
  {
    id: "GS-0010",
    title: "Verbose stack traces returned to unauthenticated clients",
    severity: "Medium",
    module: "owasp",
    target: "dast",
    epss: 0.0331,
    cvss31: 5.8,
    cvss40: 5.6,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cve: null,
    kev: false,
    nistControls: ["SI-11", "AU-9"],
    fedrampBaseline: "Moderate",
    fips1403: false,
    privacyImpact: null,
    privacyCategory: null,
    location: "GET /api/v2/lookup?id=%00",
    description: "Unhandled input errors return framework stack traces disclosing internal paths and library versions.",
    remediation: "Return a generic error envelope in production and log details server-side only.",
    remediationCode: `catch (err) {
-  return json({ error: String(err), stack: err.stack }, { status: 500 });
+  logger.error({ err, requestId });
+  return json({ error: "Internal error", requestId }, { status: 500 });
}`,
    verification: ["Probe malformed input and confirm no stack content", "Confirm details appear in server logs only"],
  },
  {
    id: "GS-0011",
    title: "Outdated cryptographic hash used for document integrity",
    severity: "High",
    module: "deps",
    target: "sast",
    epss: 0.0563,
    cvss31: 7.1,
    cvss40: 6.9,
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
    cve: null,
    kev: false,
    nistControls: ["SC-13", "SI-7", "AU-9"],
    fedrampBaseline: "High",
    fips1403: true,
    privacyImpact: null,
    privacyCategory: null,
    location: "src/lib/integrity.ts:31",
    description: "SHA-1 is used to seal signed determination documents; it is not FIPS 140-3 approved for integrity.",
    remediation: "Migrate to SHA-256 and re-seal existing artifacts during the next maintenance window.",
    remediationCode: `- const digest = createHash("sha1").update(buf).digest("hex");
+ const digest = createHash("sha256").update(buf).digest("hex");`,
    verification: ["Confirm FIPS validator reports PASS", "Re-seal and spot-check archived documents"],
  },
  {
    id: "GS-0012",
    title: "Overly permissive IAM role attached to scanning worker",
    severity: "High",
    module: "misconfig",
    target: "iac",
    epss: 0.0459,
    cvss31: 7.7,
    cvss40: 7.5,
    cvssVector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N",
    cve: null,
    kev: false,
    nistControls: ["AC-6", "AC-2", "CM-7"],
    fedrampBaseline: "High",
    fips1403: false,
    privacyImpact: null,
    privacyCategory: null,
    location: "terraform/iam.tf:88",
    description: "The worker role grants Action: \"*\" on Resource: \"*\", violating least privilege for the boundary.",
    remediation: "Scope the policy to the specific actions and resource ARNs the worker requires.",
    remediationCode: `-  actions   = ["*"]
-  resources = ["*"]
+  actions   = ["s3:GetObject", "s3:PutObject"]
+  resources = ["\${aws_s3_bucket.scan_artifacts.arn}/*"]`,
    verification: ["Re-run the IaC evaluator", "Confirm worker jobs still complete in staging"],
  },
  {
    id: "GS-0013",
    title: "Unsigned container image accepted by deployment pipeline",
    severity: "Medium",
    module: "deps",
    target: "sbom",
    epss: 0.0128,
    cvss31: 6.2,
    cvss40: 6.0,
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L",
    cve: null,
    kev: false,
    nistControls: ["CM-14", "SI-7", "SR-11"],
    fedrampBaseline: "Moderate",
    fips1403: false,
    privacyImpact: null,
    privacyCategory: null,
    location: ".github/workflows/deploy.yml:61",
    description: "Image signature verification is not enforced before promotion to the production namespace.",
    remediation: "Require cosign verification against the agency key before deploy.",
    remediationCode: `+ - name: Verify image signature
+   run: cosign verify --key \${{ secrets.COSIGN_PUB }} "$IMAGE"`,
    verification: ["Attempt deploy with an unsigned image and confirm failure", "Record supply-chain control evidence"],
  },
  {
    id: "GS-0014",
    title: "Client-side analytics beacon transmits case identifiers off-boundary",
    severity: "Low",
    module: "owasp",
    target: "dast",
    epss: 0.0042,
    cvss31: 3.7,
    cvss40: 3.5,
    cvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
    cve: null,
    kev: false,
    nistControls: ["SC-7", "AR-2"],
    fedrampBaseline: "Moderate",
    fips1403: false,
    privacyImpact: "Unauthorized data transfer to a third-party domain outside the authorization boundary",
    privacyCategory: "CM.AW-P — Awareness and Training / Data Transfer",
    location: "https://portal.agency.gov/assets/analytics.js",
    description: "Page URLs containing case identifiers are sent to an external analytics endpoint.",
    remediation: "Strip identifiers from the reported path or move analytics inside the boundary.",
    remediationCode: `- beacon({ path: location.pathname });
+ beacon({ path: location.pathname.replace(/\\/cases\\/[^/]+/, "/cases/:id") });`,
    verification: ["Inspect outbound beacon payloads", "Update the privacy impact assessment"],
  },
];

export const CONTROL_COVERAGE: ControlCoverage[] = [
  { control: "SI-2", family: "System & Information Integrity", title: "Flaw Remediation", status: "failed", findings: 3 },
  { control: "RA-5", family: "Risk Assessment", title: "Vulnerability Monitoring & Scanning", status: "partial", findings: 2 },
  { control: "SC-7", family: "System & Communications Protection", title: "Boundary Protection", status: "partial", findings: 4 },
  { control: "SC-13", family: "System & Communications Protection", title: "Cryptographic Protection", status: "failed", findings: 2 },
  { control: "AC-3", family: "Access Control", title: "Access Enforcement", status: "failed", findings: 3 },
  { control: "AC-6", family: "Access Control", title: "Least Privilege", status: "partial", findings: 2 },
  { control: "IA-5", family: "Identification & Authentication", title: "Authenticator Management", status: "failed", findings: 1 },
  { control: "AU-2", family: "Audit & Accountability", title: "Event Logging", status: "satisfied", findings: 0 },
  { control: "AU-9", family: "Audit & Accountability", title: "Protection of Audit Information", status: "satisfied", findings: 0 },
  { control: "CM-8", family: "Configuration Management", title: "System Component Inventory", status: "partial", findings: 1 },
  { control: "SI-10", family: "System & Information Integrity", title: "Information Input Validation", status: "failed", findings: 2 },
  { control: "SI-12", family: "System & Information Integrity", title: "Information Retention", status: "partial", findings: 1 },
];

export const TREND_DATA = Array.from({ length: 30 }, (_, i) => {
  const wave = Math.sin(i / 4);
  return {
    day: `D-${29 - i}`,
    critical: Math.max(1, Math.round(6 + wave * 2 - i * 0.08)),
    high: Math.max(2, Math.round(11 + wave * 3 - i * 0.1)),
    medium: Math.max(3, Math.round(15 + wave * 4 - i * 0.05)),
    posture: Math.min(98, Math.round(58 + i * 0.7 + wave * 2)),
  };
});

export const SEVERITY_ORDER: Severity[] = ["Critical", "High", "Medium", "Low"];

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  Critical: 10,
  High: 6,
  Medium: 3,
  Low: 1,
};

export function severityClasses(severity: Severity) {
  switch (severity) {
    case "Critical":
      return "bg-critical/15 text-critical border-critical/40";
    case "High":
      return "bg-high/15 text-high border-high/40";
    case "Medium":
      return "bg-medium/15 text-medium border-medium/40";
    default:
      return "bg-low/15 text-low border-low/40";
  }
}

export function computePosture(findings: Finding[]) {
  const penalty = findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0);
  return Math.max(0, Math.min(100, 100 - penalty));
}
