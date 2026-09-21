export type Severity = "Critical" | "High" | "Medium" | "Low";

export type Role = "Admin" | "Assessor" | "Read-Only Auditor";

export type TargetType = "dast" | "sast" | "sbom" | "iac";

export type ModuleKey = "owasp" | "misconfig" | "secrets" | "kev" | "deps";

export type ScanMode = "standard" | "conmon";

export type FeedId = "kev" | "nvd" | "mitre" | "epss";

export interface ThreatFeed {
  id: FeedId;
  name: string;
  source: string;
  records: number;
  lastSynced: number;
  status: "operational" | "syncing" | "degraded";
  latencyMs: number;
}

export interface ScannerPlugin {
  id: string;
  name: string;
  signature: string;
  coverage: string;
  active: boolean;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  module: ModuleKey;
  target: TargetType;
  epss: number;
  cvss31: number;
  cvss40: number;
  cvssVector: string;
  cve: string | null;
  kev: boolean;
  nistControls: string[];
  fedrampBaseline: "Moderate" | "High";
  fips1403: boolean;
  privacyImpact: string | null;
  privacyCategory: string | null;
  location: string;
  description: string;
  remediation: string;
  remediationCode: string;
  verification: string[];
}

export interface AuditEntry {
  id: string;
  timestamp: number;
  actor: string;
  role: Role;
  action: string;
  target: string;
  hash: string;
  prevHash: string;
}

export interface ControlCoverage {
  control: string;
  family: string;
  title: string;
  status: "satisfied" | "partial" | "failed";
  findings: number;
}
