# GovShield SecOps: from simulation to working software

Today everything on screen is generated in the browser. There is no backend, no accounts, no stored data, and no scanning — findings are a fixed list that appears after a four second animation.

Turning it into real software means four things: a place to store data, real accounts, real data coming in from the outside, and a place where actual scans run. Below is the order that gets there with the least risk.

## What changes at the foundation

Enable Lovable Cloud so the app gets a database, logins, file storage and server-side code. Nothing on screen has to be redesigned — the existing panels stay, they just start reading real rows instead of the built-in sample list.

New stored records: organizations and members, targets, scans, findings, threat-feed entries (KEV / NVD / EPSS), control mappings, report exports and the audit log. Every table is locked down so a member of one team can never read another team's data. Roles (Admin, Assessor, Read-Only Auditor) move out of the dropdown and become real permissions enforced on the server, not just hidden buttons.

## Phase 1 — Accounts, roles, real audit log

- Email and password sign in, an invite flow, and one shared team workspace.
- Admin / Assessor / Read-Only Auditor enforced server-side. The role picker in the top bar becomes a display of who you actually are.
- The audit log becomes a genuine append-only table written by the server on every meaningful action, with each row's hash chained to the previous one, so tampering is detectable. Verification runs server-side.

This is the phase that makes the tool trustworthy; everything after it is recorded.

## Phase 2 — Live threat intelligence

Real data pulled on a schedule and stored:

- CISA KEV catalog (public JSON, no key)
- NIST NVD 2.0 (free API key, rate limited — sync incrementally by last-modified window)
- FIRST EPSS scores (public CSV, daily)
- MITRE ATT&CK and CAPEC (published STIX bundles, weekly)

A scheduled job refreshes these and records sync time, record counts and errors. The Feed Telemetry card then shows true "last synced" and "next sync" values, and Sync Now triggers a real refresh. The rule-engine indicator reflects actual signature/dataset versions in storage.

This phase alone makes a large part of the app real, and it needs no scanning infrastructure.

## Phase 3 — Scan execution

Scanners are real programs (Semgrep, Trivy, Gitleaks, Checkov, OWASP ZAP). They cannot run inside the app's own hosting, so the app becomes the control plane and a separate worker does the heavy lifting.

Recommended setup, since you don't have infrastructure yet:

- The app writes a scan job into the database.
- A container worker runs on a managed container host (Fly.io machines, or Google Cloud Run jobs) with the scanner tools installed.
- The worker claims queued jobs over a secured API endpoint, runs the tools, streams stage progress back (which drives the existing stepper with real stages), and posts raw results.
- The server normalizes results, enriches each finding with KEV / EPSS / CVSS from Phase 2, applies the control crosswalk, and stores findings.

Order of scanners, easiest first:

1. SCA and secrets on a Git repo (Trivy + Gitleaks) — fast, safe, no consent issues.
2. SAST (Semgrep) and IaC (Checkov/Trivy) — same worker, more rules.
3. SBOM / container images (Syft + Trivy) — upload an SBOM or point at a registry.
4. DAST (ZAP) last — it actively probes a live site, so it needs target ownership verification, a written authorization record, rate limits, and a scan window. This is the one with legal exposure; the app must refuse to scan a target the team hasn't proven it controls.

Git access starts with a token the team pastes in; a GitHub App comes later if you want one-click repo selection.

Continuous Monitoring becomes a real recurring schedule per target with drift and new-finding alerts by email.

## Phase 4 — Audit-grade OSCAL

The current export is hand-built JSON. Audit-grade means:

- Generate OSCAL Assessment Results and, where needed, Plan of Action and Milestones, against the official OSCAL 1.1.x schemas.
- Validate every export against the published schema and against NIST's own validation rules before it downloads; a failing export is blocked, not shipped.
- Map findings to real NIST SP 800-53 Rev 5 controls loaded from the official catalog rather than a hardcoded list, and resolve the FedRAMP Moderate/High baseline profiles from their published sources.
- Keep every export stored and hashed so an assessor can prove which findings produced which report.

FIPS 140-3 flags stay advisory — real validation status comes from NIST's CMVP list, which we can ingest as a reference dataset.

## What this is not

Running this software is not the same as being FedRAMP authorized. The app can produce FedRAMP-aligned evidence, but if you ever want to sell it into government as a service, the hosting itself needs authorization, which is a separate multi-year program. Worth deciding early, because it changes where the worker and database are allowed to live.

## Suggested first step

Phase 1 plus Phase 2 together: real logins, real roles, real audit trail, and real threat feeds. That converts the majority of the screens from mock to live without standing up any scanning infrastructure, and it gives a working product to demo while Phase 3 is built.

## Technical notes

- Backend: Lovable Cloud (Postgres, auth, storage, server functions). Roles in a separate `user_roles` table with a security-definer check, never on the profile row.
- Feed sync and scheduled ConMon runs: scheduled invocations hitting `/api/public/*` endpoints with a shared secret, since the hosting runtime has no cron of its own.
- Worker communication: job claim / heartbeat / result endpoints under `/api/public/*`, authenticated with a per-worker key; workers are stateless and horizontally scalable.
- The app's own runtime is an edge worker — no child processes, no native binaries — which is why scanners must live in the external container worker.
- NVD requires an API key and enforces rate limits; sync in last-modified windows with backoff rather than full catalog pulls.
- DAST requires target ownership proof (DNS TXT record or a hosted file) recorded before any scan is permitted.
