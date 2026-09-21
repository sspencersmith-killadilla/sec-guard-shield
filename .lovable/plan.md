# GovShield SecOps — Security Testing & Compliance Platform

A single-page, dark institutional console for running simulated security scans and mapping findings to US government security standards. All data is mocked in the front end — no backend, no real scanning.

## Screen layout

One main console at `/` with a persistent top bar and a tabbed workspace.

```text
+--------------------------------------------------------------+
| GovShield SecOps   | Role: Admin v | Feeds: SYNCED  12:04 UTC |
+--------------------------------------------------------------+
| Tabs: Overview | Threat Feeds | New Scan | Findings | Audit   |
+--------------------------------------------------------------+
|  content area                                                 |
+--------------------------------------------------------------+
```

## Modules

**1. Threat Intelligence**
- Feed cards for CISA KEV, NIST NVD 2.0, MITRE ATT&CK/CAPEC, FIRST EPSS: status light, last synced, records ingested.
- Telemetry card: next auto-sync countdown (live ticking), "Auto-Update Rules" toggle on by default, "Sync Now" button with animated syncing state that refreshes timestamps.
- Rule engine indicator: list of active scanner plugins with signature versions that bump after a sync.

**2. Target Configuration & Scanners**
- Scope selector: Web App URL (DAST), Git Repository (SAST/SCA), Container/SBOM, Cloud IaC — each with its own input field.
- Test module checkboxes: OWASP Top 10, Misconfigurations, Secret Leaks, Zero-Day/KEV matching, Dependency Vulnerabilities.
- Scan mode: Standard vs Continuous Monitoring (ConMon) with a schedule picker.
- "Start Scan" runs a 4-second, four-stage stepper, then reveals results.

**3. Compliance Crosswalk**
- Every finding carries mapped NIST SP 800-53 Rev.5 controls, FedRAMP baseline (Moderate/High), FIPS 140-3 crypto flag, and a NIST Privacy Framework category.
- Control coverage panel summarising pass/fail per control family.
- "Export SSP" button producing a downloadable OSCAL-style JSON and a FISMA-style summary.

**4. Findings & Remediation**
- Compliance posture score gauge (0–100) plus severity distribution and a 30-day vulnerability trend chart (Recharts).
- Accordion findings list: title, severity badge, EPSS %, CVSS v3.1/v4.0 vectors, CVE link to upstream feed, NIST/FedRAMP IDs, privacy impact flag, remediation code snippet and verification steps.
- Filters by severity, module, and privacy impact.

**5. Zero Trust & Audit**
- Immutable audit log table: timestamp, actor, role, action, target, SHA-256-style hash and prior-hash chain link, with a "verify chain" action.
- Role switcher (Admin / Assessor / Read-Only Auditor) that gates scan start, config edits, and exports.

## Visual direction

Institutional dark mode: slate/zinc surfaces, cyan-teal primary for system actions, amber/red severity scale, no purple gradients. Government-console typography (condensed geometric headings, neutral sans body), dense tables, thin rules, monospace for hashes, CVEs and code. All tokens defined in `src/styles.css`; contrast held at WCAG 2.1 AA with visible focus rings and keyboard-navigable tabs, accordions and tables.

## Technical notes

- React + TanStack Start route at `src/routes/index.tsx` (replaces the placeholder), shadcn/ui, Lucide icons, Recharts.
- `GovShieldProvider` context holds feeds, scan config, scan phase, findings, audit log and current role; reducer-driven so every action also appends a hashed audit entry.
- Mock dataset module with ~14 realistic findings across the scanner types, each pre-mapped to controls and CVEs.
- Scan runs on timers in the provider; stepper reflects phase state. No network calls, no database.
- Page `head()` set with GovShield-specific title, description and social tags.
