# GovShield Guardian

Role & Goal:

You are an expert DevSecOps and full-stack software engineer. Build a production-grade, enterprise web application named "GovShield SecOps" — a centralized, FedRAMP-aligned security testing and compliance auditing platform. It evaluates web applications, APIs, source code, and cloud workloads against modern government security standards while maintaining real-time alignment with evolving global threat feeds.

Design & Tech Stack:

- Tech Stack: React, Tailwind CSS, shadcn/ui components, and Lucide React icons.

- Visual Aesthetic: Institutional dark-mode interface (slate/zinc palette with high-contrast accessibility compliant with Section 508 / WCAG 2.1 AA).

- Data Visualization: Recharts for audit metrics, telemetry, and vulnerability trends.

Core Architecture & Modules:

1. Real-Time Threat Intelligence & Automated Sync (Self-Updating Mechanism):

   - Threat Feed Manager: A dedicated status bar and configuration pane managing continuous automated polling of upstream threat feeds:

     * CISA KEV (Known Exploited Vulnerabilities) Catalog

     * NIST National Vulnerability Database (NVD) via API 2.0

     * MITRE ATT&CK & CAPEC framework updates

     * FIRST Exploit Prediction Scoring System (EPSS)

   - Feed Telemetry Card: Shows "Last Synced" timestamp, "Next Auto-Sync" countdown, an "Auto-Update Rules" toggle (default: active), and a manual "Sync Now" trigger with an animated status indicator.

   - Dynamic Rule Engine Indicator: Visual indicator showing active scanning plugins automatically updating their detection signatures based on newly ingested CVEs without requiring service restarts.

2. Target Configuration & Scanners:

   - Target Scope Selector: Options for Web App URL (DAST), Git Repository (SAST/SCA), Container Registry/SBOM (Syft/Trivy format), and Cloud Infrastructure (IaC/Terraform).

   - Test Modules: Checkboxes for OWASP Top 10, Misconfigurations, Secret Leaks, Zero-Day/KEV matching, and Dependency Vulnerabilities.

   - Scan Modes: "Standard Scan" vs. "Continuous Continuous Monitoring (ConMon)" automated recurring schedule.

3. Government Security & Privacy Compliance Mapping:

   - Standard Crosswalk Engine: Automatically correlate scan findings to specific regulatory control sets:

     * NIST SP 800-53 Rev. 5 (e.g., SI-2 Flaw Remediation, RA-5 Vulnerability Scanning, SC-7 Boundary Protection)

     * FedRAMP Moderate/High Baselines

     * FIPS 140-3 Cryptographic Validation flags

     * NIST Privacy Framework 1.0 (categorizing PII exposure, unauthorized data transfers, and data retention risks)

   - System Security Plan (SSP) Export: A prominent action button to export findings formatted as an OSCAL-compatible (Open Security Controls Assessment Language) or FISMA-ready audit report.

4. Findings & Remediation View:

   - Overall Compliance Posture Score (0–100%) alongside a dynamic CVSS v3.1 / v4.0 severity rating.

   - Data Table/Accordion for Findings: Each issue must display:

     * Title, Severity Badge (Critical, High, Medium, Low), and EPSS probability percentage.

     * Mapped NIST Control ID (e.g., NIST SI-2) and FedRAMP Control identifier.

     * CVE ID linked to the upstream feed entry.

     * Privacy Impact Flag (e.g., "Potential PII Leakage / Privacy Act Violation").

     * Remediation Code Snippet and verification steps.

5. Zero Trust & Audit Logging:

   - Immutable Audit Log Table: Tracks user actions, scan executions, and configuration changes with cryptographic hash signatures to simulate tamper-evident logging (NIST AU-2 / AU-9 compliance).

   - Role-Based Access Scoping (Admin, Assessor, Read-Only Auditor).

State & Mock Service:

- Implement a comprehensive mock state provider.

- When "Start Scan" is clicked, render a multi-stage stepper ("Ingesting latest threat feeds...", "Parsing AST/Target...", "Evaluating against NIST controls...", "Generating OSCAL Report...") taking 4 seconds before loading the fully populated results screen.

This project was built with [Lovable](https://lovable.dev).

**Live app**: https://sec-guard-shield.lovable.app

## Build with Lovable

Continue developing this project in the [Lovable editor](https://lovable.dev/projects/7711b643-feb8-4754-817c-2f8355738feb).

- **Ship faster**: describe what you want to build and Lovable handles the code.
- **Stay in sync**: every change made in Lovable is committed straight to this repository.
- **Full ownership**: this code is yours. Push to `main` on GitHub and your changes sync back into Lovable, ready for your next prompt.

## Development

Prefer working locally? You need Node.js and npm — [install with nvm](https://github.com/nvm-sh/nvm#installing-and-updating).

```sh
git clone <this-repository-url>
cd <repository-name>
npm i
npm run dev
```

## License

License: MIT, see [LICENSE](LICENSE).
