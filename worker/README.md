# GovShield scanner worker

The GovShield control plane runs on an edge runtime that cannot start processes,
so the scanners live here: a container that pulls queued assessments from the
platform, runs the real engines, and posts normalised findings back.

## Engines

| Target type | Engines |
| --- | --- |
| Git repository (SAST/SCA) | gitleaks (secrets), semgrep (OWASP Top 10 + security-audit), trivy fs (dependencies), checkov (repo IaC) |
| Container image / SBOM | syft (SPDX inventory), trivy image (vulnerabilities) |
| Cloud IaC | checkov (Terraform/CFN/Kubernetes policy), trivy config |
| Web application (DAST) | nuclei (active templates) plus a built-in TLS and security-header baseline |

Correlation against CISA KEV, FIRST EPSS and NIST NVD, the NIST SP 800-53
control crosswalk, FedRAMP baseline assignment and privacy tagging all happen in
the control plane — the worker only executes and normalises.

## Enrol a worker

1. Sign in to the console as an **Admin**.
2. Open **Scan → Worker fleet → Enrol worker**, name it, and choose which target
   types it may claim.
3. Copy the key that is shown once. Only its SHA-256 hash is stored.

## Run it

```bash
docker build -t govshield-worker ./worker

docker run -d --name govshield-worker \
  -e GOVSHIELD_URL="https://project--7711b643-feb8-4754-817c-2f8355738feb.lovable.app" \
  -e GOVSHIELD_WORKER_KEY="wrk-....<secret>" \
  govshield-worker
```

For container image scanning, mount the Docker socket or provide registry
credentials via the usual `DOCKER_CONFIG` mechanism. For private git targets,
supply credentials through a mounted `~/.git-credentials` or an SSH agent.

### Deploying on Fly.io

```bash
fly launch --no-deploy --dockerfile worker/Dockerfile
fly secrets set GOVSHIELD_URL=... GOVSHIELD_WORKER_KEY=...
fly deploy
```

A single worker processes one assessment at a time; run more machines to scan in
parallel. Jobs whose worker stops sending heartbeats for 20 minutes return to the
queue automatically and are abandoned after three attempts.

## Protocol

All three endpoints require the `x-govshield-worker-key` header.

| Endpoint | Purpose |
| --- | --- |
| `POST /api/public/hooks/worker/claim` | Atomically claim the oldest queued job matching the worker's capabilities |
| `POST /api/public/hooks/worker/progress` | Stage updates and heartbeats |
| `POST /api/public/hooks/worker/result` | Terminal findings payload, or a failure report |

## Authorisation

Active web testing is only launched for targets an operator explicitly confirms
they are authorised to assess; that confirmation is written to the tamper-evident
audit ledger alongside the queued job.

## Deploying

Step-by-step hosting instructions live in [DEPLOY.md](./DEPLOY.md).
