# Getting the scanner machine running

The GovShield console runs on Lovable's hosting, which cannot start scanning
programs. The scanner is a separate always-on machine that connects out to the
console, picks up queued assessments, runs the engines, and sends results back.
These steps take about 15 minutes, once.

Everything below is copy-paste. You need a card on file with the host (roughly
$5–15/month for one scanner); nothing else is required.

---

## Step 1 — Get a worker key from the console

1. Sign in at https://sec-guard-shield.lovable.app as an Admin.
2. Go to **Scan → Worker fleet → Enrol worker**.
3. Name it (for example `dmz-scanner-01`), tick the scan types it may run
   (SAST, SBOM, IAC, DAST), and press **Issue worker key**.
4. Copy the key immediately — it is shown once and only its fingerprint is kept.

Keep the key somewhere safe for Step 3.

---

## Step 2 — Install the Fly.io tool and sign in

On your Mac or Windows machine, open a terminal and run:

macOS / Linux:
```bash
curl -L https://fly.io/install.sh | sh
fly auth signup      # or: fly auth login
```

Windows (PowerShell):
```powershell
iwr https://fly.io/install.ps1 -useb | iex
fly auth signup
```

---

## Step 3 — Deploy the scanner

Download this project's code (Lovable → GitHub, or the download option), open a
terminal in the project folder, then:

```bash
cd worker
fly launch --no-deploy --copy-config --name govshield-scanner-YOURNAME
fly secrets set \
  GOVSHIELD_URL="https://sec-guard-shield.lovable.app" \
  GOVSHIELD_WORKER_KEY="paste-the-key-from-step-1"
fly deploy
```

Pick your own unique name in place of `govshield-scanner-YOURNAME`. The first
build takes 5–10 minutes because it installs all the scanning engines.

---

## Step 4 — Confirm it is connected

```bash
fly logs
```

You should see the scanner reporting that it is polling for work. Then reload
**Scan → Worker fleet** in the console: your machine appears with a green dot
within about a minute.

---

## Step 5 — Run a real assessment

1. Go to **Scan**, choose a target type, and enter the target
   (a public Git repository URL is the easiest first test, for example
   `https://github.com/juice-shop/juice-shop`).
2. Tick the test modules you want.
3. Tick the authorisation attestation — required, and recorded in the audit
   ledger with your name.
4. Press **Queue assessment**. Progress updates come from the scanner itself;
   results land in **Findings** when it finishes.

---

## Other hosts

Any Docker host works. The machine needs outbound internet, about 4 GB of
memory, and these two settings:

- `GOVSHIELD_URL` = `https://sec-guard-shield.lovable.app`
- `GOVSHIELD_WORKER_KEY` = the key from Step 1

Google Cloud Run (as a always-on service, minimum instances 1):
```bash
gcloud run deploy govshield-scanner --source worker --no-allow-unauthenticated \
  --min-instances 1 --cpu 2 --memory 4Gi \
  --set-env-vars GOVSHIELD_URL=https://sec-guard-shield.lovable.app \
  --set-env-vars GOVSHIELD_WORKER_KEY=paste-the-key
```

Your own server or VM:
```bash
docker build -t govshield-worker ./worker
docker run -d --restart unless-stopped --name govshield-worker \
  -e GOVSHIELD_URL="https://sec-guard-shield.lovable.app" \
  -e GOVSHIELD_WORKER_KEY="paste-the-key" \
  govshield-worker
```

---

## Notes

- One machine runs one assessment at a time. Deploy more machines (each with
  its own key) to scan in parallel.
- If a machine goes offline mid-scan, the job returns to the queue
  automatically after 20 minutes and is abandoned after three attempts.
- To retire a machine: **Worker fleet → Revoke**, then `fly apps destroy`.
- Scanning private repositories or private container images needs credentials
  mounted into the machine — ask and I'll wire that up.
