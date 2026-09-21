import { useState } from "react";
import { Check, Copy, KeyRound, Rocket, Server, ShieldCheck, Terminal } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

const CONSOLE_URL = "https://securityguard.civicplexus.org";

function CodeBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // clipboard unavailable — user can select the text manually
    }
  };
  return (
    <div className="group relative">
      <pre className="overflow-x-auto rounded-sm border border-border bg-background p-3 pr-10 font-mono text-[11px] leading-relaxed text-foreground">
        <code>{code}</code>
      </pre>
      <button
        type="button"
        onClick={copy}
        aria-label="Copy command"
        className="absolute right-2 top-2 rounded-sm border border-border bg-surface p-1.5 text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-2 focus-visible:outline-ring"
      >
        {copied ? (
          <Check className="size-3.5 text-success" aria-hidden />
        ) : (
          <Copy className="size-3.5" aria-hidden />
        )}
      </button>
    </div>
  );
}

function Step({
  n,
  title,
  children,
}: {
  n: number;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="rounded-sm border border-border bg-surface">
      <div className="flex items-center gap-3 border-b border-border px-4 py-3">
        <span
          className="flex size-6 shrink-0 items-center justify-center rounded-sm bg-primary font-mono text-[11px] font-semibold text-primary-foreground"
          aria-hidden
        >
          {n}
        </span>
        <h3 className="font-mono text-xs uppercase tracking-wider text-foreground">{title}</h3>
      </div>
      <div className="space-y-3 px-4 py-4 text-sm text-foreground">{children}</div>
    </section>
  );
}

export function SetupPanel() {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
          <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
            <Rocket className="size-4 text-primary" aria-hidden /> Scanner deployment guide
          </CardTitle>
          <Badge variant="outline" className="font-mono text-[10px] uppercase">
            ~15 min · once
          </Badge>
        </CardHeader>
        <CardContent className="space-y-3 text-sm">
          <p>
            The GovShield console runs on managed hosting, which cannot start scanning
            programs. The scanner is a separate always-on machine that connects out to
            this console, picks up queued assessments, runs the engines, and sends
            results back. Until at least one machine is connected, assessments stay
            queued.
          </p>
          <p className="font-mono text-[11px] text-muted-foreground">
            Budget roughly $5–15/month for one scanner on Fly.io. Everything below is
            copy-paste; a card on file with the host is the only requirement.
          </p>
        </CardContent>
      </Card>

      <div className="grid gap-4 xl:grid-cols-2">
        <div className="space-y-4">
          <Step n={1} title="Get a worker key from this console">
            <ol className="list-decimal space-y-1 pl-5">
              <li>
                Sign in at <span className="font-mono text-[12px]">{CONSOLE_URL}</span> as
                an Admin.
              </li>
              <li>
                Go to <strong>New Scan → Worker fleet → Enrol worker</strong>.
              </li>
              <li>
                Name it (for example <span className="font-mono text-[12px]">dmz-scanner-01</span>),
                tick the scan types it may run (SAST, SBOM, IAC, DAST), and press{" "}
                <strong>Issue worker key</strong>.
              </li>
              <li>
                Copy the key immediately — it is shown once, and only its fingerprint is
                kept.
              </li>
            </ol>
            <p className="flex items-center gap-2 font-mono text-[11px] text-muted-foreground">
              <KeyRound className="size-3.5" aria-hidden /> Keep the key safe for step 3.
            </p>
          </Step>

          <Step n={2} title="Install the Fly.io tool and sign in">
            <p className="text-muted-foreground">
              On your Mac or Windows machine, open a terminal and run:
            </p>
            <CodeBlock
              code={`# macOS / Linux\ncurl -L https://fly.io/install.sh | sh\nfly auth signup      # or: fly auth login`}
            />
            <CodeBlock
              code={`# Windows (PowerShell)\niwr https://fly.io/install.ps1 -useb | iex\nfly auth signup`}
            />
          </Step>

          <Step n={3} title="Deploy the scanner">
            <p className="text-muted-foreground">
              Download this project's code (Lovable → GitHub, or the download option),
              open a terminal in the project folder, then:
            </p>
            <CodeBlock
              code={`cd worker\nfly launch --no-deploy --copy-config --name govshield-scanner-YOURNAME\nfly secrets set \\\n  GOVSHIELD_URL="${CONSOLE_URL}" \\\n  GOVSHIELD_WORKER_KEY="paste-the-key-from-step-1"\nfly deploy`}
            />
            <p className="text-muted-foreground">
              Pick your own unique name in place of{" "}
              <span className="font-mono text-[12px]">govshield-scanner-YOURNAME</span>.
              The first build takes 5–10 minutes because it installs all the scanning
              engines.
            </p>
          </Step>
        </div>

        <div className="space-y-4">
          <Step n={4} title="Confirm it is connected">
            <CodeBlock code={`fly logs`} />
            <p className="text-muted-foreground">
              You should see the scanner polling for work. Then reload{" "}
              <strong>New Scan → Worker fleet</strong> here: your machine appears with a
              green dot within about a minute.
            </p>
          </Step>

          <Step n={5} title="Run a real assessment">
            <ol className="list-decimal space-y-1 pl-5">
              <li>
                Go to <strong>New Scan</strong>, choose a target type, and enter the
                target — a public Git repository URL is the easiest first test, for
                example{" "}
                <span className="font-mono text-[12px]">
                  https://github.com/juice-shop/juice-shop
                </span>
                .
              </li>
              <li>Tick the test modules you want.</li>
              <li>
                Tick the authorisation attestation — required, and recorded in the audit
                ledger with your name.
              </li>
              <li>
                Press <strong>Queue assessment</strong>. Progress updates come from the
                scanner itself; results land in <strong>Findings</strong> when it
                finishes.
              </li>
            </ol>
          </Step>

          <Card>
            <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
              <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
                <Server className="size-4 text-primary" aria-hidden /> Other hosts
              </CardTitle>
              <Badge variant="outline" className="font-mono text-[10px] uppercase">
                <Terminal className="mr-1 size-3" aria-hidden /> any Docker host
              </Badge>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <p className="text-muted-foreground">
                Any Docker host works. The machine needs outbound internet, about 4 GB
                of memory, and these two settings:
              </p>
              <ul className="space-y-1 font-mono text-[11px]">
                <li>GOVSHIELD_URL = {CONSOLE_URL}</li>
                <li>GOVSHIELD_WORKER_KEY = the key from step 1</li>
              </ul>
              <p className="font-semibold">Google Cloud Run (always-on service):</p>
              <CodeBlock
                code={`gcloud run deploy govshield-scanner --source worker --no-allow-unauthenticated \\\n  --min-instances 1 --cpu 2 --memory 4Gi \\\n  --set-env-vars GOVSHIELD_URL=${CONSOLE_URL} \\\n  --set-env-vars GOVSHIELD_WORKER_KEY=paste-the-key`}
              />
              <p className="font-semibold">Your own server or VM:</p>
              <CodeBlock
                code={`docker build -t govshield-worker ./worker\ndocker run -d --restart unless-stopped --name govshield-worker \\\n  -e GOVSHIELD_URL="${CONSOLE_URL}" \\\n  -e GOVSHIELD_WORKER_KEY="paste-the-key" \\\n  govshield-worker`}
              />
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="space-y-0">
              <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
                <ShieldCheck className="size-4 text-primary" aria-hidden /> Notes
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm text-muted-foreground">
              <p>
                One machine runs one assessment at a time. Deploy more machines (each
                with its own key) to scan in parallel.
              </p>
              <p>
                If a machine goes offline mid-scan, the job returns to the queue
                automatically after 20 minutes and is abandoned after three attempts.
              </p>
              <p>
                To retire a machine: <strong>Worker fleet → Revoke</strong>, then{" "}
                <span className="font-mono text-[12px]">fly apps destroy</span>.
              </p>
              <p>
                Scanning private repositories or private container images needs
                credentials mounted into the machine — just ask.
              </p>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
