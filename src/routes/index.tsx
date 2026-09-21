import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { ShieldCheck, RadioTower, FileLock2, Workflow, ArrowRight } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";

const TITLE = "GovShield SecOps — FedRAMP-Aligned Security Testing & Compliance Console";
const DESCRIPTION =
  "Centralized security testing and compliance auditing for web apps, APIs, code and cloud workloads — with live CISA KEV, NVD, MITRE ATT&CK and EPSS intelligence mapped to NIST SP 800-53 and FedRAMP baselines.";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: TITLE },
      { name: "description", content: DESCRIPTION },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESCRIPTION },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: LandingPage,
});

const PILLARS = [
  {
    icon: RadioTower,
    title: "Live threat intelligence",
    body: "CISA KEV, NIST NVD 2.0, FIRST EPSS and MITRE ATT&CK are polled on a schedule and stored, with real sync timestamps and per-run telemetry.",
  },
  {
    icon: FileLock2,
    title: "Tamper-evident ledger",
    body: "Every privileged action is appended to a hash-chained log the database itself refuses to update or delete, supporting NIST AU-2 and AU-9.",
  },
  {
    icon: Workflow,
    title: "Control crosswalk",
    body: "Findings correlate to NIST SP 800-53 Rev. 5 controls, FedRAMP Moderate and High baselines, FIPS 140-3 flags and Privacy Framework categories.",
  },
];

function LandingPage() {
  const [signedIn, setSignedIn] = useState(false);

  useEffect(() => {
    void supabase.auth.getSession().then(({ data }) => setSignedIn(Boolean(data.session)));
    const { data: sub } = supabase.auth.onAuthStateChange((_e, session) => setSignedIn(Boolean(session)));
    return () => sub.subscription.unsubscribe();
  }, []);

  return (
    <div className="min-h-screen bg-background">
      <div className="h-1 w-full gov-stripe" aria-hidden />
      <header className="border-b border-border bg-surface">
        <div className="mx-auto flex max-w-[1200px] items-center gap-3 px-4 py-4 sm:px-6">
          <div className="flex size-9 items-center justify-center rounded-sm border border-primary/40 bg-primary/10">
            <ShieldCheck className="size-5 text-primary" aria-hidden />
          </div>
          <div>
            <p className="text-lg font-semibold uppercase tracking-[0.18em]">GovShield SecOps</p>
            <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              FedRAMP-aligned assessment platform
            </p>
          </div>
          <div className="ml-auto">
            <Button asChild size="sm" className="gap-2 font-mono text-xs uppercase">
              <Link to={signedIn ? "/console" : "/auth"}>
                {signedIn ? "Open console" : "Sign in"}
                <ArrowRight className="size-3.5" aria-hidden />
              </Link>
            </Button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1200px] px-4 py-16 sm:px-6">
        <section className="max-w-3xl">
          <p className="font-mono text-[11px] uppercase tracking-[0.3em] text-primary">
            Continuous authorization support
          </p>
          <h1 className="mt-4 text-4xl font-semibold leading-tight tracking-tight sm:text-5xl">
            Security testing and compliance evidence, held to government standards.
          </h1>
          <p className="mt-5 text-base leading-relaxed text-muted-foreground">
            GovShield evaluates web applications, APIs, source code and cloud workloads against modern government
            security standards, while staying aligned with evolving global threat intelligence.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Button asChild className="gap-2 font-mono uppercase">
              <Link to={signedIn ? "/console" : "/auth"}>
                {signedIn ? "Open console" : "Request access"}
                <ArrowRight className="size-4" aria-hidden />
              </Link>
            </Button>
          </div>
        </section>

        <section className="mt-16 grid gap-4 md:grid-cols-3">
          {PILLARS.map((p) => (
            <div key={p.title} className="rounded-sm border border-border bg-surface p-6">
              <p.icon className="size-5 text-primary" aria-hidden />
              <h2 className="mt-4 text-base font-semibold uppercase tracking-wider">{p.title}</h2>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{p.body}</p>
            </div>
          ))}
        </section>

        <section className="mt-12 rounded-sm border border-border bg-surface p-6">
          <h2 className="font-mono text-xs uppercase tracking-wider text-muted-foreground">Current capability</h2>
          <p className="mt-2 max-w-3xl text-sm leading-relaxed text-muted-foreground">
            Accounts, role scoping, the audit ledger and the threat intelligence pipeline run against live data. Scan
            execution against your own repositories, containers and running sites is the next stage of the build and is
            still represented with sample findings.
          </p>
        </section>
      </main>

      <footer className="border-t border-border bg-surface">
        <div className="mx-auto max-w-[1200px] px-4 py-6 font-mono text-[11px] uppercase tracking-wider text-muted-foreground sm:px-6">
          NIST SP 800-53 Rev.5 · FedRAMP Moderate/High · FIPS 140-3 · NIST Privacy Framework 1.0 · OSCAL
        </div>
      </footer>
    </div>
  );
}
