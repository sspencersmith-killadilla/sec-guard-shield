import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { GovShieldProvider, useGovShield } from "@/lib/govshield/state";
import { TopBar } from "@/components/govshield/TopBar";
import { ThreatFeedPanel } from "@/components/govshield/ThreatFeedPanel";
import { ScanPanel } from "@/components/govshield/ScanPanel";
import { FindingsPanel } from "@/components/govshield/FindingsPanel";
import { AuditPanel } from "@/components/govshield/AuditPanel";
import { OverviewPanel } from "@/components/govshield/OverviewPanel";
import { SetupPanel } from "@/components/govshield/SetupPanel";
import { UsersPanel } from "@/components/govshield/UsersPanel";

const TITLE = "Assessment Console — GovShield SecOps";
const DESCRIPTION =
  "Role-scoped assessment console: live CISA KEV, NVD, EPSS and MITRE ATT&CK ingestion, NIST SP 800-53 crosswalk, and a tamper-evident audit ledger.";

export const Route = createFileRoute("/_authenticated/console")({
  head: () => ({
    meta: [
      { title: TITLE },
      { name: "description", content: DESCRIPTION },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESCRIPTION },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: ConsolePage,
});

function ConsolePage() {
  return (
    <GovShieldProvider>
      <Console />
    </GovShieldProvider>
  );
}

const TABS = [
  { id: "overview", label: "Overview" },
  { id: "feeds", label: "Threat Feeds" },
  { id: "scan", label: "New Scan" },
  { id: "findings", label: "Findings" },
  { id: "audit", label: "Audit Log" },
  { id: "users", label: "Users" },
  { id: "setup", label: "Setup" },
];

function Console() {
  const [tab, setTab] = useState("overview");
  const { hasResults, scanning, findings, isAdmin } = useGovShield() as ReturnType<typeof useGovShield> & { isAdmin: boolean };

  return (
    <div className="min-h-screen bg-background">
      <TopBar />
      <main className="mx-auto max-w-[1600px] px-4 py-6 sm:px-6">
        <Tabs value={tab} onValueChange={setTab} className="space-y-6">
          <TabsList className="h-auto w-full justify-start gap-1 overflow-x-auto rounded-sm border border-border bg-surface p-1">
            {TABS.filter((t) => t.id !== "users" || isAdmin).map((t) => (
              <TabsTrigger
                key={t.id}
                value={t.id}
                className="rounded-sm px-4 py-2 font-mono text-xs uppercase tracking-wider data-[state=active]:bg-primary data-[state=active]:text-primary-foreground"
              >
                {t.label}
                {t.id === "findings" && hasResults && (
                  <span className="ml-2 rounded-sm bg-critical/20 px-1.5 text-[10px] text-critical">
                    {findings.length}
                  </span>
                )}
              </TabsTrigger>
            ))}
          </TabsList>

          <TabsContent value="overview" className="mt-0">
            <OverviewPanel onStartScan={() => setTab("scan")} />
          </TabsContent>
          <TabsContent value="feeds" className="mt-0">
            <ThreatFeedPanel />
          </TabsContent>
          <TabsContent value="scan" className="mt-0">
            <ScanPanel onComplete={() => window.setTimeout(() => setTab("findings"), 4100)} />
          </TabsContent>
          <TabsContent value="findings" className="mt-0">
            {hasResults ? (
              <FindingsPanel />
            ) : (
              <p className="rounded-sm border border-border bg-surface p-10 text-center font-mono text-sm text-muted-foreground">
                {scanning ? "Assessment in progress…" : "No findings on record. Execute a scan to populate results."}
              </p>
            )}
          </TabsContent>
          <TabsContent value="audit" className="mt-0">
            <AuditPanel />
          </TabsContent>
          <TabsContent value="users" className="mt-0">
            <UsersPanel />
          </TabsContent>
          <TabsContent value="setup" className="mt-0">
            <SetupPanel />
          </TabsContent>
        </Tabs>
      </main>
      <footer className="border-t border-border bg-surface">
        <div className="mx-auto max-w-[1600px] px-4 py-4 font-mono text-[11px] uppercase tracking-wider text-muted-foreground sm:px-6">
          GovShield SecOps · Live threat intelligence · Live scan engine · NIST SP 800-53 Rev.5 · FedRAMP
          Moderate/High · FIPS 140-3 · NIST Privacy Framework 1.0
        </div>
      </footer>
    </div>
  );
}
