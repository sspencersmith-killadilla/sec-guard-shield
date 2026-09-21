import { Activity, Database, RadioTower, RefreshCw, Shield, Timer } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { useGovShield } from "@/lib/govshield/state";

function ago(ms: number) {
  if (!ms) return "—";
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  return `${Math.floor(m / 60)}h ${m % 60}m ago`;
}

function countdown(ms: number) {
  if (!ms) return "--:--";
  const total = Math.floor(ms / 1000);
  return `${String(Math.floor(total / 60)).padStart(2, "0")}:${String(total % 60).padStart(2, "0")}`;
}

export function ThreatFeedPanel() {
  const {
    feeds,
    feedRows,
    plugins,
    autoUpdate,
    toggleAutoUpdate,
    syncing,
    syncNow,
    lastSync,
    nextSyncIn,
    canWrite,
    feedsLoading,
  } = useGovShield();
  const errorsById = new Map(feedRows.map((f) => [f.id, f.last_error]));

  return (
    <div className="grid gap-4 xl:grid-cols-3">
      <Card className="xl:col-span-2">
        <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
          <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
            <RadioTower className="size-4 text-primary" aria-hidden /> Upstream threat feeds
          </CardTitle>
          <Badge variant="outline" className="font-mono text-[10px] uppercase">
            {feeds.length} sources
          </Badge>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-2">
          {feedsLoading && (
            <p className="font-mono text-xs text-muted-foreground">Loading feed registry…</p>
          )}
          {feeds.map((feed) => (
            <div key={feed.id} className="rounded-sm border border-border bg-background p-4">
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-sm font-semibold text-foreground">{feed.name}</p>
                  <p className="font-mono text-[11px] text-muted-foreground">{feed.source}</p>
                </div>
                <span
                  className={`mt-1 size-2.5 shrink-0 rounded-full ${
                    feed.status === "syncing"
                      ? "animate-pulse bg-medium"
                      : feed.status === "degraded"
                        ? "bg-high"
                        : "bg-success"
                  }`}
                  aria-label={feed.status}
                />
              </div>
              <dl className="mt-3 grid grid-cols-3 gap-2 font-mono text-[11px]">
                <div>
                  <dt className="text-muted-foreground">Records</dt>
                  <dd className="text-foreground">{feed.records.toLocaleString()}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Synced</dt>
                  <dd className="text-foreground">{ago(feed.lastSynced)}</dd>
                </div>
                <div>
                  <dt className="text-muted-foreground">Latency</dt>
                  <dd className="text-foreground">{feed.latencyMs}ms</dd>
                </div>
              </dl>
              {errorsById.get(feed.id) && (
                <p className="mt-3 break-words rounded-sm border border-high/40 bg-high/10 px-2 py-1 font-mono text-[10px] text-high">
                  {errorsById.get(feed.id)}
                </p>
              )}
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
            <Timer className="size-4 text-primary" aria-hidden /> Feed telemetry
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-sm border border-border bg-background p-4 font-mono text-xs">
            <div className="flex justify-between py-1">
              <span className="text-muted-foreground">Last synced</span>
              <span>{lastSync ? new Date(lastSync).toISOString().slice(11, 19) + " UTC" : "—"}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-muted-foreground">Next auto-sync</span>
              <span className="text-primary">{autoUpdate ? countdown(nextSyncIn) : "PAUSED"}</span>
            </div>
            <div className="flex justify-between py-1">
              <span className="text-muted-foreground">Status</span>
              <span className={syncing ? "text-medium" : "text-success"}>
                {syncing ? "INGESTING" : "IDLE / NOMINAL"}
              </span>
            </div>
          </div>

          <div className="flex items-center justify-between rounded-sm border border-border bg-background p-3">
            <div>
              <p className="text-sm font-medium">Auto-update rules</p>
              <p className="text-xs text-muted-foreground">Hot-reload detection signatures</p>
            </div>
            <Switch checked={autoUpdate} onCheckedChange={toggleAutoUpdate} aria-label="Auto-update rules" />
          </div>

          <Button onClick={syncNow} disabled={syncing || !canWrite} className="w-full gap-2 font-mono uppercase">
            <RefreshCw className={`size-4 ${syncing ? "animate-spin" : ""}`} aria-hidden />
            {syncing ? "Synchronizing feeds" : "Sync now"}
          </Button>
          {!canWrite && (
            <p className="text-xs text-muted-foreground">Read-Only Auditor scope cannot trigger feed operations.</p>
          )}
        </CardContent>
      </Card>

      <Card className="xl:col-span-3">
        <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
          <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
            <Activity className="size-4 text-primary" aria-hidden /> Dynamic rule engine
          </CardTitle>
          <span className="font-mono text-[11px] text-success">SIGNATURES HOT-LOADED · NO RESTART REQUIRED</span>
        </CardHeader>
        <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {plugins.map((p) => (
            <div key={p.id} className="flex items-center gap-3 rounded-sm border border-border bg-background p-3">
              <Shield className="size-4 shrink-0 text-primary" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{p.name}</p>
                <p className="truncate font-mono text-[11px] text-muted-foreground">{p.coverage}</p>
              </div>
              <div className="text-right">
                <span className="block font-mono text-[11px] text-primary">{p.signature}</span>
                <span className="font-mono text-[10px] uppercase text-success">active</span>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card className="xl:col-span-3">
        <CardContent className="flex flex-wrap items-center gap-4 pt-6 font-mono text-[11px] text-muted-foreground">
          <Database className="size-4 text-primary" aria-hidden />
          <span>CVE ingestion pipeline: NVD 2.0 delta pull → KEV enrichment → EPSS scoring → ATT&CK technique mapping</span>
        </CardContent>
      </Card>
    </div>
  );
}
