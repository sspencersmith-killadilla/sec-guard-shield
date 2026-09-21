import { useState } from "react";
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Crosshair,
  KeyRound,
  Loader2,
  Play,
  RotateCcw,
  ServerCog,
  XCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { TARGET_TYPES, TEST_MODULES } from "@/lib/govshield/data";
import { useGovShield } from "@/lib/govshield/state";
import type { ModuleKey, ScanMode, TargetType } from "@/lib/govshield/types";

const STATUS_STYLES: Record<string, string> = {
  queued: "border-medium/40 text-medium",
  claimed: "border-primary/40 text-primary",
  running: "border-primary/40 text-primary",
  completed: "border-success/40 text-success",
  failed: "border-critical/40 text-critical",
  cancelled: "border-border text-muted-foreground",
};

function relative(ts: string) {
  const diff = Date.now() - Date.parse(ts);
  const mins = Math.round(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  return hrs < 24 ? `${hrs}h ago` : `${Math.round(hrs / 24)}d ago`;
}

export function ScanPanel({ onComplete }: { onComplete: () => void }) {
  const {
    config,
    updateConfig,
    startScan,
    cancelScan,
    resetScan,
    scanning,
    scanProgress,
    scanStageLabel,
    scanEvents,
    scanError,
    queueError,
    selectedScan,
    scans,
    selectScan,
    hasResults,
    canWrite,
    workers,
  } = useGovShield();

  const active = TARGET_TYPES.find((t) => t.id === config.target)!;
  const onlineWorkers = workers.filter(
    (w) => !w.revoked_at && w.last_seen_at && Date.now() - Date.parse(w.last_seen_at) < 120_000,
  );
  const capable = onlineWorkers.filter((w) => w.capabilities.includes(config.target));

  if (scanning && selectedScan) {
    return (
      <div className="mx-auto max-w-2xl space-y-4">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
              <Loader2 className="size-4 animate-spin text-primary" aria-hidden /> Assessment in progress
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-6">
            <Progress value={scanProgress} className="h-1.5" />
            <p className="font-mono text-sm text-foreground">{scanStageLabel}</p>

            <ol className="space-y-2" aria-live="polite">
              {scanEvents.map((e, i) => {
                const current = i === scanEvents.length - 1;
                return (
                  <li
                    key={e.id}
                    className={`flex items-start gap-3 rounded-sm border p-3 font-mono text-xs ${
                      current
                        ? "border-primary/50 bg-primary/10 text-foreground"
                        : "border-border bg-background text-muted-foreground"
                    }`}
                  >
                    {current ? (
                      <Loader2 className="mt-0.5 size-3.5 shrink-0 animate-spin text-primary" aria-hidden />
                    ) : (
                      <CheckCircle2 className="mt-0.5 size-3.5 shrink-0 text-success" aria-hidden />
                    )}
                    <span className="min-w-0">
                      <span className="block uppercase">{e.stage}</span>
                      {e.message && <span className="block text-muted-foreground">{e.message}</span>}
                    </span>
                  </li>
                );
              })}
            </ol>

            {selectedScan.status === "queued" && !capable.length && (
              <p className="rounded-sm border border-medium/40 bg-medium/10 p-3 text-xs text-medium">
                No worker is currently online for {active.label} targets. The job stays queued until one connects.
              </p>
            )}

            <p className="text-center font-mono text-[11px] uppercase text-muted-foreground">
              {selectedScan.target_value} · {selectedScan.worker_id ?? "awaiting worker"}
            </p>
            {canWrite && (
              <Button variant="outline" className="w-full gap-2 font-mono text-xs uppercase" onClick={cancelScan}>
                <XCircle className="size-3.5" aria-hidden /> Cancel assessment
              </Button>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="grid gap-4 lg:grid-cols-3">
      <Card className="lg:col-span-2">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
            <Crosshair className="size-4 text-primary" aria-hidden /> Target scope
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-5">
          <div className="grid gap-3 sm:grid-cols-2">
            {TARGET_TYPES.map((t) => {
              const selected = config.target === t.id;
              const ready = onlineWorkers.some((w) => w.capabilities.includes(t.id));
              return (
                <button
                  key={t.id}
                  type="button"
                  aria-pressed={selected}
                  onClick={() => updateConfig({ target: t.id as TargetType, value: "" })}
                  className={`rounded-sm border p-4 text-left transition-colors ${
                    selected
                      ? "border-primary bg-primary/10"
                      : "border-border bg-background hover:border-primary/50 hover:bg-surface-raised"
                  }`}
                >
                  <p className="flex items-center gap-2 text-sm font-semibold">
                    {t.label}
                    <span
                      className={`size-1.5 rounded-full ${ready ? "bg-success" : "bg-muted-foreground/40"}`}
                      aria-label={ready ? "Worker online" : "No worker online"}
                    />
                  </p>
                  <p className="font-mono text-[11px] uppercase text-muted-foreground">{t.engine}</p>
                </button>
              );
            })}
          </div>

          <div className="space-y-2">
            <Label htmlFor="target-value" className="font-mono text-[11px] uppercase text-muted-foreground">
              Target identifier
            </Label>
            <Input
              id="target-value"
              value={config.value}
              placeholder={active.placeholder}
              disabled={!canWrite}
              onChange={(e) => updateConfig({ value: e.target.value })}
              className="bg-background font-mono text-sm"
            />
          </div>

          <fieldset className="space-y-3">
            <legend className="font-mono text-[11px] uppercase text-muted-foreground">Test modules</legend>
            <div className="grid gap-2 sm:grid-cols-2">
              {TEST_MODULES.map((m) => (
                <label
                  key={m.id}
                  htmlFor={`mod-${m.id}`}
                  className="flex cursor-pointer items-start gap-3 rounded-sm border border-border bg-background p-3 hover:border-primary/40"
                >
                  <Checkbox
                    id={`mod-${m.id}`}
                    checked={config.modules.includes(m.id)}
                    disabled={!canWrite}
                    onCheckedChange={(v) =>
                      updateConfig({
                        modules: v === true
                          ? [...config.modules, m.id]
                          : config.modules.filter((x) => x !== m.id),
                      })
                    }
                    className="mt-0.5"
                  />
                  <span>
                    <span className="block text-sm font-medium">{m.label}</span>
                    <span className="block text-xs text-muted-foreground">{m.detail}</span>
                  </span>
                </label>
              ))}
            </div>
          </fieldset>

          <label
            htmlFor="authorized"
            className="flex cursor-pointer items-start gap-3 rounded-sm border border-high/40 bg-high/5 p-3"
          >
            <Checkbox
              id="authorized"
              checked={config.authorized}
              disabled={!canWrite}
              onCheckedChange={(v) => updateConfig({ authorized: v === true })}
              className="mt-0.5"
            />
            <span>
              <span className="flex items-center gap-2 text-sm font-medium">
                <AlertTriangle className="size-3.5 text-high" aria-hidden /> Authorisation attestation
              </span>
              <span className="block text-xs text-muted-foreground">
                I am authorised to conduct security testing against this target. This attestation is written to the
                audit ledger with my identity.
              </span>
            </span>
          </label>
        </CardContent>
      </Card>

      <div className="space-y-4">
        <Card>
          <CardHeader>
            <CardTitle className="text-base uppercase tracking-wider">Scan mode</CardTitle>
          </CardHeader>
          <CardContent className="space-y-5">
            <RadioGroup
              value={config.mode}
              onValueChange={(v) => updateConfig({ mode: v as ScanMode })}
              className="space-y-2"
            >
              <label
                htmlFor="mode-standard"
                className="flex cursor-pointer items-start gap-3 rounded-sm border border-border bg-background p-3"
              >
                <RadioGroupItem value="standard" id="mode-standard" className="mt-0.5" disabled={!canWrite} />
                <span>
                  <span className="block text-sm font-medium">Standard scan</span>
                  <span className="block text-xs text-muted-foreground">One-off point-in-time assessment</span>
                </span>
              </label>
              <label
                htmlFor="mode-conmon"
                className="flex cursor-pointer items-start gap-3 rounded-sm border border-border bg-background p-3"
              >
                <RadioGroupItem value="conmon" id="mode-conmon" className="mt-0.5" disabled={!canWrite} />
                <span>
                  <span className="block text-sm font-medium">Continuous monitoring (ConMon)</span>
                  <span className="block text-xs text-muted-foreground">Recurring schedule per FedRAMP ConMon</span>
                </span>
              </label>
            </RadioGroup>

            {config.mode === "conmon" && (
              <div className="space-y-2">
                <Label htmlFor="cadence" className="font-mono text-[11px] uppercase text-muted-foreground">
                  Cadence
                </Label>
                <Select value={config.cadence} onValueChange={(v) => updateConfig({ cadence: v })}>
                  <SelectTrigger id="cadence" className="bg-background font-mono text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {["Every 6 hours", "Every 24 hours", "Weekly", "Monthly (FedRAMP minimum)"].map((c) => (
                      <SelectItem key={c} value={c} className="font-mono text-xs">
                        {c}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            <div className="rounded-sm border border-border bg-background p-3 font-mono text-[11px] text-muted-foreground">
              <p>ENGINE · {active.engine}</p>
              <p>MODULES · {config.modules.length} enabled</p>
              <p>WORKERS · {capable.length} online for this target</p>
            </div>

            {queueError && (
              <p className="rounded-sm border border-critical/40 bg-critical/10 p-3 text-xs text-critical">
                {queueError}
              </p>
            )}

            <Button
              className="w-full gap-2 font-mono uppercase"
              size="lg"
              disabled={!canWrite || config.modules.length === 0 || !config.value.trim() || !config.authorized}
              onClick={() => {
                startScan();
                onComplete();
              }}
            >
              <Play className="size-4" aria-hidden /> Queue assessment
            </Button>
            {hasResults && (
              <Button variant="outline" className="w-full gap-2 font-mono text-xs uppercase" onClick={resetScan}>
                <RotateCcw className="size-3.5" aria-hidden /> Clear selection
              </Button>
            )}
            {!canWrite && (
              <p className="text-xs text-muted-foreground">
                Read-Only Auditor scope may review findings and audit logs but cannot execute scans.
              </p>
            )}
            {scanError && (
              <p className="rounded-sm border border-critical/40 bg-critical/10 p-3 font-mono text-[11px] text-critical">
                {scanError}
              </p>
            )}
          </CardContent>
        </Card>

        <WorkerFleet />
      </div>

      {scans.length > 0 && (
        <Card className="lg:col-span-3">
          <CardHeader>
            <CardTitle className="text-base uppercase tracking-wider">Assessment history</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {scans.slice(0, 10).map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => selectScan(s.id)}
                className={`flex w-full flex-wrap items-center gap-3 rounded-sm border p-3 text-left font-mono text-xs transition-colors ${
                  selectedScan?.id === s.id
                    ? "border-primary bg-primary/10"
                    : "border-border bg-background hover:border-primary/40"
                }`}
              >
                <span className={`rounded-sm border px-1.5 py-0.5 uppercase ${STATUS_STYLES[s.status]}`}>
                  {s.status}
                </span>
                <span className="uppercase text-muted-foreground">{s.target_type}</span>
                <span className="min-w-0 flex-1 truncate text-foreground">{s.target_value}</span>
                <span className="text-muted-foreground">
                  {s.status === "completed" ? `${s.findings_count} findings · ${s.posture}%` : s.stage}
                </span>
                <span className="text-muted-foreground">{relative(s.queued_at)}</span>
              </button>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function WorkerFleet() {
  const { workers, isAdmin, issueWorkerKey, revokeWorker } = useGovShield();
  const [name, setName] = useState("");
  const [caps, setCaps] = useState<TargetType[]>(["sast", "sbom", "iac", "dast"]);
  const [issued, setIssued] = useState<{ workerId: string; key: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const enrol = async () => {
    setBusy(true);
    setError(null);
    try {
      setIssued(await issueWorkerKey(name, caps));
      setName("");
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
          <ServerCog className="size-4 text-primary" aria-hidden /> Worker fleet
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {workers.length === 0 && (
          <p className="text-xs text-muted-foreground">
            No scanner workers enrolled. Scans stay queued until a worker container connects.
          </p>
        )}

        {workers.map((w) => {
          const online = !w.revoked_at && w.last_seen_at && Date.now() - Date.parse(w.last_seen_at) < 120_000;
          return (
            <div key={w.id} className="rounded-sm border border-border bg-background p-3">
              <div className="flex items-center gap-2">
                <span
                  className={`size-2 rounded-full ${w.revoked_at ? "bg-critical" : online ? "bg-success" : "bg-muted-foreground/40"}`}
                  aria-hidden
                />
                <span className="min-w-0 flex-1 truncate text-sm font-medium">{w.name}</span>
                {isAdmin && !w.revoked_at && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 px-2 font-mono text-[10px] uppercase text-muted-foreground"
                    onClick={() => revokeWorker(w.id)}
                  >
                    Revoke
                  </Button>
                )}
              </div>
              <p className="mt-1 font-mono text-[11px] text-muted-foreground">
                {w.capabilities.join(" · ") || "no capabilities"}
                {w.version ? ` · v${w.version}` : ""}
                {w.revoked_at
                  ? " · revoked"
                  : w.last_seen_at
                    ? ` · seen ${relative(w.last_seen_at)}`
                    : " · never connected"}
              </p>
            </div>
          );
        })}

        {isAdmin && (
          <div className="space-y-3 border-t border-border pt-3">
            <Label htmlFor="worker-name" className="font-mono text-[11px] uppercase text-muted-foreground">
              Enrol a worker
            </Label>
            <Input
              id="worker-name"
              value={name}
              placeholder="dmz-scanner-01"
              onChange={(e) => setName(e.target.value)}
              className="bg-background font-mono text-xs"
            />
            <div className="flex flex-wrap gap-2">
              {(["sast", "sbom", "iac", "dast"] as TargetType[]).map((c) => (
                <label key={c} htmlFor={`cap-${c}`} className="flex cursor-pointer items-center gap-1.5">
                  <Checkbox
                    id={`cap-${c}`}
                    checked={caps.includes(c)}
                    onCheckedChange={(v) =>
                      setCaps(v === true ? [...caps, c] : caps.filter((x) => x !== c))
                    }
                  />
                  <span className="font-mono text-[11px] uppercase">{c}</span>
                </label>
              ))}
            </div>
            <Button
              variant="outline"
              className="w-full gap-2 font-mono text-xs uppercase"
              disabled={busy || !name.trim() || caps.length === 0}
              onClick={enrol}
            >
              <KeyRound className="size-3.5" aria-hidden /> Issue worker key
            </Button>
            {error && <p className="text-xs text-critical">{error}</p>}
            {issued && (
              <div className="space-y-2 rounded-sm border border-success/40 bg-success/10 p-3">
                <p className="text-xs text-foreground">
                  Copy this key now — only its hash is stored and it cannot be shown again.
                </p>
                <code className="block break-all rounded-sm bg-background p-2 font-mono text-[10px]">
                  {issued.key}
                </code>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 gap-1.5 px-2 font-mono text-[10px] uppercase"
                  onClick={() => navigator.clipboard.writeText(issued.key)}
                >
                  <Copy className="size-3" aria-hidden /> Copy key
                </Button>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
