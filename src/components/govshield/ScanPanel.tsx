import { CheckCircle2, Loader2, Play, RotateCcw, Crosshair } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { SCAN_STAGES, TARGET_TYPES, TEST_MODULES } from "@/lib/govshield/data";
import { useGovShield } from "@/lib/govshield/state";
import type { ModuleKey, ScanMode, TargetType } from "@/lib/govshield/types";

export function ScanPanel({ onComplete }: { onComplete: () => void }) {
  const { config, updateConfig, startScan, resetScan, scanning, scanStage, hasResults, canWrite } = useGovShield();
  const active = TARGET_TYPES.find((t) => t.id === config.target)!;

  const toggleModule = (id: ModuleKey, on: boolean) => {
    updateConfig({ modules: on ? [...config.modules, id] : config.modules.filter((m) => m !== id) });
  };

  if (scanning) {
    return (
      <Card className="mx-auto max-w-2xl">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
            <Loader2 className="size-4 animate-spin text-primary" aria-hidden /> Assessment in progress
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          <Progress value={((scanStage + 1) / SCAN_STAGES.length) * 100} className="h-1.5" />
          <ol className="space-y-3" aria-live="polite">
            {SCAN_STAGES.map((stage, i) => {
              const done = i < scanStage;
              const current = i === scanStage;
              return (
                <li
                  key={stage}
                  className={`flex items-center gap-3 rounded-sm border p-3 font-mono text-sm ${
                    current
                      ? "border-primary/50 bg-primary/10 text-foreground"
                      : done
                        ? "border-border bg-background text-muted-foreground"
                        : "border-border/50 bg-background text-muted-foreground/60"
                  }`}
                >
                  {done ? (
                    <CheckCircle2 className="size-4 text-success" aria-hidden />
                  ) : current ? (
                    <Loader2 className="size-4 animate-spin text-primary" aria-hidden />
                  ) : (
                    <span className="size-4 rounded-full border border-border" aria-hidden />
                  )}
                  {stage}
                </li>
              );
            })}
          </ol>
          <p className="text-center font-mono text-[11px] uppercase text-muted-foreground">
            Target: {config.value || active.placeholder}
          </p>
        </CardContent>
      </Card>
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
              return (
                <button
                  key={t.id}
                  type="button"
                  aria-pressed={selected}
                  onClick={() => updateConfig({ target: t.id as TargetType, value: t.placeholder })}
                  className={`rounded-sm border p-4 text-left transition-colors ${
                    selected
                      ? "border-primary bg-primary/10"
                      : "border-border bg-background hover:border-primary/50 hover:bg-surface-raised"
                  }`}
                >
                  <p className="text-sm font-semibold">{t.label}</p>
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
                    onCheckedChange={(v) => toggleModule(m.id, v === true)}
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
        </CardContent>
      </Card>

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
            <p>BASELINE · FedRAMP Moderate + High overlay</p>
          </div>

          <Button
            className="w-full gap-2 font-mono uppercase"
            size="lg"
            disabled={!canWrite || config.modules.length === 0}
            onClick={() => {
              startScan();
              onComplete();
            }}
          >
            <Play className="size-4" aria-hidden /> Start scan
          </Button>
          {hasResults && (
            <Button variant="outline" className="w-full gap-2 font-mono text-xs uppercase" onClick={resetScan}>
              <RotateCcw className="size-3.5" aria-hidden /> Clear results
            </Button>
          )}
          {!canWrite && (
            <p className="text-xs text-muted-foreground">
              Read-Only Auditor scope may review findings and audit logs but cannot execute scans.
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
