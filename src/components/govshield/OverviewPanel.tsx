import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { AlertTriangle, Gauge, ScanLine, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { SEVERITY_ORDER, severityClasses } from "@/lib/govshield/data";
import { useGovShield } from "@/lib/govshield/state";

const SEV_COLOR: Record<string, string> = {
  Critical: "var(--critical)",
  High: "var(--high)",
  Medium: "var(--medium)",
  Low: "var(--low)",
};

const tooltipStyle = {
  backgroundColor: "var(--popover)",
  border: "1px solid var(--border)",
  borderRadius: "4px",
  fontFamily: "var(--font-mono)",
  fontSize: "11px",
  color: "var(--popover-foreground)",
};

export function OverviewPanel({ onStartScan }: { onStartScan: () => void }) {
  const { findings, hasResults, config, feeds, posture: scanPosture, trend, selectedScan } = useGovShield();

  if (!hasResults) {
    return (
      <Card className="gov-grid">
        <CardContent className="flex flex-col items-center justify-center gap-4 py-24 text-center">
          <ScanLine className="size-10 text-primary" aria-hidden />
          <div>
            <h2 className="text-xl uppercase tracking-wider">No assessment on record</h2>
            <p className="mt-2 max-w-md text-sm text-muted-foreground">
              Threat feeds are synchronized and detection signatures are current. Configure a target and execute a scan
              to generate a FedRAMP-aligned posture report.
            </p>
          </div>
          <Button onClick={onStartScan} className="gap-2 font-mono uppercase">
            <ScanLine className="size-4" aria-hidden /> Configure scan
          </Button>
        </CardContent>
      </Card>
    );
  }

  const posture = scanPosture ?? 0;
  const counts = SEVERITY_ORDER.map((s) => ({
    severity: s,
    count: findings.filter((f) => f.severity === s).length,
  }));
  const kev = findings.filter((f) => f.kev).length;
  const privacy = findings.filter((f) => f.privacyImpact).length;
  const maxCvss = findings.length ? Math.max(...findings.map((f) => f.cvss31)) : 0;
  const moduleCounts = Object.entries(
    findings.reduce<Record<string, number>>((acc, f) => {
      acc[f.module] = (acc[f.module] ?? 0) + 1;
      return acc;
    }, {}),
  ).map(([module, count]) => ({ module, count }));

  return (
    <div className="space-y-4">
      <div className="grid gap-4 lg:grid-cols-4">
        <Card className="lg:col-span-1">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm uppercase tracking-wider text-muted-foreground">
              <Gauge className="size-4 text-primary" aria-hidden /> Compliance posture
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="font-display text-5xl text-foreground">
              {posture}
              <span className="text-xl text-muted-foreground">/100</span>
            </p>
            <Progress value={posture} className="mt-3 h-1.5" />
            <p className="mt-3 font-mono text-[11px] text-muted-foreground">
              Target: {selectedScan?.target_value ?? config.value} ·{" "}
              {selectedScan?.mode === "conmon" ? `ConMon ${selectedScan.cadence ?? ""}` : "Standard scan"}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm uppercase tracking-wider text-muted-foreground">Peak CVSS</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="font-display text-5xl text-critical">{maxCvss.toFixed(1)}</p>
            <p className="mt-3 font-mono text-[11px] text-muted-foreground">v3.1 base · v4.0 overlay applied</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm uppercase tracking-wider text-muted-foreground">
              <AlertTriangle className="size-4 text-high" aria-hidden /> KEV matches
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="font-display text-5xl text-high">{kev}</p>
            <p className="mt-3 font-mono text-[11px] text-muted-foreground">
              Known exploited · remediation due within 14 days (BOD 22-01)
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm uppercase tracking-wider text-muted-foreground">
              <ShieldCheck className="size-4 text-privacy" aria-hidden /> Privacy flags
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="font-display text-5xl text-privacy">{privacy}</p>
            <p className="mt-3 font-mono text-[11px] text-muted-foreground">
              NIST Privacy Framework 1.0 categorization
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base uppercase tracking-wider">Posture across recent assessments</CardTitle>
          </CardHeader>
          <CardContent className="h-[280px]">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="day" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                <YAxis domain={[0, 100]} tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                <Tooltip contentStyle={tooltipStyle} />
                <Area type="monotone" dataKey="posture" stroke="var(--primary)" fill="var(--primary)" fillOpacity={0.25} />
              </AreaChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base uppercase tracking-wider">Severity distribution</CardTitle>
          </CardHeader>
          <CardContent className="h-[280px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={counts} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="severity" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-raised)" }} />
                <Bar dataKey="count" radius={[2, 2, 0, 0]}>
                  {counts.map((c) => (
                    <Cell key={c.severity} fill={SEV_COLOR[c.severity]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle className="text-base uppercase tracking-wider">Findings by test module</CardTitle>
          </CardHeader>
          <CardContent className="h-[240px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={moduleCounts} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                <CartesianGrid stroke="var(--border)" strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="module" tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                <YAxis allowDecimals={false} tick={{ fontSize: 10, fill: "var(--muted-foreground)" }} />
                <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "var(--surface-raised)" }} />
                <Bar dataKey="count" fill="var(--primary)" radius={[2, 2, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base uppercase tracking-wider">Top exposures</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {findings
              .slice()
              .sort((a, b) => b.epss - a.epss)
              .slice(0, 5)
              .map((f) => (
                <div key={f.id} className="rounded-sm border border-border bg-background p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className={`rounded-sm border px-1.5 py-0.5 font-mono text-[10px] uppercase ${severityClasses(f.severity)}`}>
                      {f.severity}
                    </span>
                    <span className="font-mono text-[11px] text-muted-foreground">EPSS {(f.epss * 100).toFixed(1)}%</span>
                  </div>
                  <p className="mt-2 line-clamp-2 text-sm">{f.title}</p>
                  <p className="mt-1 font-mono text-[11px] text-primary">{f.nistControls.join(" · ")}</p>
                </div>
              ))}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardContent className="flex flex-wrap gap-x-8 gap-y-2 pt-6 font-mono text-[11px] text-muted-foreground">
          {feeds.map((f) => (
            <span key={f.id}>
              {f.name}: <span className="text-success">{f.records.toLocaleString()} records</span>
            </span>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
