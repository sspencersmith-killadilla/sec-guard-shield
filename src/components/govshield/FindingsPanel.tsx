import { useMemo, useState } from "react";
import { ExternalLink, FileDown, Filter, ShieldAlert, EyeOff } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from "@/components/ui/accordion";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { CONTROL_COVERAGE, SEVERITY_ORDER, TEST_MODULES, severityClasses } from "@/lib/govshield/data";
import { useGovShield } from "@/lib/govshield/state";
import type { Finding } from "@/lib/govshield/types";

function ExportButton({ findings }: { findings: Finding[] }) {
  const { log, canWrite, config } = useGovShield();

  const exportSSP = () => {
    const oscal = {
      "assessment-results": {
        uuid: "b7c1f0a2-9b2e-4f1e-9d65-govshield",
        metadata: {
          title: "GovShield SecOps — OSCAL Assessment Results",
          "last-modified": new Date().toISOString(),
          version: "1.0.0",
          "oscal-version": "1.1.2",
        },
        "import-ap": { href: "#agency-assessment-plan" },
        results: [
          {
            uuid: "result-0001",
            title: `FISMA-ready findings for ${config.value}`,
            start: new Date().toISOString(),
            findings: findings.map((f) => ({
              uuid: f.id,
              title: f.title,
              target: { "target-id": f.location, status: { state: "not-satisfied" } },
              props: [
                { name: "severity", value: f.severity },
                { name: "cvss-v3.1", value: String(f.cvss31) },
                { name: "cvss-v4.0", value: String(f.cvss40) },
                { name: "epss", value: f.epss.toFixed(4) },
                { name: "fedramp-baseline", value: f.fedrampBaseline },
                { name: "fips-140-3", value: String(f.fips1403) },
                ...(f.cve ? [{ name: "cve", value: f.cve }] : []),
                ...(f.privacyCategory ? [{ name: "privacy-category", value: f.privacyCategory }] : []),
              ],
              "related-controls": f.nistControls.map((c) => ({ "control-id": c.toLowerCase() })),
              remarks: f.remediation,
            })),
          },
        ],
      },
    };
    const blob = new Blob([JSON.stringify(oscal, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "govshield-oscal-assessment-results.json";
    a.click();
    URL.revokeObjectURL(url);
    log("OSCAL_SSP_EXPORTED", `${findings.length} findings · FISMA-ready`);
  };

  return (
    <Button onClick={exportSSP} disabled={!canWrite || findings.length === 0} className="gap-2 font-mono text-xs uppercase">
      <FileDown className="size-4" aria-hidden /> Export SSP (OSCAL)
    </Button>
  );
}

export function FindingsPanel() {
  const { findings } = useGovShield();
  const [severity, setSeverity] = useState("all");
  const [moduleKey, setModuleKey] = useState("all");
  const [privacyOnly, setPrivacyOnly] = useState(false);

  const filtered = useMemo(
    () =>
      findings.filter(
        (f) =>
          (severity === "all" || f.severity === severity) &&
          (moduleKey === "all" || f.module === moduleKey) &&
          (!privacyOnly || f.privacyImpact),
      ),
    [findings, severity, moduleKey, privacyOnly],
  );

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex-row flex-wrap items-center justify-between gap-3 space-y-0">
          <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
            <ShieldAlert className="size-4 text-primary" aria-hidden /> Findings & remediation
            <span className="font-mono text-[11px] font-normal text-muted-foreground">
              {filtered.length} of {findings.length}
            </span>
          </CardTitle>
          <div className="flex flex-wrap items-center gap-2">
            <Filter className="size-4 text-muted-foreground" aria-hidden />
            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger className="h-9 w-[140px] bg-background font-mono text-xs" aria-label="Filter by severity">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="font-mono text-xs">All severities</SelectItem>
                {SEVERITY_ORDER.map((s) => (
                  <SelectItem key={s} value={s} className="font-mono text-xs">{s}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={moduleKey} onValueChange={setModuleKey}>
              <SelectTrigger className="h-9 w-[190px] bg-background font-mono text-xs" aria-label="Filter by module">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="font-mono text-xs">All modules</SelectItem>
                {TEST_MODULES.map((m) => (
                  <SelectItem key={m.id} value={m.id} className="font-mono text-xs">{m.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              variant={privacyOnly ? "default" : "outline"}
              size="sm"
              className="gap-2 font-mono text-xs uppercase"
              aria-pressed={privacyOnly}
              onClick={() => setPrivacyOnly((v) => !v)}
            >
              <EyeOff className="size-3.5" aria-hidden /> Privacy impact
            </Button>
            <ExportButton findings={findings} />
          </div>
        </CardHeader>
        <CardContent>
          <Accordion type="multiple" className="space-y-2">
            {filtered.map((f) => (
              <AccordionItem
                key={f.id}
                value={f.id}
                className="rounded-sm border border-border bg-background px-4 data-[state=open]:border-primary/40"
              >
                <AccordionTrigger className="gap-3 py-3 hover:no-underline">
                  <div className="flex flex-1 flex-wrap items-center gap-3 text-left">
                    <Badge variant="outline" className={`font-mono text-[10px] uppercase ${severityClasses(f.severity)}`}>
                      {f.severity}
                    </Badge>
                    <span className="font-mono text-[11px] text-muted-foreground">{f.id}</span>
                    <span className="flex-1 text-sm font-medium">{f.title}</span>
                    {f.kev && (
                      <Badge variant="outline" className="border-critical/50 bg-critical/10 font-mono text-[10px] text-critical">
                        CISA KEV
                      </Badge>
                    )}
                    {f.privacyImpact && (
                      <Badge variant="outline" className="border-privacy/50 bg-privacy/10 font-mono text-[10px] text-privacy">
                        PRIVACY
                      </Badge>
                    )}
                    <span className="font-mono text-[11px] text-muted-foreground">
                      EPSS {(f.epss * 100).toFixed(1)}%
                    </span>
                  </div>
                </AccordionTrigger>
                <AccordionContent className="space-y-4 pb-5">
                  <p className="text-sm text-muted-foreground">{f.description}</p>

                  <dl className="grid gap-3 font-mono text-[11px] sm:grid-cols-2 lg:grid-cols-4">
                    <div className="rounded-sm border border-border p-3">
                      <dt className="text-muted-foreground">NIST SP 800-53 Rev.5</dt>
                      <dd className="mt-1 text-primary">{f.nistControls.join(" · ")}</dd>
                    </div>
                    <div className="rounded-sm border border-border p-3">
                      <dt className="text-muted-foreground">FedRAMP baseline</dt>
                      <dd className="mt-1">{f.fedrampBaseline} · {f.nistControls[0]}-FR</dd>
                    </div>
                    <div className="rounded-sm border border-border p-3">
                      <dt className="text-muted-foreground">CVSS v3.1 / v4.0</dt>
                      <dd className="mt-1">{f.cvss31.toFixed(1)} / {f.cvss40.toFixed(1)}</dd>
                    </div>
                    <div className="rounded-sm border border-border p-3">
                      <dt className="text-muted-foreground">FIPS 140-3</dt>
                      <dd className={`mt-1 ${f.fips1403 ? "text-high" : "text-success"}`}>
                        {f.fips1403 ? "NON-VALIDATED CRYPTO" : "Not applicable"}
                      </dd>
                    </div>
                  </dl>

                  <div className="flex flex-wrap items-center gap-4 font-mono text-[11px]">
                    <span className="text-muted-foreground">LOCATION · {f.location}</span>
                    {f.cve && (
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${f.cve}`}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1 text-primary underline underline-offset-4"
                      >
                        {f.cve} <ExternalLink className="size-3" aria-hidden />
                      </a>
                    )}
                    <span className="text-muted-foreground">VECTOR · {f.cvssVector}</span>
                  </div>

                  {f.privacyImpact && (
                    <div className="rounded-sm border border-privacy/40 bg-privacy/10 p-3">
                      <p className="font-mono text-[11px] uppercase text-privacy">Privacy impact flag</p>
                      <p className="mt-1 text-sm">{f.privacyImpact}</p>
                      <p className="mt-1 font-mono text-[11px] text-muted-foreground">
                        NIST Privacy Framework 1.0 · {f.privacyCategory}
                      </p>
                    </div>
                  )}

                  <div>
                    <p className="font-mono text-[11px] uppercase text-muted-foreground">Remediation</p>
                    <p className="mt-1 text-sm">{f.remediation}</p>
                    <pre className="mt-2 overflow-x-auto rounded-sm border border-border bg-surface-raised p-3 font-mono text-[11px] leading-relaxed">
                      <code>{f.remediationCode}</code>
                    </pre>
                  </div>

                  <div>
                    <p className="font-mono text-[11px] uppercase text-muted-foreground">Verification steps</p>
                    <ol className="mt-1 list-decimal space-y-1 pl-5 text-sm text-muted-foreground">
                      {f.verification.map((v) => (
                        <li key={v}>{v}</li>
                      ))}
                    </ol>
                  </div>
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base uppercase tracking-wider">Standard crosswalk — control coverage</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
          {CONTROL_COVERAGE.map((c) => (
            <div key={c.control} className="flex items-center gap-3 rounded-sm border border-border bg-background p-3">
              <span
                className={`size-2.5 shrink-0 rounded-full ${
                  c.status === "satisfied" ? "bg-success" : c.status === "partial" ? "bg-medium" : "bg-critical"
                }`}
                aria-hidden
              />
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">
                  <span className="font-mono text-primary">{c.control}</span> {c.title}
                </p>
                <p className="truncate font-mono text-[11px] text-muted-foreground">{c.family}</p>
              </div>
              <span className="font-mono text-[11px] uppercase text-muted-foreground">{c.status}</span>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
