import { FileLock2, ShieldCheck } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useGovShield } from "@/lib/govshield/state";

const ROLE_MATRIX = [
  { role: "Admin", scope: "Full control: feeds, scans, exports, role assignment" },
  { role: "Assessor", scope: "Execute scans, review findings, export SSP artifacts" },
  { role: "Read-Only Auditor", scope: "Review findings and immutable audit log only" },
];

export function AuditPanel() {
  const { auditLog, verifyChain, chainValid, chainTotal, verifying, role } = useGovShield();

  return (
    <div className="grid gap-4 xl:grid-cols-4">
      <Card className="xl:col-span-3">
        <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
          <CardTitle className="flex items-center gap-2 text-base uppercase tracking-wider">
            <FileLock2 className="size-4 text-primary" aria-hidden /> Immutable audit log
            <span className="font-mono text-[10px] font-normal text-muted-foreground">NIST AU-2 / AU-9</span>
          </CardTitle>
          <Button
            variant="outline"
            size="sm"
            className="gap-2 font-mono text-xs uppercase"
            onClick={verifyChain}
            disabled={verifying}
          >
            <ShieldCheck className="size-3.5" aria-hidden /> {verifying ? "Verifying" : "Verify chain"}
          </Button>
        </CardHeader>
        <CardContent>
          {chainValid === true && (
            <p className="mb-3 rounded-sm border border-success/40 bg-success/10 px-3 py-2 font-mono text-xs text-success">
              CHAIN INTACT · {chainTotal} entries recomputed server-side · no tamper evidence detected
            </p>
          )}
          {chainValid === false && (
            <p className="mb-3 rounded-sm border border-critical/40 bg-critical/10 px-3 py-2 font-mono text-xs text-critical">
              CHAIN BROKEN · digest mismatch detected across {chainTotal} entries · escalate per IR-6
            </p>
          )}
          <div className="max-h-[520px] overflow-auto rounded-sm border border-border">
            <Table>
              <TableHeader>
                <TableRow className="bg-surface-raised">
                  <TableHead className="font-mono text-[11px] uppercase">Timestamp</TableHead>
                  <TableHead className="font-mono text-[11px] uppercase">Actor / Role</TableHead>
                  <TableHead className="font-mono text-[11px] uppercase">Action</TableHead>
                  <TableHead className="font-mono text-[11px] uppercase">Target</TableHead>
                  <TableHead className="font-mono text-[11px] uppercase">Hash (prev ←)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {auditLog.map((e) => (
                  <TableRow key={e.id}>
                    <TableCell className="whitespace-nowrap font-mono text-xs text-muted-foreground">
                      {new Date(e.timestamp).toISOString().replace("T", " ").slice(0, 19)}Z
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-xs">
                      <span className="block font-mono">{e.actor}</span>
                      <span className="text-muted-foreground">{e.role}</span>
                    </TableCell>
                    <TableCell className="font-mono text-xs text-primary">{e.action}</TableCell>
                    <TableCell className="max-w-[220px] truncate font-mono text-xs text-muted-foreground">
                      {e.target}
                    </TableCell>
                    <TableCell className="font-mono text-[10px] leading-tight">
                      <span className="block text-foreground">{e.hash}</span>
                      <span className="block text-muted-foreground">← {e.prevHash.slice(0, 16)}…</span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base uppercase tracking-wider">Zero Trust scoping</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {ROLE_MATRIX.map((r) => (
            <div
              key={r.role}
              className={`rounded-sm border p-3 ${
                r.role === role ? "border-primary/60 bg-primary/10" : "border-border bg-background"
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <p className="text-sm font-medium">{r.role}</p>
                {r.role === role && (
                  <Badge variant="outline" className="font-mono text-[10px] uppercase">
                    active
                  </Badge>
                )}
              </div>
              <p className="mt-1 text-xs text-muted-foreground">{r.scope}</p>
            </div>
          ))}
          <p className="font-mono text-[11px] text-muted-foreground">
            Every privileged action is written to the append-only ledger and chained to the prior entry digest.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
