import { ShieldCheck, RefreshCw, CircleDot } from "lucide-react";
import { useGovShield } from "@/lib/govshield/state";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import type { Role } from "@/lib/govshield/types";

const ROLES: Role[] = ["Admin", "Assessor", "Read-Only Auditor"];

function stamp(ms: number) {
  if (!ms) return "--:--:-- UTC";
  return `${new Date(ms).toISOString().slice(11, 19)} UTC`;
}

export function TopBar() {
  const { role, setRole, lastSync, syncing, syncNow, canWrite } = useGovShield();

  return (
    <header className="sticky top-0 z-30 border-b border-border bg-surface/95 backdrop-blur">
      <div className="h-1 w-full gov-stripe" aria-hidden />
      <div className="mx-auto flex max-w-[1600px] flex-wrap items-center gap-4 px-4 py-3 sm:px-6">
        <div className="flex items-center gap-3">
          <div className="flex size-9 items-center justify-center rounded-sm border border-primary/40 bg-primary/10">
            <ShieldCheck className="size-5 text-primary" aria-hidden />
          </div>
          <div>
            <h1 className="text-lg font-semibold uppercase tracking-[0.18em] text-foreground">GovShield SecOps</h1>
            <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              FedRAMP-aligned assessment console · IL4 boundary
            </p>
          </div>
        </div>

        <div className="ml-auto flex flex-wrap items-center gap-3">
          <div
            className="flex items-center gap-2 rounded-sm border border-border bg-background px-3 py-1.5"
            aria-live="polite"
          >
            <CircleDot
              className={`size-3.5 ${syncing ? "animate-pulse text-medium" : "text-success"}`}
              aria-hidden
            />
            <span className="font-mono text-xs text-muted-foreground">
              FEEDS {syncing ? "SYNCING" : "OPERATIONAL"} · {stamp(lastSync)}
            </span>
          </div>

          <Button
            variant="outline"
            size="sm"
            onClick={syncNow}
            disabled={syncing || !canWrite}
            className="gap-2 font-mono text-xs uppercase"
          >
            <RefreshCw className={`size-3.5 ${syncing ? "animate-spin" : ""}`} aria-hidden />
            Sync now
          </Button>

          <div className="flex items-center gap-2">
            <label htmlFor="role-scope" className="font-mono text-[11px] uppercase text-muted-foreground">
              Scope
            </label>
            <Select value={role} onValueChange={(v) => setRole(v as Role)}>
              <SelectTrigger id="role-scope" className="h-9 w-[190px] bg-background font-mono text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {ROLES.map((r) => (
                  <SelectItem key={r} value={r} className="font-mono text-xs">
                    {r}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </div>
    </header>
  );
}
