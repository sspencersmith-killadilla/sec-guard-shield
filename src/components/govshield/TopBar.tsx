import { ShieldCheck, RefreshCw, CircleDot, LogOut } from "lucide-react";
import { useNavigate } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import { useGovShield } from "@/lib/govshield/state";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

function stamp(ms: number) {
  if (!ms) return "--:--:-- UTC";
  return `${new Date(ms).toISOString().slice(11, 19)} UTC`;
}

export function TopBar() {
  const { role, email, lastSync, syncing, syncNow, canWrite, feeds } = useGovShield();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  const degraded = feeds.some((f) => f.status === "degraded");

  async function signOut() {
    await queryClient.cancelQueries();
    queryClient.clear();
    await supabase.auth.signOut();
    void navigate({ to: "/auth", replace: true });
  }

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
              className={`size-3.5 ${
                syncing ? "animate-pulse text-medium" : degraded ? "text-high" : "text-success"
              }`}
              aria-hidden
            />
            <span className="font-mono text-xs text-muted-foreground">
              FEEDS {syncing ? "SYNCING" : degraded ? "DEGRADED" : "OPERATIONAL"} · {stamp(lastSync)}
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

          <div className="flex items-center gap-2 rounded-sm border border-border bg-background px-3 py-1.5">
            <span className="max-w-[180px] truncate font-mono text-xs text-muted-foreground">{email || "—"}</span>
            <Badge variant="outline" className="font-mono text-[10px] uppercase">
              {role}
            </Badge>
          </div>

          <Button
            variant="ghost"
            size="sm"
            onClick={signOut}
            className="gap-2 font-mono text-xs uppercase"
            aria-label="Sign out"
          >
            <LogOut className="size-3.5" aria-hidden />
            Sign out
          </Button>
        </div>
      </div>
    </header>
  );
}
