import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

export type AppRole = "admin" | "assessor" | "auditor";

export const ROLE_LABEL: Record<AppRole, "Admin" | "Assessor" | "Read-Only Auditor"> = {
  admin: "Admin",
  assessor: "Assessor",
  auditor: "Read-Only Auditor",
};

export interface Identity {
  userId: string;
  email: string;
  fullName: string | null;
  role: AppRole;
}

export interface FeedRow {
  id: string;
  name: string;
  source: string;
  cadence_minutes: number;
  status: string;
  last_synced_at: string | null;
  last_error: string | null;
  record_count: number;
  latency_ms: number | null;
  dataset_version: string | null;
  auto_update: boolean;
}

export interface AuditRow {
  seq: number;
  occurred_at: string;
  actor_email: string;
  actor_role: AppRole | null;
  action: string;
  target: string;
  prev_hash: string;
  hash: string;
}

/* ------------------------------- identity ------------------------------ */

export const bootstrapIdentity = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }): Promise<Identity> => {
    const { supabase, userId, claims } = context;
    const email = (claims as { email?: string }).email ?? "unknown@agency.gov";
    const fullName =
      ((claims as { user_metadata?: { full_name?: string; name?: string } }).user_metadata?.full_name ??
        (claims as { user_metadata?: { name?: string } }).user_metadata?.name) ||
      null;

    const { data, error } = await supabase.rpc("bootstrap_profile", {
      _email: email,
      ...(fullName ? { _full_name: fullName } : {}),
    });
    if (error) throw new Error(error.message);

    return { userId, email, fullName, role: (data as AppRole) ?? "auditor" };
  });

/* -------------------------------- audit -------------------------------- */

export const recordAudit = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { action: string; target: string; details?: Record<string, unknown> }) => {
    if (!input?.action || !input?.target) throw new Error("action and target are required");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { error } = await context.supabase.rpc("append_audit", {
      _action: data.action.slice(0, 120),
      _target: data.target.slice(0, 200),
      _details: (data.details ?? {}) as never,
    });
    if (error) throw new Error(error.message);
    return { ok: true };
  });

export const listAudit = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }): Promise<AuditRow[]> => {
    const { data, error } = await context.supabase
      .from("audit_log")
      .select("seq, occurred_at, actor_email, actor_role, action, target, prev_hash, hash")
      .order("seq", { ascending: false })
      .limit(200);
    if (error) throw new Error(error.message);
    return (data ?? []) as AuditRow[];
  });

export const verifyAuditChain = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data, error } = await context.supabase.rpc("verify_audit_chain");
    if (error) throw new Error(error.message);
    const row = (Array.isArray(data) ? data[0] : data) as
      | { total: number; valid: boolean; first_broken_seq: number | null }
      | undefined;
    await context.supabase.rpc("append_audit", {
      _action: "AUDIT_CHAIN_VERIFIED",
      _target: `sha-256 chain · ${row?.total ?? 0} entries`,
      _details: { valid: row?.valid ?? false },
    });
    return {
      total: Number(row?.total ?? 0),
      valid: Boolean(row?.valid),
      firstBrokenSeq: row?.first_broken_seq ?? null,
    };
  });

/* -------------------------------- feeds -------------------------------- */

export const listFeedState = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { supabase } = context;
    const [feeds, kev, epss, nvd, attack, runs] = await Promise.all([
      supabase.from("threat_feeds").select("*").order("id"),
      supabase.from("kev_entries").select("*", { count: "exact", head: true }),
      supabase.from("epss_scores").select("*", { count: "exact", head: true }),
      supabase.from("nvd_cves").select("*", { count: "exact", head: true }),
      supabase.from("attack_techniques").select("*", { count: "exact", head: true }),
      supabase
        .from("feed_sync_runs")
        .select("feed_id, started_at, finished_at, ok, records_upserted, latency_ms, error, trigger")
        .order("started_at", { ascending: false })
        .limit(12),
    ]);
    if (feeds.error) throw new Error(feeds.error.message);
    return {
      feeds: (feeds.data ?? []) as FeedRow[],
      counts: {
        kev: kev.count ?? 0,
        epss: epss.count ?? 0,
        nvd: nvd.count ?? 0,
        mitre: attack.count ?? 0,
      },
      runs: runs.data ?? [],
    };
  });

export const setAutoUpdate = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { enabled: boolean }) => input)
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: isAdmin } = await supabase.rpc("has_role", { _user_id: userId, _role: "admin" });
    const { data: isAssessor } = await supabase.rpc("has_role", { _user_id: userId, _role: "assessor" });
    if (!isAdmin && !isAssessor) throw new Error("Forbidden: read-only role");

    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { error } = await supabaseAdmin
      .from("threat_feeds")
      .update({ auto_update: data.enabled, updated_at: new Date().toISOString() })
      .neq("id", "");
    if (error) throw new Error(error.message);

    await supabase.rpc("append_audit", {
      _action: "AUTO_UPDATE_RULES_TOGGLED",
      _target: data.enabled ? "enabled" : "disabled",
      _details: {},
    });
    return { ok: true };
  });

export const syncFeedsNow = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { feedIds?: string[] }) => input ?? {})
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: isAdmin } = await supabase.rpc("has_role", { _user_id: userId, _role: "admin" });
    const { data: isAssessor } = await supabase.rpc("has_role", { _user_id: userId, _role: "assessor" });
    if (!isAdmin && !isAssessor) throw new Error("Forbidden: read-only role");

    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { runFeedSync, ALL_FEEDS } = await import("./feeds.server");
    const targets = (data.feedIds?.length ? data.feedIds : ALL_FEEDS).filter((f) =>
      ALL_FEEDS.includes(f as never),
    ) as typeof ALL_FEEDS;

    await supabase.rpc("append_audit", {
      _action: "THREAT_FEED_SYNC_INITIATED",
      _target: targets.join(","),
      _details: { trigger: "manual" },
    });

    const results = [];
    for (const feedId of targets) {
      results.push(await runFeedSync(supabaseAdmin, feedId, "manual"));
    }

    await supabase.rpc("append_audit", {
      _action: "THREAT_FEED_SYNC_COMPLETED",
      _target: results.map((r) => `${r.feedId}:${r.ok ? r.records : "failed"}`).join(" "),
      _details: { results } as never,
    });

    return { results };
  });
