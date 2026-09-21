import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";

export type ScanStatus = "queued" | "claimed" | "running" | "completed" | "failed" | "cancelled";

export interface ScanRow {
  id: string;
  created_email: string;
  target_type: string;
  target_value: string;
  modules: string[];
  mode: string;
  cadence: string | null;
  status: ScanStatus;
  stage: string;
  progress: number;
  worker_id: string | null;
  error: string | null;
  findings_count: number;
  posture: number | null;
  tool_versions: Record<string, string>;
  queued_at: string;
  claimed_at: string | null;
  finished_at: string | null;
}

export interface FindingRow {
  id: string;
  ordinal: number;
  ref: string;
  title: string;
  severity: string;
  module: string;
  target_type: string;
  tool: string;
  rule_id: string | null;
  cve: string | null;
  kev: boolean;
  kev_due_date: string | null;
  epss: number;
  cvss31: number;
  cvss40: number;
  cvss_vector: string | null;
  nist_controls: string[];
  fedramp_baseline: string;
  fips1403: boolean;
  privacy_impact: string | null;
  privacy_category: string | null;
  location: string;
  description: string;
  remediation: string;
  remediation_code: string | null;
  verification: string[];
}

export interface ScanEventRow {
  id: number;
  at: string;
  stage: string;
  message: string | null;
  progress: number | null;
}

export interface WorkerRow {
  id: string;
  name: string;
  capabilities: string[];
  version: string | null;
  status: string;
  last_seen_at: string | null;
  revoked_at: string | null;
}

const SCAN_COLUMNS =
  "id, created_email, target_type, target_value, modules, mode, cadence, status, stage, progress, worker_id, error, findings_count, posture, tool_versions, queued_at, claimed_at, finished_at";

async function assertCanWrite(supabase: { rpc: (...args: never[]) => unknown }, userId: string) {
  const rpc = (fn: string, args: Record<string, unknown>) =>
    (supabase.rpc as unknown as (f: string, a: Record<string, unknown>) => Promise<{ data: unknown }>)
      .call(supabase, fn, args);
  const [{ data: isAdmin }, { data: isAssessor }] = await Promise.all([
    rpc("has_role", { _user_id: userId, _role: "admin" }),
    rpc("has_role", { _user_id: userId, _role: "assessor" }),
  ]);
  if (!isAdmin && !isAssessor) throw new Error("Forbidden: read-only role");
  return { isAdmin: Boolean(isAdmin) };
}

/* -------------------------------- queueing -------------------------------- */

export const createScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator(
    (input: {
      targetType: string;
      targetValue: string;
      modules: string[];
      mode: string;
      cadence?: string;
      authorized: boolean;
    }) => {
      const allowedTargets = ["dast", "sast", "sbom", "iac"];
      if (!allowedTargets.includes(input?.targetType)) throw new Error("Unsupported target type");
      if (!input.targetValue?.trim()) throw new Error("A target identifier is required");
      if (!input.modules?.length) throw new Error("Select at least one test module");
      if (!input.authorized) {
        throw new Error("You must confirm you are authorised to test this target");
      }
      if (input.targetType === "dast" && !/^https?:\/\//i.test(input.targetValue.trim())) {
        throw new Error("Web application targets must be a full http(s) URL");
      }
      return input;
    },
  )
  .handler(async ({ data, context }) => {
    const { supabase, userId, claims } = context;
    await assertCanWrite(supabase, userId);
    const email = (claims as { email?: string }).email ?? "unknown@agency.gov";

    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: scan, error } = await supabaseAdmin
      .from("scans")
      .insert({
        created_by: userId,
        created_email: email,
        target_type: data.targetType,
        target_value: data.targetValue.trim(),
        modules: data.modules,
        mode: data.mode,
        cadence: data.cadence ?? null,
      })
      .select(SCAN_COLUMNS)
      .single();
    if (error) throw new Error(error.message);

    await supabaseAdmin.from("scan_events").insert({
      scan_id: scan.id,
      stage: "Queued",
      message: `Authorised assessment queued by ${email}`,
      progress: 0,
    });

    await supabase.rpc("append_audit", {
      _action: "SCAN_QUEUED",
      _target: `${data.targetType}:${data.targetValue.trim()}`,
      _details: { modules: data.modules, mode: data.mode, scan_id: scan.id } as never,
    });

    return scan as unknown as ScanRow;
  });

export const cancelScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { scanId: string }) => {
    if (!input?.scanId) throw new Error("scanId is required");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    await assertCanWrite(supabase, userId);

    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { error } = await supabaseAdmin
      .from("scans")
      .update({
        status: "cancelled",
        stage: "Cancelled by operator",
        finished_at: new Date().toISOString(),
      })
      .eq("id", data.scanId)
      .in("status", ["queued", "claimed", "running"]);
    if (error) throw new Error(error.message);

    await supabase.rpc("append_audit", {
      _action: "SCAN_CANCELLED",
      _target: data.scanId,
      _details: {} as never,
    });
    return { ok: true };
  });

/* --------------------------------- reads ---------------------------------- */

export const listScans = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data, error } = await context.supabase
      .from("scans")
      .select(SCAN_COLUMNS)
      .order("queued_at", { ascending: false })
      .limit(25);
    if (error) throw new Error(error.message);
    return (data ?? []) as unknown as ScanRow[];
  });

export const getScan = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { scanId: string }) => {
    if (!input?.scanId) throw new Error("scanId is required");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase } = context;
    const [scan, findings, events] = await Promise.all([
      supabase.from("scans").select(SCAN_COLUMNS).eq("id", data.scanId).maybeSingle(),
      supabase
        .from("scan_findings")
        .select(
          "id, ordinal, ref, title, severity, module, target_type, tool, rule_id, cve, kev, kev_due_date, epss, cvss31, cvss40, cvss_vector, nist_controls, fedramp_baseline, fips1403, privacy_impact, privacy_category, location, description, remediation, remediation_code, verification",
        )
        .eq("scan_id", data.scanId)
        .order("ordinal"),
      supabase
        .from("scan_events")
        .select("id, at, stage, message, progress")
        .eq("scan_id", data.scanId)
        .order("id"),
    ]);
    if (scan.error) throw new Error(scan.error.message);
    return {
      scan: (scan.data ?? null) as unknown as ScanRow | null,
      findings: (findings.data ?? []) as unknown as FindingRow[],
      events: (events.data ?? []) as unknown as ScanEventRow[],
    };
  });

/* --------------------------------- fleet ---------------------------------- */

export const listWorkers = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const { data, error } = await context.supabase
      .from("scan_workers")
      .select("id, name, capabilities, version, status, last_seen_at, revoked_at")
      .order("created_at");
    if (error) throw new Error(error.message);
    return (data ?? []) as WorkerRow[];
  });

/** Admin-only. Returns the worker key exactly once; only its hash is stored. */
export const issueWorkerKey = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { name: string; capabilities: string[] }) => {
    if (!input?.name?.trim()) throw new Error("A worker name is required");
    if (!input.capabilities?.length) throw new Error("Select at least one capability");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: isAdmin } = await supabase.rpc("has_role", { _user_id: userId, _role: "admin" });
    if (!isAdmin) throw new Error("Forbidden: Admin role required to enrol workers");

    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { mintWorkerKey } = await import("./scans.server");

    const workerId = `wrk-${data.name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 24)}-${Math.random().toString(36).slice(2, 6)}`;
    const { presented, hash } = mintWorkerKey(workerId);

    const { error } = await supabaseAdmin.from("scan_workers").insert({
      id: workerId,
      name: data.name.trim().slice(0, 80),
      key_hash: hash,
      capabilities: data.capabilities,
      created_by: userId,
    });
    if (error) throw new Error(error.message);

    await supabase.rpc("append_audit", {
      _action: "WORKER_KEY_ISSUED",
      _target: workerId,
      _details: { capabilities: data.capabilities } as never,
    });

    return { workerId, key: presented };
  });

export const revokeWorker = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input: { workerId: string }) => {
    if (!input?.workerId) throw new Error("workerId is required");
    return input;
  })
  .handler(async ({ data, context }) => {
    const { supabase, userId } = context;
    const { data: isAdmin } = await supabase.rpc("has_role", { _user_id: userId, _role: "admin" });
    if (!isAdmin) throw new Error("Forbidden: Admin role required");

    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    await supabaseAdmin
      .from("scan_workers")
      .update({ revoked_at: new Date().toISOString(), status: "revoked" })
      .eq("id", data.workerId);

    await supabase.rpc("append_audit", {
      _action: "WORKER_KEY_REVOKED",
      _target: data.workerId,
      _details: {} as never,
    });
    return { ok: true };
  });
