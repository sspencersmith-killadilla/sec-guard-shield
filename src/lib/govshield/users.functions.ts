import { createServerFn } from "@tanstack/react-start";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import type { AppRole } from "./platform.functions";

export interface ManagedUser {
  id: string;
  email: string;
  fullName: string | null;
  role: AppRole | null;
  createdAt: string;
  lastSignIn: string | null;
}

const ROLES: AppRole[] = ["admin", "assessor", "auditor"];

async function assertAdmin(ctx: { supabase: any; userId: string }) {
  const { data, error } = await ctx.supabase.rpc("has_role", { _user_id: ctx.userId, _role: "admin" });
  if (error || !data) throw new Error("Forbidden: admin only");
}

export const listUsers = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }): Promise<ManagedUser[]> => {
    await assertAdmin(context);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data, error } = await supabaseAdmin.auth.admin.listUsers({ perPage: 200 });
    if (error) throw new Error(error.message);
    const { data: roles } = await supabaseAdmin.from("user_roles").select("user_id, role");
    const rank = (r: string) => ROLES.indexOf(r as AppRole);
    const best = new Map<string, AppRole>();
    for (const r of roles ?? []) {
      const cur = best.get(r.user_id);
      if (!cur || rank(r.role) < rank(cur)) best.set(r.user_id, r.role as AppRole);
    }
    return data.users.map((u) => ({
      id: u.id,
      email: u.email ?? "",
      fullName: (u.user_metadata?.full_name as string | undefined) ?? null,
      role: best.get(u.id) ?? null,
      createdAt: u.created_at,
      lastSignIn: u.last_sign_in_at ?? null,
    }));
  });

export const createUser = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((i: { email: string; password: string; fullName?: string; role: AppRole }) => {
    const email = String(i?.email ?? "").trim().toLowerCase();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) throw new Error("Enter a valid email address");
    if (String(i?.password ?? "").length < 12) throw new Error("Temporary password must be at least 12 characters");
    if (!ROLES.includes(i.role)) throw new Error("Invalid role");
    return { email, password: i.password, fullName: i.fullName?.trim().slice(0, 120) || "", role: i.role };
  })
  .handler(async ({ data, context }) => {
    await assertAdmin(context);
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { data: created, error } = await supabaseAdmin.auth.admin.createUser({
      email: data.email,
      password: data.password,
      email_confirm: true,
      user_metadata: data.fullName ? { full_name: data.fullName } : {},
    });
    if (error || !created.user) throw new Error(error?.message ?? "Could not create user");
    const uid = created.user.id;
    await supabaseAdmin.from("profiles").upsert({ id: uid, email: data.email, full_name: data.fullName || null });
    const { error: rErr } = await supabaseAdmin.from("user_roles").insert({ user_id: uid, role: data.role });
    if (rErr) throw new Error(rErr.message);
    await context.supabase.rpc("append_audit", {
      _action: "USER_CREATED",
      _target: data.email,
      _details: { role: data.role } as never,
    });
    return { id: uid };
  });

export const setUserRole = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((i: { userId: string; role: AppRole }) => {
    if (!i?.userId || !ROLES.includes(i.role)) throw new Error("Invalid input");
    return i;
  })
  .handler(async ({ data, context }) => {
    await assertAdmin(context);
    if (data.userId === context.userId) throw new Error("You can't change your own role");
    const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
    const { error: dErr } = await supabaseAdmin.from("user_roles").delete().eq("user_id", data.userId);
    if (dErr) throw new Error(dErr.message);
    const { error } = await supabaseAdmin.from("user_roles").insert({ user_id: data.userId, role: data.role });
    if (error) throw new Error(error.message);
    await context.supabase.rpc("append_audit", {
      _action: "USER_ROLE_CHANGED",
      _target: data.userId,
      _details: { role: data.role } as never,
    });
    return { ok: true };
  });
