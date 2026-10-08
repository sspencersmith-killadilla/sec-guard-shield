import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { UserPlus } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { createUser, listUsers, setUserRole } from "@/lib/govshield/users.functions";
import { ROLE_LABEL, type AppRole } from "@/lib/govshield/platform.functions";
import { useGovShield } from "@/lib/govshield/state";

const ROLES: AppRole[] = ["admin", "assessor", "auditor"];
const selectCls =
  "h-9 rounded-sm border border-border bg-background px-2 font-mono text-xs text-foreground focus-visible:outline-2 focus-visible:outline-ring";

export function UsersPanel() {
  const { isAdmin, email: me } = useGovShield() as ReturnType<typeof useGovShield> & { isAdmin: boolean };
  const qc = useQueryClient();
  const list = useServerFn(listUsers);
  const create = useServerFn(createUser);
  const changeRole = useServerFn(setUserRole);
  const users = useQuery({ queryKey: ["govshield", "users"], queryFn: () => list(), enabled: isAdmin });

  const [form, setForm] = useState({ fullName: "", email: "", password: "", role: "auditor" as AppRole });
  const [msg, setMsg] = useState<string | null>(null);

  const add = useMutation({
    mutationFn: () => create({ data: form }),
    onSuccess: () => {
      setMsg(`Account created for ${form.email}. Share the temporary password with them securely.`);
      setForm({ fullName: "", email: "", password: "", role: "auditor" });
      qc.invalidateQueries({ queryKey: ["govshield"] });
    },
    onError: (e: Error) => setMsg(e.message),
  });
  const role = useMutation({
    mutationFn: (v: { userId: string; role: AppRole }) => changeRole({ data: v }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["govshield"] }),
    onError: (e: Error) => setMsg(e.message),
  });

  if (!isAdmin)
    return (
      <p className="rounded-sm border border-border bg-surface p-10 text-center font-mono text-sm text-muted-foreground">
        Only admins can manage users.
      </p>
    );

  return (
    <div className="grid gap-6 lg:grid-cols-[380px_1fr]">
      <Card className="rounded-sm border-border bg-surface">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 font-mono text-sm uppercase tracking-wider">
            <UserPlus className="size-4" aria-hidden /> Add user
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              setMsg(null);
              add.mutate();
            }}
          >
            <div className="space-y-1">
              <Label htmlFor="u-name">Full name</Label>
              <Input id="u-name" value={form.fullName} onChange={(e) => setForm({ ...form, fullName: e.target.value })} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="u-email">Email</Label>
              <Input id="u-email" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="u-pass">Temporary password (12+ characters)</Label>
              <Input id="u-pass" type="text" required minLength={12} value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            </div>
            <div className="space-y-1">
              <Label htmlFor="u-role">Role</Label>
              <select id="u-role" className={`${selectCls} w-full`} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as AppRole })}>
                {ROLES.map((r) => (
                  <option key={r} value={r}>{ROLE_LABEL[r]}</option>
                ))}
              </select>
            </div>
            <Button type="submit" className="w-full" disabled={add.isPending}>
              {add.isPending ? "Creating…" : "Create account"}
            </Button>
            {msg && <p className="text-xs text-muted-foreground" role="status">{msg}</p>}
          </form>
        </CardContent>
      </Card>

      <Card className="rounded-sm border-border bg-surface">
        <CardHeader>
          <CardTitle className="font-mono text-sm uppercase tracking-wider">Users ({users.data?.length ?? 0})</CardTitle>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          {users.isLoading ? (
            <p className="font-mono text-xs text-muted-foreground">Loading…</p>
          ) : users.error ? (
            <p className="font-mono text-xs text-critical">{(users.error as Error).message}</p>
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                <tr><th className="py-2">User</th><th>Role</th><th>Last sign-in</th></tr>
              </thead>
              <tbody>
                {users.data?.map((u) => (
                  <tr key={u.id} className="border-t border-border">
                    <td className="py-2">
                      <div>{u.fullName ?? "—"}</div>
                      <div className="font-mono text-xs text-muted-foreground">{u.email}</div>
                    </td>
                    <td>
                      <select
                        aria-label={`Role for ${u.email}`}
                        className={selectCls}
                        value={u.role ?? "auditor"}
                        disabled={u.email === me || role.isPending}
                        onChange={(e) => role.mutate({ userId: u.id, role: e.target.value as AppRole })}
                      >
                        {ROLES.map((r) => (
                          <option key={r} value={r}>{ROLE_LABEL[r]}</option>
                        ))}
                      </select>
                    </td>
                    <td className="font-mono text-xs text-muted-foreground">
                      {u.lastSignIn ? new Date(u.lastSignIn).toLocaleString() : "Never"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
