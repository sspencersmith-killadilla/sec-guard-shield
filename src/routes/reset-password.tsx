import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { ShieldCheck, Loader2 } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const TITLE = "Reset password — GovShield SecOps";
const DESCRIPTION = "Set a new password for your GovShield SecOps console account.";

export const Route = createFileRoute("/reset-password")({
  head: () => ({
    meta: [
      { title: TITLE },
      { name: "description", content: DESCRIPTION },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESCRIPTION },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: ResetPasswordPage,
});

function ResetPasswordPage() {
  const navigate = useNavigate();
  const [ready, setReady] = useState(false);
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const { data: sub } = supabase.auth.onAuthStateChange((event, session) => {
      if (event === "PASSWORD_RECOVERY" || session) setReady(true);
    });
    void supabase.auth.getSession().then(({ data }) => {
      if (data.session) setReady(true);
    });
    return () => sub.subscription.unsubscribe();
  }, []);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (password.length < 12) return setError("Use at least 12 characters.");
    if (password !== confirm) return setError("Passwords do not match.");
    setBusy(true);
    const { error: err } = await supabase.auth.updateUser({ password });
    setBusy(false);
    if (err) return setError(err.message);
    void navigate({ to: "/console", replace: true });
  }

  return (
    <div className="flex min-h-screen flex-col bg-background">
      <div className="h-1 w-full gov-stripe" aria-hidden />
      <div className="flex flex-1 items-center justify-center px-4 py-12">
        <div className="w-full max-w-md">
          <div className="mb-6 flex items-center gap-3">
            <div className="flex size-10 items-center justify-center rounded-sm border border-primary/40 bg-primary/10">
              <ShieldCheck className="size-5 text-primary" aria-hidden />
            </div>
            <p className="text-lg font-semibold uppercase tracking-[0.18em]">GovShield SecOps</p>
          </div>
          <Card>
            <CardHeader>
              <CardTitle className="text-base uppercase tracking-wider">Set a new password</CardTitle>
            </CardHeader>
            <CardContent>
              {!ready ? (
                <p className="text-sm text-muted-foreground">
                  Open this page from the reset link in your email. Link expired?{" "}
                  <Link to="/auth" className="text-primary underline">Request a new one</Link>.
                </p>
              ) : (
                <form onSubmit={submit} className="space-y-4">
                  <div className="space-y-1.5">
                    <Label htmlFor="np" className="font-mono text-[11px] uppercase">New password</Label>
                    <Input id="np" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} required />
                  </div>
                  <div className="space-y-1.5">
                    <Label htmlFor="cp" className="font-mono text-[11px] uppercase">Confirm password</Label>
                    <Input id="cp" type="password" autoComplete="new-password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
                  </div>
                  {error && (
                    <p className="rounded-sm border border-critical/40 bg-critical/10 px-3 py-2 font-mono text-xs text-critical">{error}</p>
                  )}
                  <Button type="submit" disabled={busy} className="w-full gap-2 font-mono uppercase">
                    {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
                    Update password
                  </Button>
                </form>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
