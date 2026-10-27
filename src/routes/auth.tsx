import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { ShieldCheck, Loader2 } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { lovable } from "@/integrations/lovable/index";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const TITLE = "Sign in — GovShield SecOps";
const DESCRIPTION =
  "Authenticate to the GovShield SecOps assessment console. Access is role-scoped and every session is written to the tamper-evident audit ledger.";

export const Route = createFileRoute("/auth")({
  head: () => ({
    meta: [
      { title: TITLE },
      { name: "description", content: DESCRIPTION },
      { property: "og:title", content: TITLE },
      { property: "og:description", content: DESCRIPTION },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
      { name: "robots", content: "noindex" },
    ],
  }),
  component: AuthPage,
});

function AuthPage() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"signin" | "signup" | "forgot">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    void supabase.auth.getSession().then(({ data }) => {
      if (active && data.session) void navigate({ to: "/console", replace: true });
    });
    const { data: sub } = supabase.auth.onAuthStateChange((_event, session) => {
      if (session) void navigate({ to: "/console", replace: true });
    });
    return () => {
      active = false;
      sub.subscription.unsubscribe();
    };
  }, [navigate]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setNotice(null);
    try {
      if (mode === "forgot") {
        const { error: err } = await supabase.auth.resetPasswordForEmail(email, {
          redirectTo: `${window.location.origin}/reset-password`,
        });
        if (err) throw err;
        setNotice("If that address has an account, a reset link is on its way. Check your inbox.");
        setMode("signin");
      } else if (mode === "signup") {
        const { data, error: err } = await supabase.auth.signUp({
          email,
          password,
          options: {
            emailRedirectTo: `${window.location.origin}/console`,
            data: { full_name: fullName },
          },
        });
        if (err) throw err;
        if (!data.session) {
          setNotice("Account created. Check your inbox and confirm the address before signing in.");
          setMode("signin");
        }
      } else {
        const { error: err } = await supabase.auth.signInWithPassword({ email, password });
        if (err) throw err;
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Authentication failed.");
    } finally {
      setBusy(false);
    }
  }

  async function handleGoogle() {
    setError(null);
    const result = await lovable.auth.signInWithOAuth("google", {
      redirect_uri: window.location.origin,
    });
    if (result.error) {
      setError("Google sign-in failed. Try email and password instead.");
      return;
    }
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
            <div>
              <p className="text-lg font-semibold uppercase tracking-[0.18em]">GovShield SecOps</p>
              <p className="font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
                Controlled access · IL4 boundary
              </p>
            </div>
          </div>

          <Card>
            <CardHeader>
              <CardTitle className="text-base uppercase tracking-wider">
                {mode === "signin" ? "Authenticate" : mode === "forgot" ? "Reset password" : "Request console access"}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <form onSubmit={handleSubmit} className="space-y-4">
                {mode === "signup" && (
                  <div className="space-y-1.5">
                    <Label htmlFor="fullName" className="font-mono text-[11px] uppercase">
                      Full name
                    </Label>
                    <Input
                      id="fullName"
                      value={fullName}
                      onChange={(e) => setFullName(e.target.value)}
                      autoComplete="name"
                      required
                    />
                  </div>
                )}
                <div className="space-y-1.5">
                  <Label htmlFor="email" className="font-mono text-[11px] uppercase">
                    Official email
                  </Label>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    autoComplete="email"
                    required
                  />
                </div>
                {mode !== "forgot" && (
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="password" className="font-mono text-[11px] uppercase">
                      Password
                    </Label>
                    {mode === "signin" && (
                      <button
                        type="button"
                        className="text-xs text-primary underline underline-offset-2"
                        onClick={() => {
                          setMode("forgot");
                          setError(null);
                          setNotice(null);
                        }}
                      >
                        Forgot password?
                      </button>
                    )}
                  </div>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    autoComplete={mode === "signin" ? "current-password" : "new-password"}
                    minLength={8}
                    required
                  />
                </div>
                )}

                {error && (
                  <p className="rounded-sm border border-critical/40 bg-critical/10 px-3 py-2 font-mono text-xs text-critical">
                    {error}
                  </p>
                )}
                {notice && (
                  <p className="rounded-sm border border-success/40 bg-success/10 px-3 py-2 font-mono text-xs text-success">
                    {notice}
                  </p>
                )}

                <Button type="submit" disabled={busy} className="w-full gap-2 font-mono uppercase">
                  {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
                  {mode === "signin" ? "Sign in" : mode === "forgot" ? "Send reset link" : "Create account"}
                </Button>
                {mode === "forgot" && (
                  <button
                    type="button"
                    className="w-full text-center text-xs text-primary underline underline-offset-2"
                    onClick={() => setMode("signin")}
                  >
                    Back to sign in
                  </button>
                )}
              </form>

              <div className="flex items-center gap-3">
                <span className="h-px flex-1 bg-border" />
                <span className="font-mono text-[10px] uppercase text-muted-foreground">or</span>
                <span className="h-px flex-1 bg-border" />
              </div>

              <Button variant="outline" className="w-full font-mono uppercase" onClick={handleGoogle}>
                Continue with Google
              </Button>

              <p className="text-center text-xs text-muted-foreground">
                {mode === "signin" ? "No account yet?" : "Already enrolled?"}{" "}
                <button
                  type="button"
                  className="text-primary underline underline-offset-2"
                  onClick={() => {
                    setMode(mode === "signin" ? "signup" : "signin");
                    setError(null);
                  }}
                >
                  {mode === "signin" ? "Request access" : "Sign in"}
                </button>
              </p>
              <p className="text-center font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                The first account provisioned receives Admin scope. Later accounts start as Read-Only Auditor.
              </p>
            </CardContent>
          </Card>

          <p className="mt-6 text-center">
            <Link to="/" className="font-mono text-[11px] uppercase text-muted-foreground hover:text-foreground">
              ← Back to overview
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
}
