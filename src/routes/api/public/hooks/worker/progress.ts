import { createFileRoute } from "@tanstack/react-router";

/** Workers post stage/heartbeat updates here while a scan runs. */
export const Route = createFileRoute("/api/public/hooks/worker/progress")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { authenticateWorker, appendScanEvent } = await import("@/lib/govshield/scans.server");

        const worker = await authenticateWorker(
          supabaseAdmin,
          request.headers.get("x-govshield-worker-key"),
        );
        if (!worker) return Response.json({ error: "Invalid worker key" }, { status: 401 });

        const body = (await request.json().catch(() => null)) as {
          scanId?: string;
          stage?: string;
          message?: string;
          progress?: number;
        } | null;
        if (!body?.scanId || !body.stage) {
          return Response.json({ error: "scanId and stage are required" }, { status: 400 });
        }

        const progress = Math.max(0, Math.min(99, Number(body.progress ?? 0) || 0));
        const { error } = await supabaseAdmin
          .from("scans")
          .update({
            status: "running",
            stage: body.stage.slice(0, 200),
            progress,
            heartbeat_at: new Date().toISOString(),
          })
          .eq("id", body.scanId)
          .eq("worker_id", worker.id);
        if (error) return Response.json({ error: error.message }, { status: 500 });

        await appendScanEvent(
          supabaseAdmin,
          body.scanId,
          body.stage.slice(0, 200),
          body.message?.slice(0, 400) ?? null,
          progress,
        );

        return Response.json({ ok: true });
      },
    },
  },
});
