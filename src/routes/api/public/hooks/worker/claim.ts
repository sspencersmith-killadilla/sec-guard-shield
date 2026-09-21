import { createFileRoute } from "@tanstack/react-router";

/**
 * Scanner workers long-poll this endpoint for the next queued assessment.
 * Authenticated with a per-worker key; the prefix bypasses site auth, so the
 * handler itself is the security boundary.
 */
export const Route = createFileRoute("/api/public/hooks/worker/claim")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { authenticateWorker } = await import("@/lib/govshield/scans.server");

        const worker = await authenticateWorker(
          supabaseAdmin,
          request.headers.get("x-govshield-worker-key"),
        );
        if (!worker) {
          return Response.json({ error: "Invalid worker key" }, { status: 401 });
        }

        let version: string | null = null;
        try {
          const body = (await request.json()) as { version?: string };
          version = typeof body?.version === "string" ? body.version.slice(0, 40) : null;
        } catch {
          version = null;
        }
        if (version) {
          await supabaseAdmin.from("scan_workers").update({ version }).eq("id", worker.id);
        }

        // Return abandoned jobs to the queue before looking for new work.
        await supabaseAdmin.rpc("reap_stalled_scans", { _timeout_minutes: 20 });

        const { data, error } = await supabaseAdmin.rpc("claim_scan", {
          _worker_id: worker.id,
          _capabilities: worker.capabilities,
        });
        if (error) {
          return Response.json({ error: error.message }, { status: 500 });
        }

        const job = (Array.isArray(data) ? data[0] : data) as
          | {
              id: string;
              target_type: string;
              target_value: string;
              modules: string[];
              mode: string;
            }
          | null;

        if (!job?.id) return Response.json({ job: null });

        return Response.json({
          job: {
            id: job.id,
            targetType: job.target_type,
            targetValue: job.target_value,
            modules: job.modules,
            mode: job.mode,
          },
        });
      },
    },
  },
});
