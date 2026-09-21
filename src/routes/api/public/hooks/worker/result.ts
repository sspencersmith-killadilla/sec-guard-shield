import { createFileRoute } from "@tanstack/react-router";
import type { WorkerFinding } from "@/lib/govshield/scans.server";

/** Terminal report from a worker: findings, tool versions, or a failure. */
export const Route = createFileRoute("/api/public/hooks/worker/result")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const {
          authenticateWorker,
          appendScanEvent,
          appendSystemAudit,
          enrichFindings,
          computePosture,
        } = await import("@/lib/govshield/scans.server");

        const worker = await authenticateWorker(
          supabaseAdmin,
          request.headers.get("x-govshield-worker-key"),
        );
        if (!worker) return Response.json({ error: "Invalid worker key" }, { status: 401 });

        const body = (await request.json().catch(() => null)) as {
          scanId?: string;
          ok?: boolean;
          error?: string;
          toolVersions?: Record<string, string>;
          findings?: WorkerFinding[];
        } | null;
        if (!body?.scanId) return Response.json({ error: "scanId is required" }, { status: 400 });

        const { data: scan } = await supabaseAdmin
          .from("scans")
          .select("id, target_type, target_value, worker_id, status")
          .eq("id", body.scanId)
          .maybeSingle();
        if (!scan || scan.worker_id !== worker.id) {
          return Response.json({ error: "Scan not assigned to this worker" }, { status: 409 });
        }

        const finishedAt = new Date().toISOString();

        if (body.ok === false) {
          await supabaseAdmin
            .from("scans")
            .update({
              status: "failed",
              stage: "Assessment failed",
              progress: 100,
              error: (body.error ?? "Worker reported a failure").slice(0, 1000),
              finished_at: finishedAt,
              tool_versions: body.toolVersions ?? {},
            })
            .eq("id", scan.id);
          await appendScanEvent(supabaseAdmin, scan.id, "Failed", body.error ?? null, 100);
          await appendSystemAudit(supabaseAdmin, "SCAN_FAILED", `${scan.target_type}:${scan.target_value}`, {
            scan_id: scan.id,
            worker: worker.id,
            error: body.error ?? null,
          });
          return Response.json({ ok: true });
        }

        const raw = Array.isArray(body.findings) ? body.findings.slice(0, 2000) : [];
        const rows = await enrichFindings(supabaseAdmin, scan.id, scan.target_type, raw);

        // Replace any partial results from an earlier attempt.
        await supabaseAdmin.from("scan_findings").delete().eq("scan_id", scan.id);
        for (let i = 0; i < rows.length; i += 200) {
          const { error } = await supabaseAdmin.from("scan_findings").insert(rows.slice(i, i + 200) as never);
          if (error) return Response.json({ error: error.message }, { status: 500 });
        }

        const posture = computePosture(rows);
        await supabaseAdmin
          .from("scans")
          .update({
            status: "completed",
            stage: "Assessment complete",
            progress: 100,
            findings_count: rows.length,
            posture,
            error: null,
            finished_at: finishedAt,
            tool_versions: body.toolVersions ?? {},
          })
          .eq("id", scan.id);

        await appendScanEvent(
          supabaseAdmin,
          scan.id,
          "Complete",
          `${rows.length} findings correlated · posture ${posture}%`,
          100,
        );
        await appendSystemAudit(
          supabaseAdmin,
          "SCAN_COMPLETED",
          `${scan.target_type}:${scan.target_value}`,
          {
            scan_id: scan.id,
            worker: worker.id,
            findings: rows.length,
            posture,
            kev_hits: rows.filter((r) => r.kev).length,
          },
        );

        return Response.json({ ok: true, findings: rows.length, posture });
      },
    },
  },
});
