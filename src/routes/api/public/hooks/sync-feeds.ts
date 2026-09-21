import { createFileRoute } from "@tanstack/react-router";

/**
 * Scheduled threat-feed refresh. Called by the Cloud scheduler.
 * Caller must present the shared secret; this route is otherwise unauthenticated.
 */
export const Route = createFileRoute("/api/public/hooks/sync-feeds")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const secret = process.env["FEED_SYNC_SECRET"];
        const presented = request.headers.get("x-govshield-cron");
        if (!secret || !presented || presented !== secret) {
          return new Response(JSON.stringify({ error: "unauthorized" }), {
            status: 401,
            headers: { "Content-Type": "application/json" },
          });
        }

        let body: { feedIds?: string[] } = {};
        try {
          body = (await request.json()) as { feedIds?: string[] };
        } catch {
          body = {};
        }

        const { supabaseAdmin } = await import("@/integrations/supabase/client.server");
        const { runFeedSync, ALL_FEEDS } = await import("@/lib/govshield/feeds.server");

        const now = Date.now();
        const { data: feeds } = await supabaseAdmin
          .from("threat_feeds")
          .select("id, cadence_minutes, last_synced_at, auto_update");

        const due = (feeds ?? [])
          .filter((f) => f.auto_update)
          .filter((f) => {
            if (body.feedIds?.length) return body.feedIds.includes(f.id as string);
            const last = f.last_synced_at ? Date.parse(f.last_synced_at as string) : 0;
            return now - last >= (f.cadence_minutes as number) * 60_000;
          })
          .map((f) => f.id as string)
          .filter((id) => ALL_FEEDS.includes(id as never));

        const results = [];
        for (const feedId of due) {
          results.push(await runFeedSync(supabaseAdmin, feedId as never, "scheduled"));
        }

        return new Response(JSON.stringify({ ok: true, synced: results }), {
          headers: { "Content-Type": "application/json" },
        });
      },
    },
  },
});
