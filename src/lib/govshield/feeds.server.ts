/**
 * Server-only threat-intelligence ingestion.
 * Pulls upstream government / community feeds and upserts them into Cloud.
 * Never imported from client-reachable module scope.
 */
import type { SupabaseClient } from "@supabase/supabase-js";

export type FeedId = "kev" | "nvd" | "epss" | "mitre";

export interface SyncOutcome {
  feedId: FeedId;
  ok: boolean;
  records: number;
  latencyMs: number;
  datasetVersion?: string | null;
  error?: string;
}

const UA = { "User-Agent": "GovShield-SecOps/1.0 (compliance scanner)" };

async function getJson<T>(url: string, headers: Record<string, string> = {}): Promise<T> {
  const res = await fetch(url, { headers: { ...UA, Accept: "application/json", ...headers } });
  if (!res.ok) {
    throw new Error(`${new URL(url).hostname} responded ${res.status}: ${(await res.text()).slice(0, 200)}`);
  }
  return (await res.json()) as T;
}

function chunk<T>(rows: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < rows.length; i += size) out.push(rows.slice(i, i + size));
  return out;
}

async function upsert(
  admin: SupabaseClient,
  table: string,
  rows: Record<string, unknown>[],
  conflict: string,
) {
  let written = 0;
  for (const part of chunk(rows, 500)) {
    const { error } = await admin.from(table).upsert(part, { onConflict: conflict });
    if (error) throw new Error(`${table}: ${error.message}`);
    written += part.length;
  }
  return written;
}

/* ------------------------------ CISA KEV ------------------------------ */

interface KevDoc {
  catalogVersion?: string;
  vulnerabilities: Array<{
    cveID: string;
    vendorProject?: string;
    product?: string;
    vulnerabilityName?: string;
    dateAdded?: string;
    dueDate?: string;
    requiredAction?: string;
    knownRansomwareCampaignUse?: string;
    shortDescription?: string;
  }>;
}

async function syncKev(admin: SupabaseClient): Promise<{ records: number; version: string | null }> {
  const doc = await getJson<KevDoc>(
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
  );
  const rows = doc.vulnerabilities.map((v) => ({
    cve_id: v.cveID,
    vendor_project: v.vendorProject ?? null,
    product: v.product ?? null,
    vulnerability_name: v.vulnerabilityName ?? null,
    date_added: v.dateAdded ?? null,
    due_date: v.dueDate ?? null,
    required_action: v.requiredAction ?? null,
    known_ransomware: v.knownRansomwareCampaignUse ?? null,
    short_description: v.shortDescription ?? null,
    synced_at: new Date().toISOString(),
  }));
  const records = await upsert(admin, "kev_entries", rows, "cve_id");
  return { records, version: doc.catalogVersion ?? null };
}

/* -------------------------------- EPSS -------------------------------- */

interface EpssDoc {
  "score-date"?: string;
  data: Array<{ cve: string; epss: string; percentile: string; date?: string }>;
}

/**
 * The full EPSS corpus is ~280k rows; we ingest the highest-probability slice
 * plus every CVE already tracked in the KEV catalog, which is what findings map to.
 */
async function syncEpss(admin: SupabaseClient): Promise<{ records: number; version: string | null }> {
  const collected = new Map<string, { epss: number; percentile: number; date: string }>();
  let scoreDate: string | null = null;

  for (let offset = 0; offset < 4000; offset += 1000) {
    const doc = await getJson<EpssDoc>(
      `https://api.first.org/data/v1/epss?order=!epss&limit=1000&offset=${offset}`,
    );
    scoreDate = doc["score-date"]?.slice(0, 10) ?? scoreDate;
    if (!doc.data?.length) break;
    for (const row of doc.data) {
      collected.set(row.cve, {
        epss: Number(row.epss),
        percentile: Number(row.percentile),
        date: row.date ?? scoreDate ?? new Date().toISOString().slice(0, 10),
      });
    }
    if (doc.data.length < 1000) break;
  }

  // Enrich KEV CVEs that fall outside the top slice.
  const { data: kev } = await admin.from("kev_entries").select("cve_id").limit(2000);
  const missing = (kev ?? []).map((r) => r.cve_id as string).filter((id) => !collected.has(id));
  for (const part of chunk(missing, 100)) {
    const doc = await getJson<EpssDoc>(
      `https://api.first.org/data/v1/epss?cve=${part.join(",")}`,
    );
    for (const row of doc.data ?? []) {
      collected.set(row.cve, {
        epss: Number(row.epss),
        percentile: Number(row.percentile),
        date: row.date ?? scoreDate ?? new Date().toISOString().slice(0, 10),
      });
    }
  }

  const rows = [...collected.entries()].map(([cve_id, v]) => ({
    cve_id,
    epss: v.epss,
    percentile: v.percentile,
    score_date: v.date,
    synced_at: new Date().toISOString(),
  }));
  const records = await upsert(admin, "epss_scores", rows, "cve_id");
  return { records, version: scoreDate };
}

/* --------------------------------- NVD -------------------------------- */

interface NvdDoc {
  totalResults: number;
  resultsPerPage: number;
  startIndex: number;
  vulnerabilities: Array<{
    cve: {
      id: string;
      published?: string;
      lastModified?: string;
      vulnStatus?: string;
      descriptions?: Array<{ lang: string; value: string }>;
      weaknesses?: Array<{ description?: Array<{ lang: string; value: string }> }>;
      metrics?: Record<
        string,
        Array<{
          cvssData?: { version?: string; baseScore?: number; baseSeverity?: string; vectorString?: string };
          baseSeverity?: string;
        }>
      >;
    };
  }>;
}

function pickMetric(metrics: NvdDoc["vulnerabilities"][number]["cve"]["metrics"]) {
  const order = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"];
  for (const key of order) {
    const entry = metrics?.[key]?.[0];
    if (entry?.cvssData) {
      return {
        version: entry.cvssData.version ?? null,
        score: entry.cvssData.baseScore ?? null,
        severity: entry.cvssData.baseSeverity ?? entry.baseSeverity ?? null,
        vector: entry.cvssData.vectorString ?? null,
      };
    }
  }
  return { version: null, score: null, severity: null, vector: null };
}

/** Incremental pull by last-modified window; NVD caps a window at 120 days. */
async function syncNvd(
  admin: SupabaseClient,
  since: string | null,
): Promise<{ records: number; version: string | null }> {
  const end = new Date();
  const startMs = since ? Date.parse(since) : end.getTime() - 7 * 864e5;
  const start = new Date(Math.max(startMs, end.getTime() - 110 * 864e5));
  const apiKey = process.env["NVD_API_KEY"];
  const headers: Record<string, string> = apiKey ? { apiKey } : {};

  const base =
    `https://services.nvd.nist.gov/rest/json/cves/2.0?` +
    `lastModStartDate=${encodeURIComponent(start.toISOString())}` +
    `&lastModEndDate=${encodeURIComponent(end.toISOString())}&resultsPerPage=2000`;

  let total = 0;
  const maxPages = apiKey ? 6 : 2;
  for (let page = 0; page < maxPages; page++) {
    const doc = await getJson<NvdDoc>(`${base}&startIndex=${page * 2000}`, headers);
    const rows = doc.vulnerabilities.map(({ cve }) => {
      const m = pickMetric(cve.metrics);
      return {
        cve_id: cve.id,
        published: cve.published ?? null,
        last_modified: cve.lastModified ?? null,
        vuln_status: cve.vulnStatus ?? null,
        description: cve.descriptions?.find((d) => d.lang === "en")?.value ?? null,
        cvss_version: m.version,
        cvss_score: m.score,
        cvss_severity: m.severity,
        cvss_vector: m.vector,
        cwe: cve.weaknesses?.[0]?.description?.find((d) => d.lang === "en")?.value ?? null,
        synced_at: new Date().toISOString(),
      };
    });
    if (rows.length) total += await upsert(admin, "nvd_cves", rows, "cve_id");
    if (doc.startIndex + doc.resultsPerPage >= doc.totalResults) break;
    if (!apiKey) await new Promise((r) => setTimeout(r, 6500)); // unauthenticated rate limit
  }
  return { records: total, version: `window ${start.toISOString().slice(0, 10)}..${end.toISOString().slice(0, 10)}` };
}

/* ----------------------------- MITRE ATT&CK ---------------------------- */

const ATTACK_TAXII = "https://attack-taxii.mitre.org/api/v21";
const ENTERPRISE_COLLECTION = "x-mitre-collection--1f5f1533-f617-4ca8-9ab4-6a02367fa019";

interface TaxiiEnvelope {
  more?: boolean;
  next?: string;
  objects?: Array<{
    id: string;
    type: string;
    name?: string;
    description?: string;
    revoked?: boolean;
    x_mitre_deprecated?: boolean;
    kill_chain_phases?: Array<{ kill_chain_name: string; phase_name: string }>;
    external_references?: Array<{ source_name: string; external_id?: string; url?: string }>;
  }>;
}

async function syncAttack(admin: SupabaseClient): Promise<{ records: number; version: string | null }> {
  let next: string | undefined;
  let total = 0;
  for (let page = 0; page < 8; page++) {
    const url =
      `${ATTACK_TAXII}/collections/${ENTERPRISE_COLLECTION}/objects/?match[type]=attack-pattern&limit=200` +
      (next ? `&next=${encodeURIComponent(next)}` : "");
    const doc = await getJson<TaxiiEnvelope>(url, { Accept: "application/taxii+json;version=2.1" });
    const rows = (doc.objects ?? [])
      .map((o) => {
        const ref = o.external_references?.find((r) => r.source_name === "mitre-attack");
        if (!ref?.external_id) return null;
        return {
          id: ref.external_id,
          name: o.name ?? ref.external_id,
          tactics: (o.kill_chain_phases ?? [])
            .filter((p) => p.kill_chain_name === "mitre-attack")
            .map((p) => p.phase_name),
          description: o.description?.slice(0, 4000) ?? null,
          url: ref.url ?? null,
          revoked: Boolean(o.revoked || o.x_mitre_deprecated),
          synced_at: new Date().toISOString(),
        };
      })
      .filter((r): r is NonNullable<typeof r> => r !== null);
    if (rows.length) total += await upsert(admin, "attack_techniques", rows, "id");
    if (!doc.more || !doc.next) break;
    next = doc.next;
  }
  return { records: total, version: "enterprise-attack" };
}

/* ------------------------------ Orchestration --------------------------- */

export async function runFeedSync(
  admin: SupabaseClient,
  feedId: FeedId,
  trigger: "manual" | "scheduled",
): Promise<SyncOutcome> {
  const startedAt = new Date();
  const { data: run } = await admin
    .from("feed_sync_runs")
    .insert({ feed_id: feedId, trigger, started_at: startedAt.toISOString() })
    .select("id")
    .single();

  await admin.from("threat_feeds").update({ status: "syncing", updated_at: startedAt.toISOString() }).eq("id", feedId);

  try {
    const { data: feed } = await admin
      .from("threat_feeds")
      .select("last_synced_at")
      .eq("id", feedId)
      .single();

    let result: { records: number; version: string | null };
    if (feedId === "kev") result = await syncKev(admin);
    else if (feedId === "epss") result = await syncEpss(admin);
    else if (feedId === "nvd") result = await syncNvd(admin, (feed?.last_synced_at as string) ?? null);
    else result = await syncAttack(admin);

    const latencyMs = Date.now() - startedAt.getTime();
    const table =
      feedId === "kev" ? "kev_entries" : feedId === "epss" ? "epss_scores" : feedId === "nvd" ? "nvd_cves" : "attack_techniques";
    const { count } = await admin.from(table).select("*", { count: "exact", head: true });

    await admin
      .from("threat_feeds")
      .update({
        status: "operational",
        last_synced_at: new Date().toISOString(),
        last_error: null,
        record_count: count ?? result.records,
        latency_ms: latencyMs,
        dataset_version: result.version,
        updated_at: new Date().toISOString(),
      })
      .eq("id", feedId);

    if (run?.id) {
      await admin
        .from("feed_sync_runs")
        .update({
          finished_at: new Date().toISOString(),
          ok: true,
          records_upserted: result.records,
          latency_ms: latencyMs,
        })
        .eq("id", run.id);
    }

    return { feedId, ok: true, records: result.records, latencyMs, datasetVersion: result.version };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const latencyMs = Date.now() - startedAt.getTime();
    await admin
      .from("threat_feeds")
      .update({ status: "degraded", last_error: message, latency_ms: latencyMs, updated_at: new Date().toISOString() })
      .eq("id", feedId);
    if (run?.id) {
      await admin
        .from("feed_sync_runs")
        .update({ finished_at: new Date().toISOString(), ok: false, error: message, latency_ms: latencyMs })
        .eq("id", run.id);
    }
    return { feedId, ok: false, records: 0, latencyMs, error: message };
  }
}

export const ALL_FEEDS: FeedId[] = ["kev", "nvd", "epss", "mitre"];
