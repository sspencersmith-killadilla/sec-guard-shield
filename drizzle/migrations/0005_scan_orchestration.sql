CREATE TYPE public.scan_status AS ENUM ('queued', 'claimed', 'running', 'completed', 'failed', 'cancelled');

CREATE TABLE public.scan_workers (
  id            text PRIMARY KEY,
  name          text NOT NULL,
  key_hash      text NOT NULL,
  capabilities  text[] NOT NULL DEFAULT '{}',
  version       text,
  status        text NOT NULL DEFAULT 'registered',
  last_seen_at  timestamptz,
  created_by    uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at    timestamptz NOT NULL DEFAULT now(),
  revoked_at    timestamptz
);
CREATE INDEX scan_workers_key_hash_idx ON public.scan_workers (key_hash);
GRANT SELECT ON public.scan_workers TO authenticated;
GRANT ALL ON public.scan_workers TO service_role;
ALTER TABLE public.scan_workers ENABLE ROW LEVEL SECURITY;
CREATE POLICY "workers readable by signed-in users" ON public.scan_workers FOR SELECT TO authenticated USING (true);

CREATE TABLE public.scans (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  created_by      uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  created_email   text NOT NULL,
  target_type     text NOT NULL,
  target_value    text NOT NULL,
  modules         text[] NOT NULL DEFAULT '{}',
  mode            text NOT NULL DEFAULT 'standard',
  cadence         text,
  status          public.scan_status NOT NULL DEFAULT 'queued',
  stage           text NOT NULL DEFAULT 'Queued for an available worker',
  progress        int NOT NULL DEFAULT 0,
  worker_id       text REFERENCES public.scan_workers(id) ON DELETE SET NULL,
  attempts        int NOT NULL DEFAULT 0,
  error           text,
  findings_count  int NOT NULL DEFAULT 0,
  posture         int,
  tool_versions   jsonb NOT NULL DEFAULT '{}'::jsonb,
  queued_at       timestamptz NOT NULL DEFAULT now(),
  claimed_at      timestamptz,
  finished_at     timestamptz,
  heartbeat_at    timestamptz
);
CREATE INDEX scans_queue_idx ON public.scans (status, queued_at);
CREATE INDEX scans_recent_idx ON public.scans (queued_at DESC);
GRANT SELECT ON public.scans TO authenticated;
GRANT ALL ON public.scans TO service_role;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
CREATE POLICY "scans readable by signed-in users" ON public.scans FOR SELECT TO authenticated USING (true);

CREATE TABLE public.scan_findings (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id           uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  ordinal           int NOT NULL,
  ref               text NOT NULL,
  title             text NOT NULL,
  severity          text NOT NULL,
  module            text NOT NULL,
  target_type       text NOT NULL,
  tool              text NOT NULL,
  rule_id           text,
  cve               text,
  kev               boolean NOT NULL DEFAULT false,
  kev_due_date      date,
  epss              numeric(6,5) NOT NULL DEFAULT 0,
  cvss31            numeric(3,1) NOT NULL DEFAULT 0,
  cvss40            numeric(3,1) NOT NULL DEFAULT 0,
  cvss_vector       text,
  nist_controls     text[] NOT NULL DEFAULT '{}',
  fedramp_baseline  text NOT NULL DEFAULT 'Moderate',
  fips1403          boolean NOT NULL DEFAULT false,
  privacy_impact    text,
  privacy_category  text,
  location          text NOT NULL,
  description       text NOT NULL,
  remediation       text NOT NULL,
  remediation_code  text,
  verification      text[] NOT NULL DEFAULT '{}',
  raw               jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX scan_findings_scan_idx ON public.scan_findings (scan_id, ordinal);
GRANT SELECT ON public.scan_findings TO authenticated;
GRANT ALL ON public.scan_findings TO service_role;
ALTER TABLE public.scan_findings ENABLE ROW LEVEL SECURITY;
CREATE POLICY "findings readable by signed-in users" ON public.scan_findings FOR SELECT TO authenticated USING (true);

CREATE TABLE public.scan_events (
  id        bigserial PRIMARY KEY,
  scan_id   uuid NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
  at        timestamptz NOT NULL DEFAULT now(),
  stage     text NOT NULL,
  message   text,
  progress  int
);
CREATE INDEX scan_events_scan_idx ON public.scan_events (scan_id, id);
GRANT SELECT ON public.scan_events TO authenticated;
GRANT ALL ON public.scan_events TO service_role;
ALTER TABLE public.scan_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY "scan events readable by signed-in users" ON public.scan_events FOR SELECT TO authenticated USING (true);

CREATE OR REPLACE FUNCTION public.claim_scan(_worker_id text, _capabilities text[])
RETURNS public.scans
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  claimed public.scans;
BEGIN
  SELECT * INTO claimed
  FROM public.scans
  WHERE status = 'queued'
    AND target_type = ANY(_capabilities)
  ORDER BY queued_at
  FOR UPDATE SKIP LOCKED
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN NULL;
  END IF;

  UPDATE public.scans
  SET status = 'claimed',
      worker_id = _worker_id,
      claimed_at = now(),
      heartbeat_at = now(),
      attempts = attempts + 1,
      stage = 'Claimed by worker ' || _worker_id
  WHERE id = claimed.id
  RETURNING * INTO claimed;

  INSERT INTO public.scan_events (scan_id, stage, message, progress)
  VALUES (claimed.id, 'Claimed', 'Assigned to worker ' || _worker_id, 5);

  RETURN claimed;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.claim_scan(text, text[]) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.claim_scan(text, text[]) FROM anon;
REVOKE EXECUTE ON FUNCTION public.claim_scan(text, text[]) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.claim_scan(text, text[]) TO service_role;

CREATE OR REPLACE FUNCTION public.reap_stalled_scans(_timeout_minutes int DEFAULT 20)
RETURNS int
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  affected int;
BEGIN
  WITH stalled AS (
    UPDATE public.scans
    SET status = CASE WHEN attempts >= 3 THEN 'failed'::public.scan_status ELSE 'queued'::public.scan_status END,
        stage = CASE WHEN attempts >= 3 THEN 'Abandoned after 3 attempts' ELSE 'Requeued after worker timeout' END,
        error = CASE WHEN attempts >= 3 THEN 'Worker stopped reporting progress' ELSE error END,
        finished_at = CASE WHEN attempts >= 3 THEN now() ELSE NULL END,
        worker_id = NULL
    WHERE status IN ('claimed', 'running')
      AND coalesce(heartbeat_at, claimed_at) < now() - make_interval(mins => _timeout_minutes)
    RETURNING 1
  )
  SELECT count(*) INTO affected FROM stalled;
  RETURN affected;
END;
$$;
REVOKE EXECUTE ON FUNCTION public.reap_stalled_scans(int) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.reap_stalled_scans(int) FROM anon;
REVOKE EXECUTE ON FUNCTION public.reap_stalled_scans(int) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.reap_stalled_scans(int) TO service_role;