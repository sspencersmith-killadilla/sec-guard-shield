-- ---------------------------------------------------------------
-- GovShield SecOps: identity, roles, tamper-evident audit log,
-- and threat intelligence storage.
-- ---------------------------------------------------------------

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Roles -----------------------------------------------------------
CREATE TYPE public.app_role AS ENUM ('admin', 'assessor', 'auditor');

CREATE TABLE public.profiles (
  id uuid PRIMARY KEY,
  email text NOT NULL,
  full_name text,
  created_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT, UPDATE ON public.profiles TO authenticated;
GRANT ALL ON public.profiles TO service_role;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "profiles readable by authenticated"
  ON public.profiles FOR SELECT TO authenticated USING (true);
CREATE POLICY "users update own profile"
  ON public.profiles FOR UPDATE TO authenticated
  USING (id = auth.uid()) WITH CHECK (id = auth.uid());

CREATE TABLE public.user_roles (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL,
  role public.app_role NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, role)
);

GRANT SELECT ON public.user_roles TO authenticated;
GRANT ALL ON public.user_roles TO service_role;
ALTER TABLE public.user_roles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "roles readable by authenticated"
  ON public.user_roles FOR SELECT TO authenticated USING (true);

CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role public.app_role)
RETURNS boolean
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_id = _user_id AND role = _role
  )
$$;

-- Tamper-evident audit log ----------------------------------------
CREATE TABLE public.audit_log (
  seq bigserial PRIMARY KEY,
  occurred_at timestamptz NOT NULL DEFAULT now(),
  actor_id uuid,
  actor_email text NOT NULL,
  actor_role public.app_role,
  action text NOT NULL,
  target text NOT NULL,
  details jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash text NOT NULL,
  hash text NOT NULL
);

-- Deliberately append-only: no INSERT/UPDATE/DELETE grants to app roles.
GRANT SELECT ON public.audit_log TO authenticated;
GRANT ALL ON public.audit_log TO service_role;
ALTER TABLE public.audit_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY "audit readable by authenticated"
  ON public.audit_log FOR SELECT TO authenticated USING (true);

-- Block mutation even for table owners going through the API.
CREATE OR REPLACE FUNCTION public.audit_log_immutable()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  RAISE EXCEPTION 'audit_log is append-only';
END;
$$;

CREATE TRIGGER audit_log_no_update
  BEFORE UPDATE OR DELETE ON public.audit_log
  FOR EACH ROW EXECUTE FUNCTION public.audit_log_immutable();

CREATE OR REPLACE FUNCTION public.append_audit(
  _action text,
  _target text,
  _details jsonb DEFAULT '{}'::jsonb
)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  _uid uuid := auth.uid();
  _email text;
  _role public.app_role;
  _prev text;
  _seq bigint;
  _ts timestamptz := now();
  _hash text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('govshield.audit_log'));

  SELECT email INTO _email FROM public.profiles WHERE id = _uid;
  IF _email IS NULL THEN _email := COALESCE(_uid::text, 'system'); END IF;

  SELECT role INTO _role FROM public.user_roles WHERE user_id = _uid
    ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'assessor' THEN 2 ELSE 3 END LIMIT 1;

  SELECT hash INTO _prev FROM public.audit_log ORDER BY seq DESC LIMIT 1;
  IF _prev IS NULL THEN _prev := repeat('0', 64); END IF;

  _seq := nextval('public.audit_log_seq_seq');

  _hash := encode(digest(
    _seq::text || '|' || _ts::text || '|' || _email || '|' || COALESCE(_role::text, 'none')
      || '|' || _action || '|' || _target || '|' || _details::text || '|' || _prev,
    'sha256'), 'hex');

  INSERT INTO public.audit_log (seq, occurred_at, actor_id, actor_email, actor_role, action, target, details, prev_hash, hash)
  VALUES (_seq, _ts, _uid, _email, _role, _action, _target, _details, _prev, _hash);

  RETURN _seq;
END;
$$;

GRANT EXECUTE ON FUNCTION public.append_audit(text, text, jsonb) TO authenticated, service_role;

-- Recompute and compare the whole chain.
CREATE OR REPLACE FUNCTION public.verify_audit_chain()
RETURNS TABLE (total bigint, valid boolean, first_broken_seq bigint)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  r record;
  _prev text := repeat('0', 64);
  _calc text;
  _broken bigint := NULL;
  _count bigint := 0;
BEGIN
  FOR r IN SELECT * FROM public.audit_log ORDER BY seq ASC LOOP
    _count := _count + 1;
    _calc := encode(digest(
      r.seq::text || '|' || r.occurred_at::text || '|' || r.actor_email || '|'
        || COALESCE(r.actor_role::text, 'none') || '|' || r.action || '|' || r.target
        || '|' || r.details::text || '|' || r.prev_hash,
      'sha256'), 'hex');
    IF _broken IS NULL AND (r.prev_hash <> _prev OR r.hash <> _calc) THEN
      _broken := r.seq;
    END IF;
    _prev := r.hash;
  END LOOP;
  RETURN QUERY SELECT _count, _broken IS NULL, _broken;
END;
$$;

GRANT EXECUTE ON FUNCTION public.verify_audit_chain() TO authenticated, service_role;

-- Bootstrap: create profile on first sign-in, first user becomes admin.
CREATE OR REPLACE FUNCTION public.bootstrap_profile(_email text, _full_name text DEFAULT NULL)
RETURNS public.app_role
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  _uid uuid := auth.uid();
  _role public.app_role;
  _is_first boolean;
BEGIN
  IF _uid IS NULL THEN RAISE EXCEPTION 'not authenticated'; END IF;

  INSERT INTO public.profiles (id, email, full_name)
  VALUES (_uid, _email, _full_name)
  ON CONFLICT (id) DO UPDATE SET email = EXCLUDED.email,
    full_name = COALESCE(EXCLUDED.full_name, public.profiles.full_name);

  SELECT role INTO _role FROM public.user_roles WHERE user_id = _uid
    ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'assessor' THEN 2 ELSE 3 END LIMIT 1;

  IF _role IS NULL THEN
    SELECT NOT EXISTS (SELECT 1 FROM public.user_roles) INTO _is_first;
    _role := CASE WHEN _is_first THEN 'admin'::public.app_role ELSE 'auditor'::public.app_role END;
    INSERT INTO public.user_roles (user_id, role) VALUES (_uid, _role)
      ON CONFLICT (user_id, role) DO NOTHING;
  END IF;

  RETURN _role;
END;
$$;

GRANT EXECUTE ON FUNCTION public.bootstrap_profile(text, text) TO authenticated;

-- Threat intelligence ---------------------------------------------
CREATE TABLE public.threat_feeds (
  id text PRIMARY KEY,
  name text NOT NULL,
  source text NOT NULL,
  cadence_minutes integer NOT NULL DEFAULT 360,
  status text NOT NULL DEFAULT 'idle',
  last_synced_at timestamptz,
  last_error text,
  record_count integer NOT NULL DEFAULT 0,
  latency_ms integer,
  dataset_version text,
  auto_update boolean NOT NULL DEFAULT true,
  updated_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON public.threat_feeds TO authenticated;
GRANT ALL ON public.threat_feeds TO service_role;
ALTER TABLE public.threat_feeds ENABLE ROW LEVEL SECURITY;
CREATE POLICY "feeds readable by authenticated"
  ON public.threat_feeds FOR SELECT TO authenticated USING (true);

INSERT INTO public.threat_feeds (id, name, source, cadence_minutes) VALUES
  ('kev',   'CISA KEV Catalog',            'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', 360),
  ('nvd',   'NIST NVD API 2.0',            'https://services.nvd.nist.gov/rest/json/cves/2.0', 360),
  ('epss',  'FIRST EPSS',                  'https://epss.empiricalsecurity.com/epss_scores-current.csv.gz', 1440),
  ('mitre', 'MITRE ATT&CK Enterprise',     'https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json', 10080);

CREATE TABLE public.kev_entries (
  cve_id text PRIMARY KEY,
  vendor_project text,
  product text,
  vulnerability_name text,
  date_added date,
  due_date date,
  required_action text,
  known_ransomware text,
  short_description text,
  synced_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON public.kev_entries TO authenticated;
GRANT ALL ON public.kev_entries TO service_role;
ALTER TABLE public.kev_entries ENABLE ROW LEVEL SECURITY;
CREATE POLICY "kev readable by authenticated"
  ON public.kev_entries FOR SELECT TO authenticated USING (true);

CREATE TABLE public.epss_scores (
  cve_id text PRIMARY KEY,
  epss numeric NOT NULL,
  percentile numeric NOT NULL,
  score_date date NOT NULL,
  synced_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON public.epss_scores TO authenticated;
GRANT ALL ON public.epss_scores TO service_role;
ALTER TABLE public.epss_scores ENABLE ROW LEVEL SECURITY;
CREATE POLICY "epss readable by authenticated"
  ON public.epss_scores FOR SELECT TO authenticated USING (true);

CREATE TABLE public.nvd_cves (
  cve_id text PRIMARY KEY,
  published timestamptz,
  last_modified timestamptz,
  vuln_status text,
  description text,
  cvss_version text,
  cvss_score numeric,
  cvss_severity text,
  cvss_vector text,
  cwe text,
  synced_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX nvd_cves_last_modified_idx ON public.nvd_cves (last_modified DESC);
CREATE INDEX nvd_cves_severity_idx ON public.nvd_cves (cvss_severity);

GRANT SELECT ON public.nvd_cves TO authenticated;
GRANT ALL ON public.nvd_cves TO service_role;
ALTER TABLE public.nvd_cves ENABLE ROW LEVEL SECURITY;
CREATE POLICY "nvd readable by authenticated"
  ON public.nvd_cves FOR SELECT TO authenticated USING (true);

CREATE TABLE public.attack_techniques (
  id text PRIMARY KEY,
  name text NOT NULL,
  tactics text[],
  description text,
  url text,
  revoked boolean NOT NULL DEFAULT false,
  synced_at timestamptz NOT NULL DEFAULT now()
);

GRANT SELECT ON public.attack_techniques TO authenticated;
GRANT ALL ON public.attack_techniques TO service_role;
ALTER TABLE public.attack_techniques ENABLE ROW LEVEL SECURITY;
CREATE POLICY "attack readable by authenticated"
  ON public.attack_techniques FOR SELECT TO authenticated USING (true);

CREATE TABLE public.feed_sync_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  feed_id text NOT NULL REFERENCES public.threat_feeds(id) ON DELETE CASCADE,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz,
  trigger text NOT NULL DEFAULT 'manual',
  ok boolean,
  records_upserted integer,
  latency_ms integer,
  error text
);

CREATE INDEX feed_sync_runs_feed_idx ON public.feed_sync_runs (feed_id, started_at DESC);

GRANT SELECT ON public.feed_sync_runs TO authenticated;
GRANT ALL ON public.feed_sync_runs TO service_role;
ALTER TABLE public.feed_sync_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY "sync runs readable by authenticated"
  ON public.feed_sync_runs FOR SELECT TO authenticated USING (true);
