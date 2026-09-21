-- Helper: elevated read roles (admin = full oversight, auditor = compliance read)
CREATE OR REPLACE FUNCTION public.is_oversight(_user_id uuid)
RETURNS boolean
LANGUAGE sql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.user_roles
    WHERE user_id = _user_id AND role IN ('admin','auditor')
  )
$$;
REVOKE ALL ON FUNCTION public.is_oversight(uuid) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.is_oversight(uuid) TO authenticated, service_role;

-- profiles: own row or admin
DROP POLICY IF EXISTS "profiles readable by authenticated" ON public.profiles;
CREATE POLICY "profiles readable by self or admin"
ON public.profiles FOR SELECT TO authenticated
USING (id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

-- user_roles: own rows or admin
DROP POLICY IF EXISTS "roles readable by authenticated" ON public.user_roles;
CREATE POLICY "roles readable by self or admin"
ON public.user_roles FOR SELECT TO authenticated
USING (user_id = auth.uid() OR public.has_role(auth.uid(), 'admin'));

-- audit_log: oversight roles only
DROP POLICY IF EXISTS "audit readable by authenticated" ON public.audit_log;
CREATE POLICY "audit readable by oversight roles"
ON public.audit_log FOR SELECT TO authenticated
USING (public.is_oversight(auth.uid()));

-- scan_workers: admin only (contains key hashes / infrastructure metadata)
DROP POLICY IF EXISTS "workers readable by signed-in users" ON public.scan_workers;
CREATE POLICY "workers readable by admins"
ON public.scan_workers FOR SELECT TO authenticated
USING (public.has_role(auth.uid(), 'admin'));

-- scans: owner or oversight roles
DROP POLICY IF EXISTS "scans readable by signed-in users" ON public.scans;
CREATE POLICY "scans readable by owner or oversight"
ON public.scans FOR SELECT TO authenticated
USING (created_by = auth.uid() OR public.is_oversight(auth.uid()));

-- scan_events: tied to a readable scan
DROP POLICY IF EXISTS "scan events readable by signed-in users" ON public.scan_events;
CREATE POLICY "scan events readable with parent scan"
ON public.scan_events FOR SELECT TO authenticated
USING (EXISTS (
  SELECT 1 FROM public.scans s
  WHERE s.id = scan_events.scan_id
    AND (s.created_by = auth.uid() OR public.is_oversight(auth.uid()))
));

-- scan_findings: tied to a readable scan
DROP POLICY IF EXISTS "findings readable by signed-in users" ON public.scan_findings;
CREATE POLICY "findings readable with parent scan"
ON public.scan_findings FOR SELECT TO authenticated
USING (EXISTS (
  SELECT 1 FROM public.scans s
  WHERE s.id = scan_findings.scan_id
    AND (s.created_by = auth.uid() OR public.is_oversight(auth.uid()))
));

-- Harden SECURITY DEFINER functions callable by signed-in users
CREATE OR REPLACE FUNCTION public.has_role(_user_id uuid, _role app_role)
RETURNS boolean
LANGUAGE plpgsql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $$
BEGIN
  IF auth.uid() IS NULL THEN
    RAISE EXCEPTION 'not authenticated';
  END IF;
  IF _user_id <> auth.uid() AND NOT EXISTS (
      SELECT 1 FROM public.user_roles WHERE user_id = auth.uid() AND role = 'admin') THEN
    RAISE EXCEPTION 'forbidden';
  END IF;
  RETURN EXISTS (
    SELECT 1 FROM public.user_roles WHERE user_id = _user_id AND role = _role
  );
END;
$$;
REVOKE ALL ON FUNCTION public.has_role(uuid, app_role) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.has_role(uuid, app_role) TO authenticated, service_role;

CREATE OR REPLACE FUNCTION public.verify_audit_chain()
RETURNS TABLE(total bigint, valid boolean, first_broken_seq bigint)
LANGUAGE plpgsql
STABLE SECURITY DEFINER
SET search_path TO 'public'
AS $$
DECLARE
  r record;
  _prev text := repeat('0', 64);
  _calc text;
  _broken bigint := NULL;
  _count bigint := 0;
BEGIN
  IF auth.uid() IS NULL OR NOT public.is_oversight(auth.uid()) THEN
    RAISE EXCEPTION 'forbidden';
  END IF;
  FOR r IN SELECT * FROM public.audit_log ORDER BY seq ASC LOOP
    _count := _count + 1;
    _calc := encode(sha256(convert_to(
      r.seq::text || '|' || r.occurred_at::text || '|' || r.actor_email || '|'
        || COALESCE(r.actor_role::text, 'none') || '|' || r.action || '|' || r.target
        || '|' || r.details::text || '|' || r.prev_hash,
      'UTF8')), 'hex');
    IF _broken IS NULL AND (r.prev_hash <> _prev OR r.hash <> _calc) THEN
      _broken := r.seq;
    END IF;
    _prev := r.hash;
  END LOOP;
  RETURN QUERY SELECT _count, _broken IS NULL, _broken;
END;
$$;
REVOKE ALL ON FUNCTION public.verify_audit_chain() FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.verify_audit_chain() TO authenticated, service_role;

-- append_audit must only ever run for an authenticated caller
CREATE OR REPLACE FUNCTION public.append_audit(_action text, _target text, _details jsonb DEFAULT '{}'::jsonb)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
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
  IF _uid IS NULL THEN RAISE EXCEPTION 'not authenticated'; END IF;

  PERFORM pg_advisory_xact_lock(hashtext('govshield.audit_log'));

  SELECT email INTO _email FROM public.profiles WHERE id = _uid;
  IF _email IS NULL THEN _email := _uid::text; END IF;

  SELECT role INTO _role FROM public.user_roles WHERE user_id = _uid
    ORDER BY CASE role WHEN 'admin' THEN 1 WHEN 'assessor' THEN 2 ELSE 3 END LIMIT 1;

  SELECT hash INTO _prev FROM public.audit_log ORDER BY seq DESC LIMIT 1;
  IF _prev IS NULL THEN _prev := repeat('0', 64); END IF;

  _seq := nextval('public.audit_log_seq_seq');

  _hash := encode(sha256(convert_to(
    _seq::text || '|' || _ts::text || '|' || _email || '|' || COALESCE(_role::text, 'none')
      || '|' || _action || '|' || _target || '|' || _details::text || '|' || _prev,
    'UTF8')), 'hex');

  INSERT INTO public.audit_log (seq, occurred_at, actor_id, actor_email, actor_role, action, target, details, prev_hash, hash)
  VALUES (_seq, _ts, _uid, _email, _role, _action, _target, _details, _prev, _hash);

  RETURN _seq;
END;
$$;
REVOKE ALL ON FUNCTION public.append_audit(text, text, jsonb) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.append_audit(text, text, jsonb) TO authenticated, service_role;

REVOKE ALL ON FUNCTION public.bootstrap_profile(text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.bootstrap_profile(text, text) TO authenticated, service_role;