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

  _hash := encode(sha256(convert_to(
    _seq::text || '|' || _ts::text || '|' || _email || '|' || COALESCE(_role::text, 'none')
      || '|' || _action || '|' || _target || '|' || _details::text || '|' || _prev,
    'UTF8')), 'hex');

  INSERT INTO public.audit_log (seq, occurred_at, actor_id, actor_email, actor_role, action, target, details, prev_hash, hash)
  VALUES (_seq, _ts, _uid, _email, _role, _action, _target, _details, _prev, _hash);

  RETURN _seq;
END;
$$;

GRANT EXECUTE ON FUNCTION public.append_audit(text, text, jsonb) TO authenticated, service_role;

CREATE OR REPLACE FUNCTION public.append_audit_system(
  _actor text,
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
  _prev text;
  _seq bigint;
  _ts timestamptz := now();
  _hash text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtext('govshield.audit_log'));

  SELECT hash INTO _prev FROM public.audit_log ORDER BY seq DESC LIMIT 1;
  IF _prev IS NULL THEN _prev := repeat('0', 64); END IF;

  _seq := nextval('public.audit_log_seq_seq');

  _hash := encode(sha256(convert_to(
    _seq::text || '|' || _ts::text || '|' || _actor || '|' || 'none'
      || '|' || _action || '|' || _target || '|' || _details::text || '|' || _prev,
    'UTF8')), 'hex');

  INSERT INTO public.audit_log (seq, occurred_at, actor_id, actor_email, actor_role, action, target, details, prev_hash, hash)
  VALUES (_seq, _ts, NULL, _actor, NULL, _action, _target, _details, _prev, _hash);

  RETURN _seq;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.append_audit_system(text, text, text, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.append_audit_system(text, text, text, jsonb) FROM anon;
REVOKE EXECUTE ON FUNCTION public.append_audit_system(text, text, text, jsonb) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.append_audit_system(text, text, text, jsonb) TO service_role;

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

GRANT EXECUTE ON FUNCTION public.verify_audit_chain() TO authenticated, service_role;