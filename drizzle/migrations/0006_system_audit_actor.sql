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

  _hash := encode(digest(
    _seq::text || '|' || _ts::text || '|' || _actor || '|' || 'none'
      || '|' || _action || '|' || _target || '|' || _details::text || '|' || _prev,
    'sha256'), 'hex');

  INSERT INTO public.audit_log (seq, occurred_at, actor_id, actor_email, actor_role, action, target, details, prev_hash, hash)
  VALUES (_seq, _ts, NULL, _actor, NULL, _action, _target, _details, _prev, _hash);

  RETURN _seq;
END;
$$;

REVOKE EXECUTE ON FUNCTION public.append_audit_system(text, text, text, jsonb) FROM PUBLIC;
REVOKE EXECUTE ON FUNCTION public.append_audit_system(text, text, text, jsonb) FROM anon;
REVOKE EXECUTE ON FUNCTION public.append_audit_system(text, text, text, jsonb) FROM authenticated;
GRANT EXECUTE ON FUNCTION public.append_audit_system(text, text, text, jsonb) TO service_role;