ALTER FUNCTION public.bootstrap_profile(text, text) SET search_path = public;

REVOKE EXECUTE ON FUNCTION public.bootstrap_profile(text, text) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.append_audit(text, text, jsonb) FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.verify_audit_chain() FROM PUBLIC, anon;
REVOKE EXECUTE ON FUNCTION public.has_role(uuid, public.app_role) FROM PUBLIC, anon;

GRANT EXECUTE ON FUNCTION public.bootstrap_profile(text, text) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.append_audit(text, text, jsonb) TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.verify_audit_chain() TO authenticated, service_role;
GRANT EXECUTE ON FUNCTION public.has_role(uuid, public.app_role) TO authenticated, service_role;