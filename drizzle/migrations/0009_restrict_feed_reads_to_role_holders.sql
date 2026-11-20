DROP POLICY IF EXISTS "sync runs readable by authenticated" ON public.feed_sync_runs;
CREATE POLICY "sync runs readable by role holders" ON public.feed_sync_runs FOR SELECT TO authenticated
USING (public.has_role(auth.uid(),'admin') OR public.has_role(auth.uid(),'assessor') OR public.has_role(auth.uid(),'auditor'));
DROP POLICY IF EXISTS "feeds readable by authenticated" ON public.threat_feeds;
CREATE POLICY "feeds readable by role holders" ON public.threat_feeds FOR SELECT TO authenticated
USING (public.has_role(auth.uid(),'admin') OR public.has_role(auth.uid(),'assessor') OR public.has_role(auth.uid(),'auditor'));