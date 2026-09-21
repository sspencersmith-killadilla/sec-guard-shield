import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useServerFn } from "@tanstack/react-start";
import { FINDINGS, INITIAL_PLUGINS, SCAN_STAGES } from "./data";
import {
  ROLE_LABEL,
  bootstrapIdentity,
  listAudit,
  listFeedState,
  recordAudit,
  setAutoUpdate as setAutoUpdateFn,
  syncFeedsNow,
  verifyAuditChain,
  type AppRole,
  type AuditRow,
  type FeedRow,
} from "./platform.functions";
import type {
  AuditEntry,
  Finding,
  ModuleKey,
  Role,
  ScanMode,
  ScannerPlugin,
  TargetType,
  ThreatFeed,
} from "./types";

export interface ScanConfig {
  target: TargetType;
  value: string;
  modules: ModuleKey[];
  mode: ScanMode;
  cadence: string;
}

interface GovShieldState {
  identityLoading: boolean;
  email: string;
  appRole: AppRole;
  role: Role;
  canWrite: boolean;
  feeds: ThreatFeed[];
  feedRows: FeedRow[];
  counts: { kev: number; epss: number; nvd: number; mitre: number };
  plugins: ScannerPlugin[];
  autoUpdate: boolean;
  toggleAutoUpdate: () => void;
  syncing: boolean;
  syncNow: () => void;
  lastSync: number;
  nextSyncIn: number;
  feedsLoading: boolean;
  config: ScanConfig;
  updateConfig: (patch: Partial<ScanConfig>) => void;
  scanStage: number;
  scanning: boolean;
  hasResults: boolean;
  startScan: () => void;
  resetScan: () => void;
  findings: Finding[];
  auditLog: AuditEntry[];
  log: (action: string, target: string) => void;
  chainValid: boolean | null;
  chainTotal: number;
  verifyChain: () => void;
  verifying: boolean;
}

const Ctx = createContext<GovShieldState | null>(null);

function toFeed(row: FeedRow): ThreatFeed {
  return {
    id: row.id as ThreatFeed["id"],
    name: row.name,
    source: new URL(row.source).hostname,
    records: row.record_count,
    lastSynced: row.last_synced_at ? Date.parse(row.last_synced_at) : 0,
    status:
      row.status === "syncing" ? "syncing" : row.status === "degraded" ? "degraded" : "operational",
    latencyMs: row.latency_ms ?? 0,
  };
}

function toAuditEntry(row: AuditRow): AuditEntry {
  return {
    id: `AU-${String(row.seq).padStart(5, "0")}`,
    timestamp: Date.parse(row.occurred_at),
    actor: row.actor_email,
    role: row.actor_role ? ROLE_LABEL[row.actor_role] : "Read-Only Auditor",
    action: row.action,
    target: row.target,
    prevHash: row.prev_hash,
    hash: row.hash,
  };
}

export function GovShieldProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const bootstrap = useServerFn(bootstrapIdentity);
  const fetchFeeds = useServerFn(listFeedState);
  const fetchAudit = useServerFn(listAudit);
  const appendAudit = useServerFn(recordAudit);
  const runSync = useServerFn(syncFeedsNow);
  const toggleAuto = useServerFn(setAutoUpdateFn);
  const verify = useServerFn(verifyAuditChain);

  const identity = useQuery({
    queryKey: ["govshield", "identity"],
    queryFn: () => bootstrap({ data: undefined as never }),
    staleTime: 5 * 60_000,
  });

  const feedState = useQuery({
    queryKey: ["govshield", "feeds"],
    queryFn: () => fetchFeeds(),
    refetchInterval: 30_000,
  });

  const audit = useQuery({
    queryKey: ["govshield", "audit"],
    queryFn: () => fetchAudit(),
  });

  const [now, setNow] = useState(0);
  const [chainValid, setChainValid] = useState<boolean | null>(null);
  const [chainTotal, setChainTotal] = useState(0);
  const [config, setConfig] = useState<ScanConfig>({
    target: "dast",
    value: "https://portal.agency.gov",
    modules: ["owasp", "misconfig", "secrets", "kev", "deps"],
    mode: "standard",
    cadence: "Every 24 hours",
  });
  const [scanStage, setScanStage] = useState(-1);
  const [hasResults, setHasResults] = useState(false);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  useEffect(() => {
    setNow(Date.now());
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const invalidateAudit = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: ["govshield", "audit"] });
  }, [queryClient]);

  const log = useCallback(
    (action: string, target: string) => {
      appendAudit({ data: { action, target } })
        .then(invalidateAudit)
        .catch(() => undefined);
    },
    [appendAudit, invalidateAudit],
  );

  // One session entry per authenticated console load.
  const sessionLogged = useRef(false);
  useEffect(() => {
    if (identity.data && !sessionLogged.current) {
      sessionLogged.current = true;
      log("SESSION_ESTABLISHED", "govshield.console");
    }
  }, [identity.data, log]);

  const syncMutation = useMutation({
    mutationFn: () => runSync({ data: {} }),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["govshield", "feeds"] });
      invalidateAudit();
    },
  });

  const autoMutation = useMutation({
    mutationFn: (enabled: boolean) => toggleAuto({ data: { enabled } }),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["govshield", "feeds"] });
      invalidateAudit();
    },
  });

  const verifyMutation = useMutation({
    mutationFn: () => verify({ data: undefined as never }),
    onSuccess: (res) => {
      setChainValid(res.valid);
      setChainTotal(res.total);
      invalidateAudit();
    },
  });

  const startScan = useCallback(() => {
    setHasResults(false);
    setScanStage(0);
    log("SCAN_EXECUTION_STARTED", `${config.target}:${config.value}`);
    SCAN_STAGES.forEach((_, i) => {
      const t = setTimeout(() => setScanStage(i), i * 1000);
      timers.current.push(t);
    });
    const done = setTimeout(() => {
      setScanStage(-1);
      setHasResults(true);
      log("SCAN_COMPLETED_OSCAL_GENERATED", `${FINDINGS.length} findings correlated`);
    }, 4000);
    timers.current.push(done);
  }, [config.target, config.value, log]);

  const resetScan = useCallback(() => {
    setHasResults(false);
    setScanStage(-1);
    log("RESULTS_CLEARED", "assessment.workspace");
  }, [log]);

  const feedRows = feedState.data?.feeds ?? [];
  const feeds = useMemo(() => feedRows.map(toFeed), [feedRows]);
  const appRole: AppRole = identity.data?.role ?? "auditor";
  const autoUpdate = feedRows.length > 0 && feedRows.every((f) => f.auto_update);
  const syncing = syncMutation.isPending || feedRows.some((f) => f.status === "syncing");
  const lastSync = feeds.reduce((max, f) => Math.max(max, f.lastSynced), 0);

  const nextSyncIn = useMemo(() => {
    if (!autoUpdate || !now) return 0;
    const due = feedRows
      .map((f) => (f.last_synced_at ? Date.parse(f.last_synced_at) + f.cadence_minutes * 60_000 : now))
      .filter((t) => Number.isFinite(t));
    if (!due.length) return 0;
    return Math.max(0, Math.min(...due) - now);
  }, [autoUpdate, feedRows, now]);

  // Signature version reflects the newest ingested dataset, not a timer.
  const plugins = useMemo<ScannerPlugin[]>(() => {
    if (!lastSync) return INITIAL_PLUGINS;
    const d = new Date(lastSync).toISOString();
    const sig = `${d.slice(0, 4)}.${d.slice(5, 7)}.${d.slice(8, 10)}-${d.slice(11, 13)}${d.slice(14, 16)}`;
    return INITIAL_PLUGINS.map((p) => ({ ...p, signature: sig }));
  }, [lastSync]);

  const auditLog = useMemo(() => (audit.data ?? []).map(toAuditEntry), [audit.data]);

  const value: GovShieldState = useMemo(
    () => ({
      identityLoading: identity.isLoading,
      email: identity.data?.email ?? "",
      appRole,
      role: ROLE_LABEL[appRole],
      canWrite: appRole !== "auditor",
      feeds,
      feedRows,
      counts: feedState.data?.counts ?? { kev: 0, epss: 0, nvd: 0, mitre: 0 },
      plugins,
      autoUpdate,
      toggleAutoUpdate: () => autoMutation.mutate(!autoUpdate),
      syncing,
      syncNow: () => syncMutation.mutate(),
      lastSync,
      nextSyncIn,
      feedsLoading: feedState.isLoading,
      config,
      updateConfig: (patch) => setConfig((c) => ({ ...c, ...patch })),
      scanStage,
      scanning: scanStage >= 0,
      hasResults,
      startScan,
      resetScan,
      findings: hasResults ? FINDINGS : [],
      auditLog,
      log,
      chainValid,
      chainTotal,
      verifyChain: () => verifyMutation.mutate(),
      verifying: verifyMutation.isPending,
    }),
    [
      identity.isLoading,
      identity.data,
      appRole,
      feeds,
      feedRows,
      feedState.data,
      feedState.isLoading,
      plugins,
      autoUpdate,
      autoMutation,
      syncing,
      syncMutation,
      lastSync,
      nextSyncIn,
      config,
      scanStage,
      hasResults,
      startScan,
      resetScan,
      auditLog,
      log,
      chainValid,
      chainTotal,
      verifyMutation,
    ],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useGovShield() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useGovShield must be used within GovShieldProvider");
  return ctx;
}
