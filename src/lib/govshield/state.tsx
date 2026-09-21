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
import { INITIAL_PLUGINS } from "./data";
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
import {
  cancelScan as cancelScanFn,
  createScan,
  getScan,
  issueWorkerKey as issueWorkerKeyFn,
  listScans,
  listWorkers,
  revokeWorker as revokeWorkerFn,
  type FindingRow,
  type ScanEventRow,
  type ScanRow,
  type WorkerRow,
} from "./scans.functions";
import type {
  AuditEntry,
  ControlCoverage,
  Finding,
  ModuleKey,
  Role,
  ScanMode,
  ScannerPlugin,
  Severity,
  TargetType,
  ThreatFeed,
} from "./types";

export interface ScanConfig {
  target: TargetType;
  value: string;
  modules: ModuleKey[];
  mode: ScanMode;
  cadence: string;
  authorized: boolean;
}

const ACTIVE_STATUSES = new Set(["queued", "claimed", "running"]);

interface GovShieldState {
  identityLoading: boolean;
  email: string;
  appRole: AppRole;
  role: Role;
  canWrite: boolean;
  isAdmin: boolean;
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
  scans: ScanRow[];
  selectedScan: ScanRow | null;
  selectScan: (id: string) => void;
  scanEvents: ScanEventRow[];
  scanning: boolean;
  scanProgress: number;
  scanStageLabel: string;
  scanError: string | null;
  queueError: string | null;
  startScan: () => void;
  cancelScan: () => void;
  resetScan: () => void;
  hasResults: boolean;
  findings: Finding[];
  findingsLoading: boolean;
  posture: number | null;
  controlCoverage: ControlCoverage[];
  trend: { day: string; posture: number; critical: number; high: number }[];
  workers: WorkerRow[];
  issueWorkerKey: (name: string, capabilities: string[]) => Promise<{ workerId: string; key: string }>;
  revokeWorker: (workerId: string) => void;
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

function toFinding(row: FindingRow): Finding {
  return {
    id: row.ref,
    title: row.title,
    severity: row.severity as Severity,
    module: row.module as ModuleKey,
    target: row.target_type as TargetType,
    epss: Number(row.epss),
    cvss31: Number(row.cvss31),
    cvss40: Number(row.cvss40),
    cvssVector: row.cvss_vector ?? "",
    cve: row.cve,
    kev: row.kev,
    nistControls: row.nist_controls,
    fedrampBaseline: row.fedramp_baseline === "High" ? "High" : "Moderate",
    fips1403: row.fips1403,
    privacyImpact: row.privacy_impact,
    privacyCategory: row.privacy_category,
    location: row.location,
    description: row.description,
    remediation: row.remediation,
    remediationCode: row.remediation_code ?? "",
    verification: row.verification,
  };
}

const CONTROL_TITLES: Record<string, { family: string; title: string }> = {
  "SI-2": { family: "System and Information Integrity", title: "Flaw Remediation" },
  "SI-3": { family: "System and Information Integrity", title: "Malicious Code Protection" },
  "SI-10": { family: "System and Information Integrity", title: "Information Input Validation" },
  "SI-11": { family: "System and Information Integrity", title: "Error Handling" },
  "RA-5": { family: "Risk Assessment", title: "Vulnerability Monitoring and Scanning" },
  "SC-7": { family: "System and Communications Protection", title: "Boundary Protection" },
  "SC-8": { family: "System and Communications Protection", title: "Transmission Confidentiality" },
  "SC-12": { family: "System and Communications Protection", title: "Cryptographic Key Management" },
  "SC-13": { family: "System and Communications Protection", title: "Cryptographic Protection" },
  "SC-28": { family: "System and Communications Protection", title: "Protection of Information at Rest" },
  "AC-3": { family: "Access Control", title: "Access Enforcement" },
  "CM-6": { family: "Configuration Management", title: "Configuration Settings" },
  "CM-7": { family: "Configuration Management", title: "Least Functionality" },
  "CM-8": { family: "Configuration Management", title: "System Component Inventory" },
  "IA-5": { family: "Identification and Authentication", title: "Authenticator Management" },
  "AU-9": { family: "Audit and Accountability", title: "Protection of Audit Information" },
  "SA-11": { family: "System and Services Acquisition", title: "Developer Testing and Evaluation" },
  "PT-2": { family: "Personally Identifiable Information Processing", title: "Authority to Process PII" },
};

export function GovShieldProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient();
  const bootstrap = useServerFn(bootstrapIdentity);
  const fetchFeeds = useServerFn(listFeedState);
  const fetchAudit = useServerFn(listAudit);
  const appendAudit = useServerFn(recordAudit);
  const runSync = useServerFn(syncFeedsNow);
  const toggleAuto = useServerFn(setAutoUpdateFn);
  const verify = useServerFn(verifyAuditChain);
  const queueScan = useServerFn(createScan);
  const fetchScans = useServerFn(listScans);
  const fetchScan = useServerFn(getScan);
  const abortScan = useServerFn(cancelScanFn);
  const fetchWorkers = useServerFn(listWorkers);
  const mintWorker = useServerFn(issueWorkerKeyFn);
  const revoke = useServerFn(revokeWorkerFn);

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

  const scansQuery = useQuery({
    queryKey: ["govshield", "scans"],
    queryFn: () => fetchScans(),
    refetchInterval: (query) =>
      (query.state.data ?? []).some((s) => ACTIVE_STATUSES.has(s.status)) ? 2500 : 20_000,
  });

  const workersQuery = useQuery({
    queryKey: ["govshield", "workers"],
    queryFn: () => fetchWorkers(),
    refetchInterval: 20_000,
  });

  const [now, setNow] = useState(0);
  const [chainValid, setChainValid] = useState<boolean | null>(null);
  const [chainTotal, setChainTotal] = useState(0);
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [queueError, setQueueError] = useState<string | null>(null);
  const [config, setConfig] = useState<ScanConfig>({
    target: "sast",
    value: "",
    modules: ["owasp", "misconfig", "secrets", "kev", "deps"],
    mode: "standard",
    cadence: "Every 24 hours",
    authorized: false,
  });

  const scans = useMemo(() => scansQuery.data ?? [], [scansQuery.data]);

  // Follow the newest scan until the operator picks a different one.
  const effectiveScanId = selectedScanId ?? scans[0]?.id ?? null;

  const scanDetail = useQuery({
    queryKey: ["govshield", "scan", effectiveScanId],
    queryFn: () => fetchScan({ data: { scanId: effectiveScanId! } }),
    enabled: Boolean(effectiveScanId),
    refetchInterval: (query) => {
      const status = query.state.data?.scan?.status;
      return status && ACTIVE_STATUSES.has(status) ? 2000 : false;
    },
  });

  useEffect(() => {
    setNow(Date.now());
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
  }, []);

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

  // A finished scan writes its own audit entry from the worker endpoint.
  const lastStatus = useRef<string | null>(null);
  const detailStatus = scanDetail.data?.scan?.status ?? null;
  useEffect(() => {
    if (detailStatus && lastStatus.current && detailStatus !== lastStatus.current) {
      invalidateAudit();
    }
    lastStatus.current = detailStatus;
  }, [detailStatus, invalidateAudit]);

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

  const queueMutation = useMutation({
    mutationFn: () =>
      queueScan({
        data: {
          targetType: config.target,
          targetValue: config.value,
          modules: config.modules,
          mode: config.mode,
          cadence: config.cadence,
          authorized: config.authorized,
        },
      }),
    onSuccess: (scan) => {
      setQueueError(null);
      setSelectedScanId(scan.id);
      void queryClient.invalidateQueries({ queryKey: ["govshield", "scans"] });
      invalidateAudit();
    },
    onError: (err: Error) => setQueueError(err.message),
  });

  const cancelMutation = useMutation({
    mutationFn: (scanId: string) => abortScan({ data: { scanId } }),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["govshield", "scans"] });
      void queryClient.invalidateQueries({ queryKey: ["govshield", "scan"] });
      invalidateAudit();
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (workerId: string) => revoke({ data: { workerId } }),
    onSettled: () => {
      void queryClient.invalidateQueries({ queryKey: ["govshield", "workers"] });
      invalidateAudit();
    },
  });

  const issueWorkerKey = useCallback(
    async (name: string, capabilities: string[]) => {
      const res = await mintWorker({ data: { name, capabilities } });
      void queryClient.invalidateQueries({ queryKey: ["govshield", "workers"] });
      invalidateAudit();
      return res;
    },
    [mintWorker, queryClient, invalidateAudit],
  );

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

  const selectedScan = scanDetail.data?.scan ?? null;
  const findings = useMemo(
    () => (scanDetail.data?.findings ?? []).map(toFinding),
    [scanDetail.data],
  );
  const scanEvents = scanDetail.data?.events ?? [];
  const scanning = Boolean(selectedScan && ACTIVE_STATUSES.has(selectedScan.status));

  const controlCoverage = useMemo<ControlCoverage[]>(() => {
    const counts = new Map<string, number>();
    findings.forEach((f) => f.nistControls.forEach((c) => counts.set(c, (counts.get(c) ?? 0) + 1)));
    const baseline = ["SI-2", "RA-5", "SC-7", "SC-8", "AC-3", "CM-6", "IA-5", "AU-9", "SI-10"];
    const all = new Set([...baseline, ...counts.keys()]);
    return Array.from(all)
      .map((control) => {
        const hits = counts.get(control) ?? 0;
        const meta = CONTROL_TITLES[control] ?? { family: "Other", title: control };
        return {
          control,
          family: meta.family,
          title: meta.title,
          status: hits === 0 ? "satisfied" : hits > 2 ? "failed" : ("partial" as const),
          findings: hits,
        } as ControlCoverage;
      })
      .sort((a, b) => b.findings - a.findings || a.control.localeCompare(b.control));
  }, [findings]);

  // Posture history from real completed assessments.
  const trend = useMemo(() => {
    return scans
      .filter((s) => s.status === "completed" && s.posture !== null)
      .slice(0, 30)
      .reverse()
      .map((s) => ({
        day: new Date(s.finished_at ?? s.queued_at).toLocaleDateString(undefined, {
          month: "short",
          day: "numeric",
        }),
        posture: s.posture ?? 0,
        critical: 0,
        high: 0,
      }));
  }, [scans]);

  const startScan = useCallback(() => {
    setQueueError(null);
    queueMutation.mutate();
  }, [queueMutation]);

  const value: GovShieldState = useMemo(
    () => ({
      identityLoading: identity.isLoading,
      email: identity.data?.email ?? "",
      appRole,
      role: ROLE_LABEL[appRole],
      canWrite: appRole !== "auditor",
      isAdmin: appRole === "admin",
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
      scans,
      selectedScan,
      selectScan: (id: string) => setSelectedScanId(id),
      scanEvents,
      scanning,
      scanProgress: selectedScan?.progress ?? 0,
      scanStageLabel: selectedScan?.stage ?? "",
      scanError: selectedScan?.error ?? null,
      queueError: queueError ?? (queueMutation.isPending ? null : queueError),
      startScan,
      cancelScan: () => selectedScan && cancelMutation.mutate(selectedScan.id),
      resetScan: () => setSelectedScanId(null),
      hasResults: Boolean(selectedScan?.status === "completed"),
      findings,
      findingsLoading: scanDetail.isLoading,
      posture: selectedScan?.posture ?? null,
      controlCoverage,
      trend,
      workers: workersQuery.data ?? [],
      issueWorkerKey,
      revokeWorker: (id: string) => revokeMutation.mutate(id),
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
      scans,
      selectedScan,
      scanEvents,
      scanning,
      queueError,
      queueMutation.isPending,
      startScan,
      cancelMutation,
      findings,
      scanDetail.isLoading,
      controlCoverage,
      trend,
      workersQuery.data,
      issueWorkerKey,
      revokeMutation,
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
