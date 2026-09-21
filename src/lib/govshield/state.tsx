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
import { FINDINGS, INITIAL_FEEDS, INITIAL_PLUGINS, SCAN_STAGES } from "./data";
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

const SYNC_INTERVAL_MS = 15 * 60 * 1000;

/** Deterministic, non-cryptographic digest used to simulate tamper-evident chaining. */
function pseudoHash(input: string): string {
  let h1 = 0x811c9dc5;
  let h2 = 0x01000193;
  for (let i = 0; i < input.length; i++) {
    h1 = (h1 ^ input.charCodeAt(i)) * 16777619;
    h2 = (h2 + input.charCodeAt(i) * (i + 7)) ^ (h1 >>> 3);
  }
  const part = (n: number) => (n >>> 0).toString(16).padStart(8, "0");
  return `${part(h1)}${part(h2)}${part(h1 ^ h2)}${part(h1 + h2)}`;
}

export interface ScanConfig {
  target: TargetType;
  value: string;
  modules: ModuleKey[];
  mode: ScanMode;
  cadence: string;
}

interface GovShieldState {
  role: Role;
  setRole: (role: Role) => void;
  canWrite: boolean;
  feeds: ThreatFeed[];
  plugins: ScannerPlugin[];
  autoUpdate: boolean;
  toggleAutoUpdate: () => void;
  syncing: boolean;
  syncNow: () => void;
  lastSync: number;
  nextSyncIn: number;
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
  verifyChain: () => void;
}

const Ctx = createContext<GovShieldState | null>(null);

const GENESIS = "0".repeat(32);

export function GovShieldProvider({ children }: { children: ReactNode }) {
  const [role, setRoleState] = useState<Role>("Admin");
  const [feeds, setFeeds] = useState<ThreatFeed[]>(INITIAL_FEEDS);
  const [plugins, setPlugins] = useState<ScannerPlugin[]>(INITIAL_PLUGINS);
  const [autoUpdate, setAutoUpdate] = useState(true);
  const [syncing, setSyncing] = useState(false);
  const [lastSync, setLastSync] = useState(0);
  const [now, setNow] = useState(0);
  const [config, setConfig] = useState<ScanConfig>({
    target: "dast",
    value: "https://portal.agency.gov",
    modules: ["owasp", "misconfig", "secrets", "kev", "deps"],
    mode: "standard",
    cadence: "Every 24 hours",
  });
  const [scanStage, setScanStage] = useState(-1);
  const [hasResults, setHasResults] = useState(false);
  const [auditLog, setAuditLog] = useState<AuditEntry[]>([]);
  const [chainValid, setChainValid] = useState<boolean | null>(null);
  const timers = useRef<ReturnType<typeof setTimeout>[]>([]);

  const log = useCallback((action: string, target: string) => {
    setAuditLog((prev) => {
      const prevHash = prev[0]?.hash ?? GENESIS;
      const timestamp = Date.now();
      const id = `AU-${(prev.length + 1).toString().padStart(4, "0")}`;
      const actor = "s.smith@agency.gov";
      const entry: AuditEntry = {
        id,
        timestamp,
        actor,
        role,
        action,
        target,
        prevHash,
        hash: pseudoHash(`${id}|${timestamp}|${actor}|${action}|${target}|${prevHash}`),
      };
      return [entry, ...prev].slice(0, 80);
    });
  }, [role]);

  // Clock + initial sync timestamps (client-only to avoid hydration drift).
  useEffect(() => {
    const t = Date.now();
    setNow(t);
    setLastSync(t - 4 * 60 * 1000);
    setFeeds((prev) => prev.map((f, i) => ({ ...f, lastSynced: t - (4 + i) * 60 * 1000 })));
    log("SESSION_ESTABLISHED", "govshield.console");
    const interval = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(interval);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  const syncNow = useCallback(() => {
    setSyncing(true);
    setFeeds((prev) => prev.map((f) => ({ ...f, status: "syncing" as const })));
    log("THREAT_FEED_SYNC_INITIATED", "kev,nvd,mitre,epss");
    const t = setTimeout(() => {
      const stamp = Date.now();
      setFeeds((prev) =>
        prev.map((f) => ({
          ...f,
          status: "operational" as const,
          lastSynced: stamp,
          records: f.records + Math.floor(3 + Math.random() * 40),
          latencyMs: 280 + Math.floor(Math.random() * 700),
        })),
      );
      const sig = new Date(stamp).toISOString().slice(0, 10).replace(/-/g, "") ;
      setPlugins((prev) =>
        prev.map((p) => ({
          ...p,
          signature: `${sig.slice(0, 4)}.${sig.slice(4, 6)}.${sig.slice(6, 8)}-${new Date(stamp)
            .toISOString()
            .slice(11, 16)
            .replace(":", "")}`,
        })),
      );
      setLastSync(stamp);
      setSyncing(false);
      log("THREAT_FEED_SYNC_COMPLETED", "signatures.hot-reloaded");
    }, 1800);
    timers.current.push(t);
  }, [log]);

  // Auto-sync scheduler
  useEffect(() => {
    if (!autoUpdate || !lastSync) return;
    const due = lastSync + SYNC_INTERVAL_MS - Date.now();
    const t = setTimeout(() => syncNow(), Math.max(1000, due));
    return () => clearTimeout(t);
  }, [autoUpdate, lastSync, syncNow]);

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

  const value: GovShieldState = useMemo(
    () => ({
      role,
      setRole: (r) => {
        setRoleState(r);
        log("ROLE_SCOPE_CHANGED", r);
      },
      canWrite: role !== "Read-Only Auditor",
      feeds,
      plugins,
      autoUpdate,
      toggleAutoUpdate: () => {
        setAutoUpdate((v) => {
          log("AUTO_UPDATE_RULES_TOGGLED", v ? "disabled" : "enabled");
          return !v;
        });
      },
      syncing,
      syncNow,
      lastSync,
      nextSyncIn: autoUpdate && lastSync && now ? Math.max(0, lastSync + SYNC_INTERVAL_MS - now) : 0,
      config,
      updateConfig: (patch) => {
        setConfig((c) => ({ ...c, ...patch }));
        log("SCAN_CONFIGURATION_UPDATED", Object.keys(patch).join(","));
      },
      scanStage,
      scanning: scanStage >= 0,
      hasResults,
      startScan,
      resetScan,
      findings: hasResults ? FINDINGS : [],
      auditLog,
      log,
      chainValid,
      verifyChain: () => {
        setChainValid(true);
        log("AUDIT_CHAIN_VERIFIED", "sha-256 chain intact");
      },
    }),
    [
      role,
      feeds,
      plugins,
      autoUpdate,
      syncing,
      syncNow,
      lastSync,
      now,
      config,
      scanStage,
      hasResults,
      startScan,
      resetScan,
      auditLog,
      log,
      chainValid,
    ],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useGovShield() {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useGovShield must be used within GovShieldProvider");
  return ctx;
}

export { pseudoHash };
