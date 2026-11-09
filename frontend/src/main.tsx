import React, { useCallback, useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ArrowDownLeft,
  ArrowRight,
  Bell,
  Boxes,
  Check,
  ChevronRight,
  CircleDot,
  Cloud,
  Code2,
  Database,
  FileCheck2,
  Fingerprint,
  GitBranch,
  Globe2,
  Layers3,
  LayoutDashboard,
  LockKeyhole,
  LogOut,
  Network,
  Radar,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldCheck,
  Terminal,
  Workflow,
  X,
} from "lucide-react";
import "./style.css";

type RecordData = { [key: string]: any };
type Page =
  | "Overview"
  | "Findings"
  | "Incidents"
  | "Assets"
  | "Detections"
  | "Automation"
  | "Approvals"
  | "Audit trail"
  | "Integrations";
const navigation: { name: Page; icon: typeof Shield }[] = [
  { name: "Overview", icon: LayoutDashboard },
  { name: "Findings", icon: Radar },
  { name: "Incidents", icon: Layers3 },
  { name: "Assets", icon: Boxes },
  { name: "Detections", icon: Code2 },
  { name: "Automation", icon: Workflow },
  { name: "Approvals", icon: FileCheck2 },
  { name: "Audit trail", icon: Fingerprint },
  { name: "Integrations", icon: Network },
];
const family = (source: string) => source.split(".")[0];
const short = (value: string, length = 28) =>
  value?.length > length ? value.slice(0, length) + "…" : value;
const date = (value: string | number) =>
  value
    ? new Date(
        typeof value === "number" ? value * 1000 : value,
      ).toLocaleString()
    : "No evidence received";
const label = (value: string) => value.replaceAll("_", " ");
function Badge({
  children,
  tone = "neutral",
}: {
  children: React.ReactNode;
  tone?: string;
}) {
  return <span className={"badge " + tone}>{children}</span>;
}
function Empty({ text }: { text: string }) {
  return (
    <div className="empty">
      <Database size={26} />
      <p>{text}</p>
    </div>
  );
}

function App() {
  const [generation, setGeneration] = useState(0);
  return (
    <Session
      key={generation}
      endSession={() => setGeneration((value) => value + 1)}
    />
  );
}

function Session({ endSession }: { endSession: () => void }) {
  const lifecycle = useRef({ active: true, controller: new AbortController() });
  useEffect(() => {
    const owner = { active: true, controller: new AbortController() };
    lifecycle.current = owner;
    return () => {
      owner.active = false;
      owner.controller.abort();
    };
  }, []);
  const [token, setToken] = useState("");
  const [inputToken, setInputToken] = useState("");
  const [me, setMe] = useState<RecordData | null>(null);
  const [page, setPage] = useState<Page>("Overview");
  const [data, setData] = useState<RecordData>({
    overview: {},
    sources: [],
    events: [],
    incidents: [],
    actions: [],
    rules: [],
    audit: [],
    targets: [],
  });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<RecordData | null>(null);
  const [packet, setPacket] = useState<RecordData | null>(null);
  const [reports, setReports] = useState<RecordData[]>([]);
  const [replay, setReplay] = useState<RecordData | null>(null);
  const [checkpoint, setCheckpoint] = useState<RecordData | null>(null);

  const api = useCallback(
    async (
      path: string,
      method = "GET",
      body?: unknown,
      credential = token,
    ) => {
      const owner = lifecycle.current;
      if (!owner.active) throw new DOMException("Session ended", "AbortError");
      const response = await fetch("/api" + path, {
        method,
        headers: {
          Authorization: "Bearer " + credential,
          ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        },
        body: body !== undefined ? JSON.stringify(body) : undefined,
        signal: owner.controller.signal,
      });
      const result = await response.json();
      if (!owner.active || lifecycle.current !== owner)
        throw new DOMException("Session ended", "AbortError");
      if (!response.ok)
        throw new Error(
          typeof result.detail === "string"
            ? result.detail
            : "The request could not be validated.",
        );
      return result;
    },
    [token],
  );
  const refresh = useCallback(async () => {
    if (!token) return;
    try {
      const paths = [
        "overview",
        "sources",
        "events",
        "incidents",
        "actions",
        "rules",
        "audit",
        "targets",
      ];
      const responses = await Promise.all(paths.map((p) => api("/" + p)));
      setData(Object.fromEntries(paths.map((p, i) => [p, responses[i]])));
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }, [api, token]);
  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), 30000);
    return () => clearInterval(timer);
  }, [refresh]);
  async function run(operation: () => Promise<void>) {
    setBusy(true);
    setError("");
    try {
      await operation();
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function login(e: React.FormEvent) {
    e.preventDefault();
    await run(async () => {
      const identity = await api("/me", "GET", undefined, inputToken);
      if (
        !identity.roles.some((r: string) =>
          ["observer", "analyst", "approver", "executor"].includes(r),
        )
      )
        throw new Error(
          "This credential is for collection only. Use an operations credential.",
        );
      setMe(identity);
      setToken(inputToken);
      setInputToken("");
    });
  }
  function logout() {
    lifecycle.current.active = false;
    lifecycle.current.controller.abort();
    endSession();
  }
  const allowed = (role: string) => me?.roles.includes(role);
  async function inspectIncident(incident: RecordData) {
    await run(async () => {
      const [detail, history] = await Promise.all([
        api("/incidents/" + incident.id),
        api("/incidents/" + incident.id + "/investigations"),
      ]);
      setPacket(detail);
      setReports(history);
      setSelected({ kind: "incident", ...incident });
    });
  }
  async function investigate() {
    if (!selected) return;
    await run(async () => {
      const report = await api(
        "/incidents/" + selected.id + "/investigate",
        "POST",
        { use_ai: false },
      );
      setReports([report, ...reports]);
    });
  }
  async function propose(
    target: string,
    action = "contain",
    original?: string,
  ) {
    if (!selected) return;
    await run(async () => {
      const plan = await api("/actions", "POST", {
        incident_id: selected.id,
        target,
        action,
        original_action_id: original ?? null,
      });
      setSelected({ kind: "action", ...plan });
      setPage("Approvals");
    });
  }

  if (!me)
    return (
      <main className="login">
        <div className="login-brand">
          <span className="brand-icon">
            <Shield size={23} />
          </span>{" "}
          SecOpsMesh <span className="version">v0.1</span>
        </div>
        <div className="login-grid">
          <section>
            <div className="eyebrow">
              <span className="dot" /> UNIFIED SECURITY OPERATIONS
            </div>
            <h1>
              Every signal.
              <br />
              One evidence trail.
            </h1>
            <p className="login-description">
              Investigate across your infrastructure. Correlate what matters.
              Respond with independent approval and verified outcomes.
            </p>
            <div className="environment-row">
              {["ON-PREMISES", "AWS", "AZURE", "GCP", "KUBERNETES"].map((s) => (
                <span key={s}>{s}</span>
              ))}
            </div>
            <div className="trust-note">
              <ShieldCheck size={20} />
              <span>
                Evidence first. Explicit authority. Measurable response.
              </span>
            </div>
          </section>
          <form onSubmit={login} className="login-card">
            <span className="mini-label">OPERATIONS CONSOLE</span>
            <h2>Open your workspace</h2>
            <p>
              Use your tenant-scoped operations credential. Sessions stay in
              this browser tab’s memory.
            </p>
            <label htmlFor="credential">Access credential</label>
            <input
              id="credential"
              aria-label="Access credential"
              type="password"
              autoComplete="off"
              value={inputToken}
              onChange={(e) => setInputToken(e.target.value)}
              required
              placeholder="Enter your access credential"
            />
            {error && (
              <p role="alert" className="error">
                {error}
              </p>
            )}
            <button className="primary full" disabled={busy}>
              Connect to workspace <ArrowRight size={16} />
            </button>
            <div className="credential-help">
              <LockKeyhole size={16} />
              <span>
                Use a generated local lab credential or an operator-issued
                credential. Collectors cannot open the console.
              </span>
            </div>
          </form>
        </div>
        <footer>
          OPEN SOURCE SECURITY AUTOMATION{" "}
          <span>Read-only investigation · Approval-bound response</span>
        </footer>
      </main>
    );

  const overview = data.overview;
  const events: RecordData[] = data.events.filter((e: RecordData) =>
    canonicalSearch(e).includes(search.toLowerCase()),
  );
  const pending = data.actions.filter((a: RecordData) => a.state === "pending");
  const families = ["wazuh", "aws", "azure", "gcp", "kubernetes"];
  const descriptions: Record<Page, string> = {
    Overview: "Your security operations, connected.",
    Findings:
      "Normalized evidence with source provenance and quality indicators.",
    Incidents:
      "Correlated activity across assets, identities, and environments.",
    Assets:
      "Observed assets and identities. Missing telemetry never implies security.",
    Detections:
      "Versioned rules, deterministic execution, reproducible replay.",
    Automation:
      "Exact action plans, durable execution, independent verification.",
    Approvals: "Independent review before any privileged response.",
    "Audit trail": "Tenant-scoped, integrity-protected operational history.",
    Integrations: "Transport health and explicit provider acceptance status.",
  };
  const findingsTable = (rows: RecordData[]) =>
    rows.length ? (
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Finding / observed evidence</th>
              <th>Source</th>
              <th>Risk</th>
              <th>Asset</th>
              <th>Data quality</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={e.id}>
                <td>
                  <button
                    className="text-button finding-title"
                    onClick={() => setSelected({ kind: "event", ...e })}
                  >
                    {e.title}
                  </button>
                  <small>
                    {date(e.observed_at)}{" "}
                    <span className="synthetic-label">
                      {e.synthetic ? "SYNTHETIC" : "PROVIDER INPUT"}
                    </span>
                  </small>
                </td>
                <td>
                  <span className="source-name">
                    <span className={"source-dot " + family(e.source)} />
                    {e.source}
                  </span>
                </td>
                <td>
                  <Badge tone={e.risk >= 70 ? "danger" : "warn"}>
                    {e.risk >= 70 ? "High" : "Medium"} · {e.risk}
                  </Badge>
                </td>
                <td>
                  <span title={e.asset}>{short(e.asset, 24)}</span>
                  <small>
                    {short(e.identity || "Identity unavailable", 24)}
                  </small>
                </td>
                <td>
                  {e.quality.length ? (
                    <Badge tone="warn">
                      {e.quality.length} indicator
                      {e.quality.length > 1 ? "s" : ""}
                    </Badge>
                  ) : (
                    <span className="quality">
                      <Check size={13} /> Required fields present
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    ) : (
      <Empty text="No evidence matches this view." />
    );
  const actionsList = (rows: RecordData[]) =>
    rows.length ? (
      <div className="action-list">
        {rows.map((a) => (
          <button
            className="action-row"
            key={a.id}
            onClick={() => setSelected({ kind: "action", ...a })}
          >
            <span className="action-icon">
              <Workflow size={19} />
            </span>
            <span>
              <strong>
                {label(a.plan.action)} · {a.plan.target}
              </strong>
              <small>
                {a.requester}{" "}
                <span className="mono">{a.fingerprint.slice(0, 12)}</span>
              </small>
            </span>
            <Badge
              tone={
                a.state === "verified"
                  ? "good"
                  : a.state === "ambiguous" || a.state === "verification_failed"
                    ? "danger"
                    : "warn"
              }
            >
              {label(a.state)}
            </Badge>
            <ChevronRight size={16} />
          </button>
        ))}
      </div>
    ) : (
      <Empty text="No action plans in this view." />
    );

  return (
    <div className="shell">
      <aside className="sidebar">
        <a
          className="brand"
          href="#"
          onClick={(e) => {
            e.preventDefault();
            setPage("Overview");
          }}
        >
          <span className="brand-icon">
            <Shield size={23} />
          </span>
          <span>
            SecOpsMesh<small>SECURITY OPERATIONS</small>
          </span>
        </a>
        <div className="workspace">
          <span className="workspace-icon">
            {me.tenant.slice(0, 1).toUpperCase()}
          </span>
          <div>
            <strong>{me.tenant} workspace</strong>
            <small>Unified operations</small>
          </div>
          <ChevronRight size={14} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav aria-label="Main navigation">
          {navigation.map(({ name, icon: Icon }) => (
            <button
              aria-label={name}
              className={page === name ? "active" : ""}
              onClick={() => {
                setPage(name);
                setSearch("");
                setSelected(null);
              }}
              key={name}
            >
              <Icon size={18} />
              {name}
              {name === "Approvals" && pending.length > 0 && (
                <span className="nav-count">{pending.length}</span>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="boundary-note">
            <LockKeyhole size={16} />
            <div>
              Controlled response<small>Independent approval required</small>
            </div>
          </div>
          <button className="user" onClick={logout} title="Switch credential">
            <span className="avatar">{me.name.slice(0, 1).toUpperCase()}</span>
            <span>
              <strong>{me.name}</strong>
              <small>{me.roles.join(", ")}</small>
            </span>
            <LogOut size={16} />
          </button>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <div className="breadcrumb">
            Workspace <ChevronRight size={13} />
            <strong>{page}</strong>
          </div>
          <div className="topbar-right">
            <span className="session">
              <span className="dot" /> Authenticated session
            </span>
            <button
              className="icon-button"
              aria-label="Refresh data"
              onClick={() => void refresh()}
            >
              <RefreshCw size={17} />
            </button>
            <span className="top-avatar">
              {me.name.slice(0, 1).toUpperCase()}
            </span>
          </div>
        </header>
        <main className="content">
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECOPS / {page.toUpperCase()}</div>
              <h1>{page === "Overview" ? "Security overview" : page}</h1>
              <p>{descriptions[page]}</p>
            </div>
            <div className="heading-actions">
              <span className="updated">
                {overview.as_of
                  ? "Updated " + new Date(overview.as_of).toLocaleTimeString()
                  : ""}
              </span>
              <button
                className="button"
                onClick={() => void refresh()}
                disabled={busy}
              >
                <RefreshCw size={14} /> Refresh
              </button>
            </div>
          </div>
          {error && (
            <div className="error-banner" role="alert">
              <Shield size={16} />
              {error}
              <button aria-label="Dismiss error" onClick={() => setError("")}>
                <X size={15} />
              </button>
            </div>
          )}
          <div className="lab-banner">
            <FlaskIcon />
            <span>
              <strong>
                {overview.synthetic_events === overview.events &&
                overview.events > 0
                  ? "Synthetic lab evidence"
                  : overview.synthetic_events > 0
                    ? "Mixed evidence workspace"
                    : "Evidence workspace"}
              </strong>{" "}
              · {overview.synthetic_events ?? 0} synthetic /{" "}
              {overview.events ?? 0} received records. Provider acceptance is
              tracked separately.
            </span>
            <button
              className="text-button"
              onClick={() => setPage("Integrations")}
            >
              View source status <ArrowRight size={13} />
            </button>
          </div>
          {page === "Overview" && (
            <>
              <div className="metrics">
                {[
                  {
                    label: "Evidence received",
                    value: overview.events,
                    icon: ArrowDownLeft,
                    sub: "Normalized source records",
                    tone: "blue",
                  },
                  {
                    label: "Active incidents",
                    value: overview.incidents,
                    icon: Layers3,
                    sub: `${overview.high_risk ?? 0} with high risk evidence`,
                    tone: "orange",
                  },
                  {
                    label: "Awaiting approval",
                    value: overview.pending_approvals,
                    icon: FileCheck2,
                    sub: "Independent review required",
                    tone: "purple",
                  },
                  {
                    label: "Verified responses",
                    value: overview.verified_actions,
                    icon: ShieldCheck,
                    sub: `${overview.uncertain_actions ?? 0} uncertain outcomes`,
                    tone: "green",
                  },
                ].map(({ label, value, icon: Icon, sub, tone }) => (
                  <article className="metric-card" key={label}>
                    <div>
                      <span>{label}</span>
                      <span className={"metric-icon " + tone}>
                        <Icon size={18} />
                      </span>
                    </div>
                    <strong>{value ?? "—"}</strong>
                    <small>{sub}</small>
                  </article>
                ))}
              </div>
              <div className="overview-grid">
                <section className="panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Environment coverage</h2>
                      <p>Received evidence by environment</p>
                    </div>
                    <Badge tone="neutral">
                      {
                        data.sources.filter(
                          (s: RecordData) => s.health === "receiving",
                        ).length
                      }{" "}
                      receiving sources
                    </Badge>
                  </div>
                  <div className="coverage-grid">
                    {families.map((f) => {
                      const sources = data.sources.filter(
                        (s: RecordData) => family(s.source) === f,
                      );
                      const count = sources.reduce(
                        (n: number, s: RecordData) => n + (s.accepted || 0),
                        0,
                      );
                      const receiving = sources.some(
                        (s: RecordData) => s.health === "receiving",
                      );
                      return (
                        <button
                          key={f}
                          className="environment"
                          onClick={() => {
                            setPage("Findings");
                            setSearch(f);
                          }}
                        >
                          <span className={"environment-icon " + f}>
                            {f === "wazuh" ? (
                              <Server size={22} />
                            ) : f === "kubernetes" ? (
                              <Boxes size={22} />
                            ) : (
                              <Cloud size={22} />
                            )}
                          </span>
                          <strong>
                            {f === "wazuh"
                              ? "On-premises"
                              : f === "kubernetes"
                                ? "Kubernetes"
                                : f.toUpperCase()}
                          </strong>
                          <span
                            className={
                              "health " + (receiving ? "good-text" : "muted")
                            }
                          >
                            <span className="dot" />
                            {receiving ? "Receiving" : "No fresh evidence"}
                          </span>
                          <b>
                            {count}
                            <small>records</small>
                          </b>
                        </button>
                      );
                    })}
                  </div>
                  <div className="panel-foot">
                    <Activity size={14} /> Freshness reflects receipt in the
                    last 15 minutes. It does not establish asset security.
                  </div>
                </section>
                <section className="panel response-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Response safeguards</h2>
                      <p>Current workspace configuration</p>
                    </div>
                    <ShieldCheck size={20} />
                  </div>
                  <div className="safeguard">
                    <LockKeyhole size={17} />
                    <span>
                      Approval boundary
                      <small>Exact plan and separate principals</small>
                    </span>
                    <Badge>Policy v1.0</Badge>
                  </div>
                  <div className="safeguard">
                    <FileCheck2 size={17} />
                    <span>
                      Outcome verification
                      <small>Readback required for success</small>
                    </span>
                    <Badge>Per execution</Badge>
                  </div>
                  <div className="safeguard">
                    <GitBranch size={17} />
                    <span>
                      External AI<small>Advisory access only</small>
                    </span>
                    <Badge tone={overview.ai_enabled ? "warn" : "neutral"}>
                      {overview.ai_enabled ? "Enabled" : "Disabled"}
                    </Badge>
                  </div>
                  <button
                    className="text-button"
                    onClick={() => setPage("Automation")}
                  >
                    Inspect response records <ArrowRight size={14} />
                  </button>
                </section>
              </div>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Recent security evidence</h2>
                    <p>
                      Normalized records from your connected collection paths
                    </p>
                  </div>
                  <button
                    className="button subtle"
                    onClick={() => setPage("Findings")}
                  >
                    All findings <ArrowRight size={14} />
                  </button>
                </div>
                {findingsTable(data.events.slice(0, 6))}
              </section>
              <div className="lower-grid">
                <section className="panel">
                  <div className="panel-heading">
                    <h2>Incident activity</h2>
                    <button
                      className="text-button"
                      onClick={() => setPage("Incidents")}
                    >
                      View all <ArrowRight size={13} />
                    </button>
                  </div>
                  {data.incidents.slice(0, 4).map((i: RecordData) => (
                    <button
                      className="incident-row"
                      key={i.id}
                      onClick={() => void inspectIncident(i)}
                    >
                      <span className="incident-marker" />
                      <span>
                        <strong>{short(i.title, 65)}</strong>
                        <small>
                          {i.evidence_ids.length} evidence records ·{" "}
                          {i.environments.join(" / ")}
                        </small>
                      </span>
                      <Badge tone="danger">{i.risk}</Badge>
                    </button>
                  ))}
                  {!data.incidents.length && (
                    <Empty text="No detections have formed an incident." />
                  )}
                </section>
                <section className="panel">
                  <div className="panel-heading">
                    <h2>Response activity</h2>
                    <Badge>{data.actions.length} plans</Badge>
                  </div>
                  {actionsList(data.actions.slice(-3).reverse())}
                </section>
              </div>
            </>
          )}
          {page === "Findings" && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Consolidated findings</h2>
                  <p>
                    Showing up to 50 most recent records. Open a record for
                    provenance.
                  </p>
                </div>
                <label className="search">
                  <Search size={15} />
                  <input
                    aria-label="Search findings"
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                    placeholder="Search evidence, asset, source…"
                  />
                </label>
              </div>
              {findingsTable(events)}
            </section>
          )}
          {page === "Incidents" && (
            <section className="panel">
              <div className="panel-heading">
                <h2>Investigation queue</h2>
                <Badge>{data.incidents.length} incidents</Badge>
              </div>
              {data.incidents.map((i: RecordData) => (
                <button
                  className="incident-row large"
                  onClick={() => void inspectIncident(i)}
                  key={i.id}
                >
                  <span className="incident-icon">
                    <Layers3 size={19} />
                  </span>
                  <span>
                    <strong>{i.title}</strong>
                    <small>
                      {i.entity} · {i.evidence_ids.length} evidence records ·{" "}
                      {date(i.updated_at)}
                    </small>
                    <span className="chips">
                      {i.environments.map((f: string) => (
                        <Badge key={f}>{f}</Badge>
                      ))}
                      <Badge tone={i.synthetic ? "warn" : "neutral"}>
                        {i.synthetic ? "Synthetic" : "Provider input"}
                      </Badge>
                    </span>
                  </span>
                  <Badge tone="danger">Risk {i.risk}</Badge>
                  <ChevronRight size={17} />
                </button>
              ))}
              {!data.incidents.length && (
                <Empty text="No incidents to investigate." />
              )}
            </section>
          )}
          {page === "Assets" && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Observed asset inventory</h2>
                  <p>
                    Derived from the latest evidence page; collection coverage
                    may be incomplete.
                  </p>
                </div>
              </div>
              {Array.from(
                new Set(data.events.map((e: RecordData) => e.asset)),
              ).map((asset) => {
                const rows = data.events.filter(
                  (e: RecordData) => e.asset === asset,
                );
                return (
                  <div className="asset-row" key={String(asset)}>
                    <Server size={20} />
                    <div>
                      <strong>{String(asset)}</strong>
                      <small>
                        {Array.from(
                          new Set(
                            rows.map(
                              (e: RecordData) =>
                                e.identity || "Identity unavailable",
                            ),
                          ),
                        ).join(" · ")}
                      </small>
                    </div>
                    <Badge>{rows.length} records</Badge>
                    <button
                      className="button"
                      onClick={() => {
                        setPage("Findings");
                        setSearch(String(asset));
                      }}
                    >
                      View timeline <ArrowRight size={14} />
                    </button>
                  </div>
                );
              })}
            </section>
          )}
          {page === "Detections" && (
            <>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Detection-as-code</h2>
                    <p>Validated rules loaded from version-controlled YAML</p>
                  </div>
                  <button
                    className="primary"
                    disabled={busy || !allowed("analyst")}
                    onClick={() =>
                      void run(async () =>
                        setReplay(await api("/replay", "POST")),
                      )
                    }
                  >
                    <RefreshCw size={15} /> Replay detections
                  </button>
                </div>
                <div className="rule-grid">
                  {data.rules.map((r: RecordData) => (
                    <article key={r.id} className="rule-card">
                      <div>
                        <Code2 size={20} />
                        <Badge>v{r.version}</Badge>
                      </div>
                      <h3>{r.name}</h3>
                      <code>{r.id}</code>
                      <p>
                        {r.kind === "single"
                          ? "Single-event detection"
                          : "Time-window correlation"}{" "}
                        · {r.window_seconds}s window
                      </p>
                      <dl>
                        <dt>Minimum severity</dt>
                        <dd>{r.min_severity}</dd>
                        <dt>Minimum evidence / sources</dt>
                        <dd>
                          {r.min_events} / {r.min_sources}
                        </dd>
                      </dl>
                    </article>
                  ))}
                </div>
              </section>
              {replay && (
                <section className="panel">
                  <div className="panel-heading">
                    <h2>Replay evaluation</h2>
                    <Badge>{replay.events_evaluated} events evaluated</Badge>
                  </div>
                  <pre>{JSON.stringify(replay, null, 2)}</pre>
                </section>
              )}
            </>
          )}
          {(page === "Automation" || page === "Approvals") && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>
                    {page === "Approvals"
                      ? "Human approval queue"
                      : "Workflow executions"}
                  </h2>
                  <p>
                    {page === "Approvals"
                      ? "Review the exact plan. A different principal must execute it."
                      : "Open a plan to inspect execution, verification, and rollback history."}
                  </p>
                </div>
                <Badge>
                  {page === "Approvals" ? pending.length : data.actions.length}{" "}
                  plans
                </Badge>
              </div>
              {actionsList(page === "Approvals" ? pending : data.actions)}
            </section>
          )}
          {page === "Audit trail" && (
            <>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Audit integrity</h2>
                    <p>
                      Retain signed checkpoints outside this database to detect
                      truncation.
                    </p>
                  </div>
                  <button
                    className="button"
                    onClick={() =>
                      void run(async () =>
                        setCheckpoint(await api("/audit/checkpoint")),
                      )
                    }
                  >
                    <Fingerprint size={15} /> Verify audit chain
                  </button>
                </div>
                {checkpoint && (
                  <div className="checkpoint">
                    <Badge tone={checkpoint.valid ? "good" : "danger"}>
                      {checkpoint.valid
                        ? "Chain verified"
                        : "Integrity failure"}
                    </Badge>
                    <span>{checkpoint.records} records</span>
                    <code>{checkpoint.head}</code>
                  </div>
                )}
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>Operational trail</h2>
                  <span className="muted">Latest 100 records</span>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Sequence / time</th>
                        <th>Operation</th>
                        <th>Principal</th>
                        <th>Integrity signature</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.audit.map((a: RecordData) => (
                        <tr key={a.seq}>
                          <td>
                            #{a.seq}
                            <small>{date(a.at)}</small>
                          </td>
                          <td>
                            <button
                              className="text-button"
                              onClick={() =>
                                setSelected({
                                  ...a,
                                  kind: "audit",
                                  operation: a.kind,
                                })
                              }
                            >
                              {a.kind}
                            </button>
                          </td>
                          <td>{a.actor}</td>
                          <td>
                            <code>{a.signature.slice(0, 24)}…</code>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            </>
          )}
          {page === "Integrations" && (
            <>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Source diagnostics</h2>
                    <p>Receipt health is distinct from provider acceptance.</p>
                  </div>
                  <a
                    className="button"
                    target="_blank"
                    rel="noreferrer"
                    href="https://github.com/jayekwere/secopsmesh/blob/main/docs/CONNECTORS.md"
                  >
                    Connection guide <ArrowRight size={14} />
                  </a>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Integration</th>
                        <th>Receipt status</th>
                        <th>Records / duplicates</th>
                        <th>Last received</th>
                        <th>Validation status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.sources.map((s: RecordData) => (
                        <tr key={s.source}>
                          <td>
                            <span className="source-name">
                              <span
                                className={"source-dot " + family(s.source)}
                              />
                              {s.source}
                            </span>
                            <small>{s.mode || "No data received"}</small>
                          </td>
                          <td>
                            <Badge
                              tone={s.health === "receiving" ? "good" : "warn"}
                            >
                              {label(s.health)}
                            </Badge>
                          </td>
                          <td>
                            {s.accepted ?? 0} / {s.duplicates ?? 0}
                          </td>
                          <td>{date(s.last_received)}</td>
                          <td className="acceptance">{s.acceptance}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>Scoped response inventory</h2>
                  <Badge>{data.targets.length} configured</Badge>
                </div>
                {data.targets.map((t: RecordData) => (
                  <div className="asset-row" key={t.id}>
                    <LockKeyhole size={18} />
                    <div>
                      <strong>{t.id}</strong>
                      <small>
                        {t.kind} · {t.asset}
                      </small>
                    </div>
                    <Badge tone={t.enabled ? "warn" : "neutral"}>
                      {t.enabled ? "Explicitly enabled" : "Disabled"}
                    </Badge>
                  </div>
                ))}
              </section>
            </>
          )}
          <footer className="content-footer">
            <span>
              <Shield size={12} /> SecOpsMesh · Evidence-grounded operations
            </span>
            <span>
              Schema 1.0 · External AI{" "}
              {overview.ai_enabled ? "enabled" : "disabled"}
            </span>
          </footer>
        </main>
      </div>
      {selected && (
        <div className="drawer-backdrop" onClick={() => setSelected(null)}>
          <section
            className="drawer"
            role="dialog"
            aria-modal="true"
            aria-label="Evidence and action inspector"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="drawer-heading">
              <div className="eyebrow">
                {selected.kind === "action"
                  ? "ACTION PLAN"
                  : selected.kind === "incident"
                    ? "INCIDENT INVESTIGATION"
                    : "EVIDENCE INSPECTOR"}
              </div>
              <button
                className="icon-button"
                aria-label="Close inspector"
                onClick={() => setSelected(null)}
              >
                <X size={19} />
              </button>
            </div>
            {selected.kind === "event" && (
              <>
                <h2>{selected.title}</h2>
                <div className="chips">
                  <Badge tone="danger">Risk {selected.risk}</Badge>
                  <Badge>{selected.source}</Badge>
                  <Badge tone="warn">
                    {selected.synthetic ? "Synthetic" : "Provider input"}
                  </Badge>
                </div>
                <dl className="detail-list">
                  <dt>Evidence ID</dt>
                  <dd className="mono">{selected.id}</dd>
                  <dt>Observed</dt>
                  <dd>{date(selected.observed_at)}</dd>
                  <dt>Received</dt>
                  <dd>{date(selected.received_at)}</dd>
                  <dt>Asset</dt>
                  <dd>{selected.asset}</dd>
                  <dt>Identity</dt>
                  <dd>{selected.identity || "Unavailable"}</dd>
                  <dt>Confidence</dt>
                  <dd>{selected.confidence}</dd>
                  <dt>Quality indicators</dt>
                  <dd>
                    {selected.quality.join(", ") || "Required fields present"}
                  </dd>
                  <dt>MITRE techniques</dt>
                  <dd>
                    {selected.techniques.join(", ") ||
                      "No defensible mapping supplied"}
                  </dd>
                </dl>
                <h3>Redacted source evidence</h3>
                <pre>{JSON.stringify(selected.evidence, null, 2)}</pre>
              </>
            )}
            {selected.kind === "incident" && (
              <>
                <h2>{selected.title}</h2>
                <div className="chips">
                  <Badge tone="danger">Risk {selected.risk}</Badge>
                  <Badge>{selected.evidence_ids.length} evidence records</Badge>
                </div>
                <p className="muted">{selected.entity}</p>
                <div className="drawer-actions">
                  <button
                    className="primary"
                    disabled={busy || !allowed("analyst")}
                    onClick={() => void investigate()}
                  >
                    <Search size={15} /> Investigate evidence
                  </button>
                </div>
                <h3>Evidence timeline</h3>
                <div className="timeline">
                  {packet?.events.map((e: RecordData) => (
                    <div key={e.id}>
                      <span className="timeline-dot" />
                      <small>
                        {date(e.observed_at)} · {e.source}
                      </small>
                      <button
                        className="text-button"
                        onClick={() => setSelected({ kind: "event", ...e })}
                      >
                        {e.title}
                      </button>
                      <code>{e.id.slice(0, 20)}</code>
                    </div>
                  ))}
                </div>
                <h3>Investigation history</h3>
                {reports.length ? (
                  reports.map((r: RecordData) => (
                    <article className="report" key={r.id}>
                      <Badge>{r.mode}</Badge>
                      <p>{r.summary}</p>
                      <strong>Suggested next steps</strong>
                      <ul>
                        {r.next_steps.map((s: string, i: number) => (
                          <li key={i}>{s}</li>
                        ))}
                      </ul>
                      <strong>Evidence citations</strong>
                      {r.evidence_ids.map((id: string) => (
                        <code className="citation" key={id}>
                          {id}
                        </code>
                      ))}
                      {r.untrusted_instructions_detected && (
                        <Badge tone="warn">
                          Untrusted instructions detected in evidence
                        </Badge>
                      )}
                    </article>
                  ))
                ) : (
                  <p className="muted">No investigation report yet.</p>
                )}
                <h3>Propose a scoped response</h3>
                <p className="muted">
                  Every plan requires independent approval and a separate
                  executor.
                </p>
                {data.targets
                  .filter((t: RecordData) =>
                    packet?.events.some((e: RecordData) => e.asset === t.asset),
                  )
                  .map((t: RecordData) => (
                    <button
                      key={t.id}
                      className="button"
                      disabled={busy || !allowed("analyst") || !t.enabled}
                      onClick={() => void propose(t.id)}
                    >
                      Propose containment · {t.id} <ArrowRight size={14} />
                    </button>
                  ))}
              </>
            )}
            {selected.kind === "action" && (
              <>
                <h2>
                  {label(selected.plan.action)} · {selected.plan.target}
                </h2>
                <div className="chips">
                  <Badge tone={selected.state === "verified" ? "good" : "warn"}>
                    {label(selected.state)}
                  </Badge>
                  <Badge>{selected.plan.policy_version} policy</Badge>
                </div>
                <dl className="detail-list">
                  <dt>Requester</dt>
                  <dd>{selected.requester}</dd>
                  <dt>Approver</dt>
                  <dd>
                    {selected.approver || "Awaiting independent approval"}
                  </dd>
                  <dt>Approval expires</dt>
                  <dd>{date(selected.expires)}</dd>
                  <dt>Plan fingerprint</dt>
                  <dd className="mono">{selected.fingerprint}</dd>
                  <dt>Execution attempts</dt>
                  <dd>{selected.attempts}</dd>
                </dl>
                <h3>Exact plan for review</h3>
                <pre>{JSON.stringify(selected.plan, null, 2)}</pre>
                <div className="drawer-actions">
                  {selected.state === "pending" && (
                    <button
                      className="primary"
                      disabled={
                        busy ||
                        !allowed("approver") ||
                        me.name === selected.requester
                      }
                      onClick={() =>
                        void run(async () =>
                          setSelected({
                            kind: "action",
                            ...(await api(
                              "/actions/" + selected.id + "/approve",
                              "POST",
                              { fingerprint: selected.fingerprint },
                            )),
                          }),
                        )
                      }
                    >
                      <FileCheck2 size={16} /> Approve exact plan
                    </button>
                  )}
                  {[
                    "approved",
                    "ambiguous",
                    "verification_failed",
                    "executing",
                  ].includes(selected.state) && (
                    <button
                      className="primary"
                      disabled={busy || !allowed("executor")}
                      onClick={() =>
                        void run(async () =>
                          setSelected({
                            kind: "action",
                            ...(await api(
                              "/actions/" + selected.id + "/execute",
                              "POST",
                            )),
                          }),
                        )
                      }
                    >
                      <Workflow size={16} />
                      {selected.state === "approved"
                        ? "Execute approved plan"
                        : "Reconcile by readback"}
                    </button>
                  )}
                  {selected.state === "verified" &&
                    selected.plan.action === "contain" && (
                      <button
                        className="button"
                        disabled={busy || !allowed("analyst")}
                        onClick={() =>
                          void run(async () => {
                            const result = await api("/actions", "POST", {
                              incident_id: selected.incident_id,
                              target: selected.plan.target,
                              action: "rollback",
                              original_action_id: selected.id,
                            });
                            setSelected({ kind: "action", ...result });
                          })
                        }
                      >
                        Propose authorized rollback <GitBranch size={15} />
                      </button>
                    )}
                </div>
                <p className="muted">
                  The server rechecks role separation, expiry, plan integrity,
                  target inventory, and evidence before execution.
                </p>
                <h3>Outcome and verification history</h3>
                <pre>{JSON.stringify(selected.result, null, 2)}</pre>
              </>
            )}
            {selected.kind === "audit" && (
              <>
                <h2>{selected.operation}</h2>
                <pre>{JSON.stringify(selected, null, 2)}</pre>
              </>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
function canonicalSearch(e: RecordData) {
  return [e.title, e.asset, e.identity, e.source].join(" ").toLowerCase();
}
function FlaskIcon() {
  return <Terminal size={16} />;
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
