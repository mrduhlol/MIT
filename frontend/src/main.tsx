import React, { useEffect, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Shield,
  Activity,
  Layers,
  BarChart3,
  ScrollText,
  Play,
  StepForward,
  RotateCcw,
  Search,
  ArrowUpRight,
  ChevronRight,
  Check,
  X,
  LockKeyhole,
  Radio,
  Mail,
  Globe,
  Fingerprint,
  Sparkles,
  AlertTriangle,
  Server,
  Loader2,
  Plus,
} from "lucide-react";
import "./styles.css";
import AgentOverview from "./AgentOverview";
import Servers from "./Servers";
import Modal from "./Modal";
import { downloadLogs } from "./logExport";

type Evidence = { feature: string; category: string; explanation: string };
type Event = {
  id: string;
  timestamp: string;
  source: string;
  identity: string;
  host: string;
  ip: string;
  details: Record<string, unknown>;
  suspicious: boolean;
  confidence: number;
  evidence: Evidence[];
};
type Incident = {
  id: string;
  title: string;
  severity: string;
  confidence: number;
  status: string;
  summary: string;
  event_ids: string[];
  identities: string[];
  hosts: string[];
  categories: string[];
  first_seen: string;
  last_seen: string;
  priority: number;
};
type Action = {
  id: string;
  incident_id: string;
  kind: string;
  target: string;
  status: string;
  reason: string;
  verification?: string | Record<string, unknown>;
};
type Audit = {
  id: string;
  timestamp: string;
  actor: string;
  action: string;
  detail: unknown;
};
type Metrics = {
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
  mean_latency_ms: number;
  p95_latency_ms: number;
  samples: number;
  batch_latency_ms?: number;
  batch_size?: number;
  batch_latency_scope?: string;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  dataset: string;
  scope: string;
  model: string;
};
type Dashboard = {
  events: Event[];
  incidents: Incident[];
  actions: Action[];
  audit: Audit[];
  metrics: Metrics;
  sandbox: { isolated_hosts: string[]; revoked_identities: string[] };
  replay: { cursor: number; total: number };
  model: string;
};
type Investigation = {
  summary: string;
  evidence: { event_id: string; explanation: string }[];
  recommendations: Action[];
  limitations: string[];
};
const percent = (v: number) => `${((v || 0) * 100).toFixed(1)}%`;
const time = (v: string) =>
  new Date(v).toLocaleTimeString("en-GB", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZone: "UTC",
  });
const actionName = (a: Action) =>
  a.kind === "isolate_host" ? "Isolate host" : "Revoke sessions";
const display = (v: unknown) => (typeof v === "string" ? v : JSON.stringify(v));
function SourceIcon({ source }: { source: string }) {
  const Icon =
    source === "email" ? Mail : source === "auth" ? Fingerprint : Globe;
  return <Icon size={16} />;
}
function App() {
  const [data, setData] = useState<Dashboard | null>(null),
    [page, setPage] = useState("Agent overview"),
    [addServerRequest, setAddServerRequest] = useState(0),
    [selected, setSelected] = useState(""),
    [search, setSearch] = useState(""),
    [filter, setFilter] = useState("all"),
    [severityFilter, setSeverityFilter] = useState("all"),
    [frozenEvents, setFrozenEvents] = useState<Event[] | null>(null),
    [busy, setBusy] = useState(""),
    [error, setError] = useState(""),
    [notice, setNotice] = useState("");
  const [investigation, setInvestigation] = useState<
      Record<string, Investigation>
    >({}),
    [modal, setModal] = useState<{
      action: Action;
      decision: "approve" | "reject";
    } | null>(null),
    [actor, setActor] = useState("Demo analyst"),
    [reason, setReason] = useState(""),
    [confirmed, setConfirmed] = useState(false),
    [reset, setReset] = useState(false);
  const token = useRef("");
  async function request(path: string, body?: unknown) {
    const res = await fetch("/api" + path, {
      headers: {
        "Content-Type": "application/json",
        ...(token.current ? { "X-SOC-Token": token.current } : {}),
      },
      ...(body !== undefined
        ? { method: "POST", body: JSON.stringify(body) }
        : {}),
    });
    if (!res.ok) {
      const e = await res.json().catch(() => ({ detail: "Request failed" }));
      throw new Error(
        typeof e.detail === "string" ? e.detail : JSON.stringify(e.detail),
      );
    }
    return res.json();
  }
  async function refresh() {
    const d = await request("/dashboard");
    setData(d);
  }
  useEffect(() => {
    let active = true;
    async function boot() {
      try {
        token.current = (await request("/session")).token;
        const d = await request("/dashboard");
        if (active) {
          setData(d);
          setError("");
        }
      } catch (e) {
        if (active) setError((e as Error).message);
      }
    }
    boot();
    const timer = setInterval(() => {
      if (active) refresh().catch((e) => setError(e.message));
    }, 3000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, []);
  useEffect(() => {
    if (data && !data.incidents.some((i) => i.id === selected))
      setSelected(data.incidents[0]?.id || "");
  }, [data, selected]);
  async function run(key: string, work: () => Promise<void>) {
    setBusy(key);
    setError("");
    setNotice("");
    try {
      await work();
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  function openDecision(action: Action, decision: "approve" | "reject") {
    setModal({ action, decision });
    setReason("");
    setConfirmed(false);
  }
  const incident = data?.incidents.find((i) => i.id === selected),
    current = selected ? investigation[selected] : undefined;
  const incidentEvents =
    data?.events
      .filter((e) => incident?.event_ids.includes(e.id))
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp)) || [];
  const pending = data?.actions.filter((a) => a.status === "pending") || [];
  const actions = data?.actions.filter((a) => a.incident_id === selected) || [];
  const eventSeverity = (event: Event) =>
    event.suspicious
      ? data?.incidents.find((i) => i.event_ids.includes(event.id))?.severity ||
        "medium"
      : "normal";
  const filteredEvents =
    (frozenEvents ?? data?.events)?.filter(
      (e) =>
        (filter === "all" ||
          (filter === "suspicious" ? e.suspicious : e.source === filter)) &&
        (severityFilter === "all" || eventSeverity(e) === severityFilter) &&
        JSON.stringify(e).toLowerCase().includes(search.toLowerCase()),
    ) || [];
  const nav = [
    { name: "Agent overview", icon: Shield },
    { name: "Servers", icon: Server },
    { name: "Operations", icon: Layers },
    { name: "Event stream", icon: Activity },
    { name: "Evaluation", icon: BarChart3 },
    { name: "Audit & sandbox", icon: ScrollText },
  ];
  return (
    <div className="app-shell">
      <aside className="sidebar">
        <a
          href="#"
          className="brand"
          aria-label="AI vs AI home"
          onClick={(e) => {
            e.preventDefault();
            setPage("Agent overview");
          }}
        >
          <div className="brand-mark">
            <Shield size={25} />
          </div>
          <div>
            AI <span>vs</span> AI<small>DEFENSE OPERATIONS</small>
          </div>
        </a>
        <div className="workspace">
          <span className="workspace-icon">
            <Server size={17} />
          </span>
          <div>
            Challenge workspace<small>Local environment</small>
          </div>
          <ChevronRight size={14} />
        </div>
        <div className="nav-label">WORKSPACE</div>
        <nav>
          {nav.map((n) => (
            <button
              key={n.name}
              className={page === n.name ? "nav-item active" : "nav-item"}
              onClick={() => {
                if (n.name === "Servers") setAddServerRequest(0);
                setPage(n.name);
                setSearch("");
              }}
            >
              <n.icon size={19} />
              <span>{n.name}</span>
              {n.name === "Operations" && data && (
                <b>{data.incidents.length}</b>
              )}
            </button>
          ))}
        </nav>
        <div className="sidebar-foot">
          <div className="safe-label">
            <LockKeyhole size={16} /> Isolated by design
          </div>
          <p>
            Fixtures and authorized data sources.
            <br />
            Every response needs your approval.
          </p>
          <div className="analyst">
            <span>DA</span>
            <div>
              Demo analyst<small>Human in the loop</small>
            </div>
            <span className="online-dot" />
          </div>
        </div>
      </aside>
      <main>
        <header className="topbar">
          <div>
            <span className="breadcrumb">Workspace</span>
            <ChevronRight size={13} />
            <strong>{page}</strong>
          </div>
          <div className="environment">
            <span className="online-dot" /> LOCAL CONTROL PLANE
            <span className="divider" />
            UTC
          </div>
        </header>
        <div className="main-content">
          <section className="page-heading">
            <div>
              <div className="eyebrow">AUTONOMOUS CYBER DEFENSE CHALLENGE</div>
              <h1>
                {page === "Agent overview"
                  ? "ATLAS command center"
                  : page === "Servers"
                    ? "Connected data sources"
                    : page === "Operations"
                      ? "Incident investigation"
                      : page === "Event stream"
                        ? "Live event stream"
                        : page === "Evaluation"
                          ? "Detection performance"
                          : "Response accountability"}
              </h1>
              <p>
                {page === "Agent overview"
                  ? "Monitor the signals. Schedule safe patrols. Investigate what matters."
                  : page === "Servers"
                    ? "Connect website APIs and Linux agents, manage permissions, and investigate their security signals."
                    : page === "Operations"
                      ? "Connect the evidence. Understand the attack. Stay in control."
                      : page === "Event stream"
                        ? "Email, authentication, and network events from fixtures, enrolled agents, and authorized website APIs."
                        : page === "Evaluation"
                          ? "Measured results from a labeled synthetic holdout dataset."
                          : "Every recommendation, decision, and simulated state change is traceable."}
              </p>
            </div>
            <div className="heading-actions">
              <button
                className="button primary"
                disabled={!data}
                onClick={() => {
                  setPage("Servers");
                  setAddServerRequest((v) => v + 1);
                }}
              >
                <Plus size={15} />
                Add Server
              </button>
              <button
                className="button subtle"
                disabled={!!busy || !data}
                onClick={() => setReset(true)}
                title="Reset simulation"
              >
                <RotateCcw size={15} />
                Reset
              </button>
              <button
                className="button subtle"
                disabled={
                  !!busy || !data || data.replay.cursor >= data.replay.total
                }
                onClick={() =>
                  run("step", async () => {
                    await request("/replay", { mode: "step" });
                  })
                }
              >
                <StepForward size={15} />
                Next event
              </button>
              <button
                className="button primary"
                disabled={
                  !!busy || !data || data.replay.cursor >= data.replay.total
                }
                onClick={() =>
                  run("replay", async () => {
                    await request("/replay", { mode: "all" });
                    setNotice(
                      "Attack replay complete. Review the correlated incidents below.",
                    );
                  })
                }
              >
                <Play size={15} />
                Run replay
              </button>
            </div>
          </section>
          {error && (
            <div role="alert" className="banner error">
              <AlertTriangle size={18} />
              <span>{error}</span>
              <button
                onClick={() => {
                  setError("");
                  request("/session")
                    .then((s) => {
                      token.current = s.token;
                      return refresh();
                    })
                    .catch((e) => setError(e.message));
                }}
              >
                Retry
              </button>
            </div>
          )}
          {notice && (
            <div role="status" className="banner success">
              <Check size={17} />
              {notice}
            </div>
          )}
          {!data ? (
            <div className="loading">
              <Loader2 className="spin" />
              Connecting to the defense engine…
              <small>Start the FastAPI backend on port 8000.</small>
            </div>
          ) : (
            <>
              <div className="metric-strip">
                <Metric
                  label="Active campaigns"
                  value={String(
                    data.incidents.filter((i) => i.status !== "contained")
                      .length,
                  )}
                  icon={<Layers size={17} />}
                  note={`${data.incidents.filter((i) => i.severity === "critical").length} critical priority`}
                  tone="red"
                />
                <Metric
                  label="Events analyzed"
                  value={String(data.events.length)}
                  icon={<Activity size={17} />}
                  note={`${data.events.filter((e) => e.suspicious).length} flagged for investigation`}
                />
                <Metric
                  label="Awaiting approval"
                  value={String(pending.length)}
                  icon={<LockKeyhole size={17} />}
                  note="No action executes automatically"
                  tone="amber"
                />
                <Metric
                  label="Detection F1"
                  value={percent(data.metrics.f1)}
                  icon={<BarChart3 size={17} />}
                  note={`${data.metrics.samples} synthetic holdout events`}
                  tone="teal"
                />
              </div>
              <div className="replay-bar">
                <div>
                  <span className="live-indicator" />
                  <strong>
                    Fixture replay{" "}
                    {data.replay.cursor === data.replay.total
                      ? "loaded"
                      : "in progress"}
                  </strong>
                  <span>
                    {data.replay.cursor} / {data.replay.total} events
                  </span>
                </div>
                <div className="replay-track">
                  <span
                    style={{
                      width: `${data.replay.total ? (data.replay.cursor / data.replay.total) * 100 : 0}%`,
                    }}
                  />
                </div>
                <small>
                  Refreshing every 3 seconds · API event collection is manual
                </small>
              </div>
              {page === "Servers" && (
                <Servers
                  request={request}
                  addRequest={addServerRequest}
                  reviewIncident={(id) => {
                    setSelected(id);
                    setPage("Operations");
                  }}
                />
              )}
              {page === "Agent overview" && (
                <AgentOverview
                  request={request}
                  onChange={refresh}
                  review={() => setPage("Operations")}
                />
              )}
              {page === "Operations" && (
                <>
                  <div className="operations-grid">
                    <section className="panel incident-panel">
                      <div className="panel-heading">
                        <div>
                          <h2>
                            Incident queue{" "}
                            <span className="count">
                              {data.incidents.length}
                            </span>
                          </h2>
                          <p>Correlated and prioritized</p>
                        </div>
                        <Layers size={17} />
                      </div>
                      <div className="incident-list">
                        {data.incidents.length === 0 ? (
                          <Empty
                            title="Ready for the first signal"
                            text="Use Next event or Run replay to analyze the synthetic attack."
                          />
                        ) : (
                          data.incidents.map((i, index) => (
                            <button
                              key={i.id}
                              className={`incident-card ${i.id === selected ? "selected" : ""}`}
                              onClick={() => setSelected(i.id)}
                            >
                              <div className="incident-top">
                                <span className={`badge ${i.severity}`}>
                                  {i.severity}
                                </span>
                                <span className="incident-number">
                                  INC-{String(index + 1).padStart(3, "0")}
                                </span>
                                <ChevronRight size={15} />
                              </div>
                              <h3>{i.title}</h3>
                              <div className="incident-identity">
                                <Fingerprint size={13} />
                                {i.identities.join(", ")}
                              </div>
                              <div className="incident-meta">
                                <span>{i.event_ids.length} linked events</span>
                                <span>{percent(i.confidence)} signal</span>
                              </div>
                              <div className="incident-bottom">
                                <span>{i.status}</span>
                                <span>{time(i.first_seen)} UTC</span>
                              </div>
                            </button>
                          ))
                        )}
                      </div>
                      <div className="queue-note">
                        <Shield size={14} />
                        Ranked by impact and attack progression
                      </div>
                    </section>
                    <section className="panel investigation-panel">
                      {incident ? (
                        <>
                          <div className="panel-heading investigation-heading">
                            <div>
                              <div className="detail-kicker">
                                <span className={`badge ${incident.severity}`}>
                                  {incident.severity}
                                </span>
                                <span>CAMPAIGN INVESTIGATION</span>
                              </div>
                              <h2>{incident.title}</h2>
                              <p>
                                {incident.hosts.join(" · ")}{" "}
                                <span className="muted">/</span>{" "}
                                {incident.categories.length} attack categories
                              </p>
                            </div>
                            <button
                              className="button primary"
                              disabled={!!busy}
                              onClick={() =>
                                run("investigate", async () => {
                                  const r = await request(
                                    `/incidents/${selected}/investigate`,
                                    {},
                                  );
                                  setInvestigation((v) => ({
                                    ...v,
                                    [selected]: r,
                                  }));
                                  setNotice(
                                    "Investigation complete. Review the proposed actions before approving.",
                                  );
                                })
                              }
                            >
                              {busy === "investigate" ? (
                                <Loader2 size={16} className="spin" />
                              ) : (
                                <Sparkles size={16} />
                              )}
                              Investigate incident
                            </button>
                          </div>
                          <div className="investigation-body">
                            <div className="analysis-box">
                              <div className="section-label">
                                <Sparkles size={15} />
                                DEFENSE ENGINE ASSESSMENT
                                <span className="model-tag">LOCAL ML</span>
                              </div>
                              <p>{current?.summary || incident.summary}</p>
                              <div className="category-tags">
                                {incident.categories.map((c) => (
                                  <span key={c}>{c}</span>
                                ))}
                              </div>
                            </div>
                            <div className="timeline-heading">
                              <h3>Attack timeline</h3>
                              <span>
                                {incidentEvents.length} correlated events
                              </span>
                            </div>
                            <ol className="timeline">
                              {incidentEvents.map((e, index) => (
                                <li key={e.id}>
                                  <div
                                    className={`timeline-node ${e.suspicious ? "flagged" : ""}`}
                                  >
                                    <SourceIcon source={e.source} />
                                  </div>
                                  <div className="timeline-content">
                                    <div className="timeline-title">
                                      <strong>
                                        {e.evidence[0]?.category ||
                                          "Supporting activity"}
                                      </strong>
                                      <time>{time(e.timestamp)}</time>
                                    </div>
                                    <p>
                                      {e.evidence
                                        .map((v) => v.explanation)
                                        .join(" ") ||
                                        `Normal ${e.source} activity linked by shared identity or host.`}
                                    </p>
                                    <div className="evidence-meta">
                                      <span>{e.id}</span>
                                      <span>{e.source}</span>
                                      <span>{e.host}</span>
                                    </div>
                                    <details>
                                      <summary>
                                        View source evidence{" "}
                                        <ChevronRight size={12} />
                                      </summary>
                                      <pre>
                                        {JSON.stringify(e.details, null, 2)}
                                      </pre>
                                    </details>
                                  </div>
                                </li>
                              ))}
                            </ol>
                            {current && (
                              <div className="limitations">
                                <strong>Analyst considerations</strong>
                                {current.limitations.map((l, i) => (
                                  <p key={i}>{l}</p>
                                ))}
                              </div>
                            )}
                          </div>
                        </>
                      ) : (
                        <Empty
                          title="No incident selected"
                          text="Detected campaigns will appear here with their supporting evidence."
                        />
                      )}
                    </section>
                  </div>
                  <section className="panel response-panel">
                    <div className="panel-heading">
                      <div>
                        <h2>
                          <LockKeyhole size={18} />
                          Human approval required{" "}
                          <span className="count">
                            {
                              actions.filter((a) => a.status === "pending")
                                .length
                            }
                          </span>
                        </h2>
                        <p>
                          Recommended responses for the selected incident. Each
                          action is simulated independently.
                        </p>
                      </div>
                      <span className="safe-pill">SANDBOX ONLY</span>
                    </div>
                    {actions.length === 0 ? (
                      <div className="response-empty">
                        <Shield size={22} />
                        <div>
                          <strong>No responses proposed yet</strong>
                          <p>
                            Investigate an incident to generate evidence-backed
                            recommendations.
                          </p>
                        </div>
                      </div>
                    ) : (
                      <div className="action-list">
                        {actions.map((a) => (
                          <div className="action-row" key={a.id}>
                            <div className="action-icon">
                              <Shield size={18} />
                            </div>
                            <div className="action-description">
                              <h3>
                                {actionName(a)} <code>{a.target}</code>
                              </h3>
                              <p>{a.reason}</p>
                              {!!a.verification && (
                                <small className="verification">
                                  <Check size={13} />
                                  {display(a.verification)}
                                </small>
                              )}
                            </div>
                            {a.status === "pending" ? (
                              <div className="action-buttons">
                                <button
                                  className="button subtle"
                                  disabled={!!busy}
                                  onClick={() => openDecision(a, "reject")}
                                >
                                  <X size={15} />
                                  Reject
                                </button>
                                <button
                                  className="button approve"
                                  disabled={!!busy}
                                  onClick={() => openDecision(a, "approve")}
                                >
                                  <Check size={15} />
                                  Approve
                                </button>
                              </div>
                            ) : (
                              <span
                                className={`badge ${a.status === "approved" ? "verified" : "neutral"}`}
                              >
                                {a.status === "approved"
                                  ? "Verified · approved"
                                  : a.status}
                              </span>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </section>
                  <section className="panel feed-preview">
                    <div className="panel-heading">
                      <h2>
                        <Radio size={17} />
                        Latest telemetry
                      </h2>
                      <button
                        className="text-button"
                        onClick={() => setPage("Event stream")}
                      >
                        View all events <ArrowUpRight size={15} />
                      </button>
                    </div>
                    <EventTable events={data.events.slice(-4).reverse()} />
                  </section>
                </>
              )}
              {page === "Event stream" && (
                <section className="panel">
                  <div className="panel-heading">
                    <h2>
                      Telemetry explorer{" "}
                      <span className="count">{filteredEvents.length}</span>
                    </h2>
                    <div className="table-controls">
                      <label className="search">
                        <Search size={16} />
                        <input
                          aria-label="Search events"
                          placeholder="Search identity, host, evidence…"
                          value={search}
                          onChange={(e) => setSearch(e.target.value)}
                        />
                      </label>
                      <select
                        aria-label="Filter events"
                        value={filter}
                        onChange={(e) => setFilter(e.target.value)}
                      >
                        <option value="all">All events</option>
                        <option value="suspicious">Suspicious only</option>
                        <option value="email">Email</option>
                        <option value="auth">Authentication</option>
                        <option value="network">Network</option>
                      </select>
                      <select
                        aria-label="Filter severity"
                        value={severityFilter}
                        onChange={(e) => setSeverityFilter(e.target.value)}
                      >
                        <option value="all">All severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="normal">Normal</option>
                      </select>
                    </div>
                  </div>
                  <div className="log-toolbar">
                    <span>
                      <span
                        className={`online-dot ${frozenEvents ? "paused-dot" : ""}`}
                      />
                      {frozenEvents
                        ? "Display paused · snapshot retained"
                        : "Live display · refreshes every 3 seconds"}
                    </span>
                    <div>
                      <button
                        className="button subtle"
                        onClick={() =>
                          setFrozenEvents(
                            frozenEvents ? null : [...data.events],
                          )
                        }
                      >
                        {frozenEvents ? "Resume live feed" : "Pause live feed"}
                      </button>
                      <button
                        className="button subtle"
                        onClick={() => downloadLogs(filteredEvents, "json")}
                      >
                        Download JSON
                      </button>
                      <button
                        className="button subtle"
                        onClick={() => downloadLogs(filteredEvents, "csv")}
                      >
                        Download CSV
                      </button>
                    </div>
                  </div>
                  <EventTable events={[...filteredEvents].reverse()} expanded />
                  {filteredEvents.length === 0 && (
                    <Empty
                      title="No matching events"
                      text="Change the filter, search, or replay additional events."
                    />
                  )}
                </section>
              )}
              {page === "Evaluation" && (
                <div className="evaluation-grid">
                  <section className="panel">
                    <div className="panel-heading">
                      <div>
                        <h2>Classifier quality</h2>
                        <p>
                          {data.metrics.dataset} · {data.metrics.samples}{" "}
                          samples
                        </p>
                      </div>
                      <button
                        className="button subtle"
                        disabled={!!busy}
                        onClick={() =>
                          run("evaluate", async () => {
                            await request("/evaluate", {});
                            setNotice(
                              "Evaluation rerun on the labeled synthetic holdout.",
                            );
                          })
                        }
                      >
                        <RotateCcw size={15} />
                        Run evaluation
                      </button>
                    </div>
                    <div className="quality-bars">
                      {[
                        ["Precision", data.metrics.precision],
                        ["Recall", data.metrics.recall],
                        ["F1 score", data.metrics.f1],
                        [
                          "False-positive rate",
                          data.metrics.false_positive_rate,
                        ],
                      ].map(([label, value]) => (
                        <div className="quality-row" key={String(label)}>
                          <div>
                            <span>{label}</span>
                            <strong>{percent(Number(value))}</strong>
                          </div>
                          <div className="quality-track">
                            <span
                              className={
                                label === "False-positive rate" ? "warning" : ""
                              }
                              style={{ width: `${Number(value) * 100}%` }}
                            />
                          </div>
                        </div>
                      ))}
                    </div>
                    <div className="evaluation-note">
                      <AlertTriangle size={17} />
                      <p>
                        {data.metrics.scope} Confidence values are uncalibrated
                        model probabilities. Synthetic test results do not
                        establish production reliability.
                      </p>
                    </div>
                  </section>
                  <section className="panel">
                    <div className="panel-heading">
                      <h2>Confusion matrix</h2>
                      <span className="muted">Actual × predicted</span>
                    </div>
                    <div className="matrix">
                      <div>
                        <small>TRUE POSITIVES</small>
                        <strong>{data.metrics.tp}</strong>
                        <span>Attacks detected</span>
                      </div>
                      <div className="mistake">
                        <small>FALSE POSITIVES</small>
                        <strong>{data.metrics.fp}</strong>
                        <span>Benign events flagged</span>
                      </div>
                      <div className="mistake">
                        <small>FALSE NEGATIVES</small>
                        <strong>{data.metrics.fn}</strong>
                        <span>Attacks missed</span>
                      </div>
                      <div>
                        <small>TRUE NEGATIVES</small>
                        <strong>{data.metrics.tn}</strong>
                        <span>Benign events cleared</span>
                      </div>
                    </div>
                    <div className="latency">
                      <div>
                        <small>Mean classifier latency</small>
                        <strong>
                          {data.metrics.mean_latency_ms.toFixed(3)}{" "}
                          <span>ms</span>
                        </strong>
                      </div>
                      <div>
                        <small>p95 classifier latency</small>
                        <strong>
                          {data.metrics.p95_latency_ms.toFixed(3)}{" "}
                          <span>ms</span>
                        </strong>
                      </div>
                    </div>
                  </section>
                  <section className="panel model-info">
                    {data.metrics.batch_latency_ms !== undefined && (
                      <div className="panel-heading">
                        <h2>Batch pipeline latency</h2>
                        <span>
                          {data.metrics.batch_latency_ms.toFixed(2)} ms ·{" "}
                          {data.metrics.batch_size} events
                        </span>
                      </div>
                    )}
                    {data.metrics.batch_latency_scope && (
                      <p>{data.metrics.batch_latency_scope}</p>
                    )}
                    <div className="panel-heading">
                      <h2>
                        <Sparkles size={18} />
                        Transparent by design
                      </h2>
                    </div>
                    <p>
                      <strong>{data.metrics.model || data.model}</strong> learns
                      from separate synthetic training fixtures. Evidence
                      features cover credential lures, authentication anomalies,
                      suspicious network traffic, prompt overrides, and
                      obfuscation.
                    </p>
                    <p>
                      The engine cannot reliably determine whether an email was
                      AI-generated. It flags observable risk indicators,
                      explains them, and leaves containment decisions to you.
                    </p>
                  </section>
                </div>
              )}
              {page === "Audit & sandbox" && (
                <>
                  <section className="panel sandbox-panel">
                    <div className="panel-heading">
                      <div>
                        <h2>
                          <LockKeyhole size={18} />
                          Isolated response state
                        </h2>
                        <p>
                          SQLite simulation only. No network, operating system,
                          or account changes.
                        </p>
                      </div>
                      <span className="safe-pill">NO REAL CONTAINMENT</span>
                    </div>
                    <div className="sandbox-columns">
                      <div>
                        <h3>Isolated hosts</h3>
                        {data.sandbox.isolated_hosts.length ? (
                          data.sandbox.isolated_hosts.map((h) => (
                            <p className="state-item" key={h}>
                              <Check size={15} />
                              <code>{h}</code>
                            </p>
                          ))
                        ) : (
                          <p>No hosts isolated.</p>
                        )}
                      </div>
                      <div>
                        <h3>Revoked identities</h3>
                        {data.sandbox.revoked_identities.length ? (
                          data.sandbox.revoked_identities.map((h) => (
                            <p className="state-item" key={h}>
                              <Check size={15} />
                              <code>{h}</code>
                            </p>
                          ))
                        ) : (
                          <p>No sessions revoked.</p>
                        )}
                      </div>
                    </div>
                  </section>
                  <section className="panel">
                    <div className="panel-heading">
                      <h2>
                        Audit trail{" "}
                        <span className="count">{data.audit.length}</span>
                      </h2>
                      <span className="muted">Most recent first</span>
                    </div>
                    <div className="table-wrap">
                      <table>
                        <thead>
                          <tr>
                            <th>Time · UTC</th>
                            <th>Actor</th>
                            <th>Operation</th>
                            <th>Detail</th>
                          </tr>
                        </thead>
                        <tbody>
                          {data.audit.map((a) => (
                            <tr key={a.id}>
                              <td className="mono">{time(a.timestamp)}</td>
                              <td>{a.actor}</td>
                              <td>
                                <span className="audit-operation">
                                  {a.action}
                                </span>
                              </td>
                              <td className="audit-detail">
                                {display(a.detail)}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {!data.audit.length && (
                      <Empty
                        title="Audit trail is empty"
                        text="Replay events or investigate an incident to record activity."
                      />
                    )}
                  </section>
                </>
              )}
              <footer>
                <span>
                  <Shield size={13} />
                  AI vs AI · Autonomous Cyber Defense Challenge
                </span>
                <span>
                  Local ML · Explicit data provenance · Human-authorized
                  response
                </span>
              </footer>
            </>
          )}
        </div>
      </main>
      <Modal
        open={!!modal}
        onDismiss={() => setModal(null)}
        labelledBy="decision-title"
        initialFocus="input"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!modal) return;
            run("decision", async () => {
              await request(`/actions/${modal.action.id}/decision`, {
                decision: modal.decision,
                confirmed: modal.decision === "approve" ? confirmed : false,
                actor,
                reason,
              });
              setModal(null);
              setNotice(
                modal.decision === "approve"
                  ? "Approved response executed and verified in the isolated sandbox."
                  : "Response rejected. No containment action was executed.",
              );
            });
          }}
        >
          <div className="dialog-heading">
            <span className="dialog-icon">
              <LockKeyhole size={24} />
            </span>
            <button
              type="button"
              aria-label="Close decision"
              onClick={() => setModal(null)}
            >
              <X size={20} />
            </button>
          </div>
          <div className="eyebrow">HUMAN DECISION</div>
          <h2 id="decision-title">
            {modal?.decision === "approve"
              ? "Approve simulated response"
              : "Reject proposed response"}
          </h2>
          <p>
            {modal && actionName(modal.action)} for{" "}
            <strong>{modal?.action.target}</strong>.{" "}
            {modal?.decision === "approve"
              ? "This changes only the local sandbox state."
              : "The action will not execute."}
          </p>
          <label>
            Analyst name
            <input
              required
              minLength={2}
              maxLength={80}
              value={actor}
              onChange={(e) => setActor(e.target.value)}
            />
          </label>
          <label>
            Decision reason
            <textarea
              required
              minLength={3}
              maxLength={500}
              placeholder="Explain why this response is appropriate…"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
          </label>
          {modal?.decision === "approve" && (
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(e) => setConfirmed(e.target.checked)}
              />
              I explicitly approve this individual simulated containment action.
            </label>
          )}
          {error && (
            <div role="alert" className="banner error">
              {error}
            </div>
          )}
          <div className="dialog-actions">
            <button
              className="button subtle"
              type="button"
              onClick={() => setModal(null)}
            >
              Cancel
            </button>
            <button
              className={`button ${modal?.decision === "approve" ? "approve" : "primary"}`}
              type="submit"
              disabled={!!busy || (modal?.decision === "approve" && !confirmed)}
            >
              {busy === "decision"
                ? "Saving…"
                : modal?.decision === "approve"
                  ? "Confirm approval"
                  : "Confirm rejection"}
            </button>
          </div>
        </form>
      </Modal>
      <Modal
        open={reset}
        onDismiss={() => setReset(false)}
        labelledBy="reset-title"
        dismissOnBackdrop={!busy}
      >
        <div className="dialog-heading">
          <span className="dialog-icon">
            <RotateCcw size={24} />
          </span>
          <button
            type="button"
            aria-label="Close reset confirmation"
            onClick={() => setReset(false)}
          >
            <X size={20} />
          </button>
        </div>
        <h2 id="reset-title">Restart the simulation?</h2>
        <p>
          This clears fixture replay events and their simulated responses.
          Enrolled-server telemetry, incidents, approvals, and patrol history
          are preserved. You can replay the fixture attack from its first event.
        </p>
        <div className="dialog-actions">
          <button className="button subtle" onClick={() => setReset(false)}>
            Cancel
          </button>
          <button
            className="button primary"
            disabled={!!busy}
            onClick={() =>
              run("reset", async () => {
                await request("/reset", {});
                setInvestigation({});
                setSelected("");
                setReset(false);
                setNotice(
                  "Simulation reset. Start with Next event or Run replay.",
                );
              })
            }
          >
            Reset simulation
          </button>
        </div>
      </Modal>
    </div>
  );
}
function Metric({
  label,
  value,
  note,
  icon,
  tone = "",
}: {
  label: string;
  value: string;
  note: string;
  icon: React.ReactNode;
  tone?: string;
}) {
  return (
    <div className={`metric ${tone}`}>
      <div className="metric-label">
        {label}
        {icon}
      </div>
      <div className="metric-value">{value}</div>
      <small>{note}</small>
    </div>
  );
}
function Empty({ title, text }: { title: string; text: string }) {
  return (
    <div className="empty">
      <Shield size={30} />
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}
function EventTable({
  events,
  expanded = false,
}: {
  events: Event[];
  expanded?: boolean;
}) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Time · UTC</th>
            <th>Source</th>
            <th>Identity / host</th>
            <th>Detection</th>
            <th>Signal</th>
            {expanded && <th>Evidence</th>}
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <tr key={e.id}>
              <td className="mono">
                {time(e.timestamp)}
                <small>{e.id}</small>
              </td>
              <td>
                <span className="table-source">
                  <SourceIcon source={e.source} />
                  {e.source}
                </span>
              </td>
              <td>
                {e.identity}
                <small>{e.host}</small>
              </td>
              <td>
                <span className={`badge ${e.suspicious ? "high" : "neutral"}`}>
                  {e.suspicious
                    ? e.evidence[0]?.category || "Suspicious"
                    : "Normal activity"}
                </span>
              </td>
              <td className="mono">{percent(e.confidence)}</td>
              {expanded && (
                <td>
                  <details>
                    <summary>Inspect</summary>
                    <pre>
                      {JSON.stringify(
                        { details: e.details, evidence: e.evidence },
                        null,
                        2,
                      )}
                    </pre>
                  </details>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
