import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  Clock3,
  Globe,
  Pause,
  Play,
  Radio,
  ShieldCheck,
  Timer,
  Loader2,
} from "lucide-react";

type Run = {
  id: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  events_analyzed: number;
  incidents_found: number;
  suspicious_events: number;
  trigger: string;
  status: string;
  error?: string;
};
type Agent = {
  name: string;
  mode: string;
  site: { name: string; environment: string; collector_status: string };
  status: string;
  enabled: boolean;
  interval_seconds: number;
  last_run_at: string | null;
  next_run_at: string | null;
  runs: Run[];
  coverage: {
    source: string;
    label: string;
    status: string;
    events: number;
    last_event_at: string | null;
  }[];
  uptime_seconds: number;
};
type Point = {
  timestamp: string;
  events: number;
  suspicious: number;
  auth_failures: number;
  bytes_out: number;
};
type Analytics = {
  window_minutes: number;
  anchor_at: string | null;
  start_at: string | null;
  bucket_seconds: number;
  series: Point[];
  sources: { source: string; total: number; suspicious: number }[];
  categories: { category: string; count: number }[];
  hosts: {
    host: string;
    identities: string[];
    events: number;
    suspicious: number;
    last_seen: string;
    status: string;
  }[];
  totals: {
    events: number;
    suspicious: number;
    bytes_out: number;
    auth_failures: number;
  };
  scope: string;
};
type Props = {
  request: (path: string, body?: unknown) => Promise<any>;
  review: () => void;
  onChange: () => Promise<void>;
};
const stamp = (value: string | null) =>
  value
    ? new Date(value).toLocaleTimeString("en-GB", {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        timeZone: "UTC",
      })
    : "Not yet";
const bytes = (value: number) =>
  value >= 1e6
    ? `${(value / 1e6).toFixed(1)} MB`
    : `${(value / 1e3).toFixed(1)} kB`;

export default function AgentOverview({ request, review, onChange }: Props) {
  const [agent, setAgent] = useState<Agent | null>(null);
  const [analytics, setAnalytics] = useState<Analytics | null>(null);
  const [windowMinutes, setWindowMinutes] = useState(15);
  const [interval, setIntervalValue] = useState(300);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const api = useRef(request);
  api.current = request;
  async function load() {
    const [nextAgent, nextAnalytics] = await Promise.all([
      api.current("/agent"),
      api.current(`/analytics?window_minutes=${windowMinutes}`),
    ]);
    setAgent(nextAgent);
    setAnalytics(nextAnalytics);
  }
  useEffect(() => {
    let active = true;
    async function refresh() {
      try {
        const [a, b] = await Promise.all([
          api.current("/agent"),
          api.current(`/analytics?window_minutes=${windowMinutes}`),
        ]);
        if (active) {
          setAgent(a);
          setAnalytics(b);
          setIntervalValue(a.interval_seconds);
        }
      } catch (e) {
        if (active) setError((e as Error).message);
      }
    }
    refresh();
    const timer = window.setInterval(refresh, 3000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [windowMinutes]);
  async function act(key: string, work: () => Promise<void>) {
    setBusy(key);
    setError("");
    setMessage("");
    try {
      await work();
      await load();
      await onChange();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  async function settings(enabled: boolean, seconds: number) {
    await act("settings", async () => {
      await api.current("/agent/settings", {
        enabled,
        interval_seconds: seconds,
      });
      setMessage(
        enabled
          ? "Scheduled patrol is enabled. Containment still requires approval."
          : "Scheduled patrol paused. Manual scans remain available.",
      );
    });
  }
  if (!agent || !analytics)
    return (
      <section className="panel agent-loading">
        {error ? (
          <div role="alert">
            {error}
            <button
              className="button subtle"
              onClick={() => load().catch((e) => setError(e.message))}
            >
              Retry agent connection
            </button>
          </div>
        ) : (
          <>
            <Loader2 className="spin" size={20} />
            Loading patrol and telemetry analytics…
          </>
        )}
      </section>
    );
  const latest = agent.runs[0];
  return (
    <div className="agent-overview">
      {error && (
        <div role="alert" className="banner error">
          {error}
        </div>
      )}
      {message && (
        <div role="status" className="banner success">
          {message}
        </div>
      )}
      <section className="panel patrol-panel">
        <div className="patrol-identity">
          <div className="agent-emblem">
            <ShieldCheck size={27} />
          </div>
          <div>
            <div className="eyebrow">
              DEFENSE AGENT <span className="safe-pill">APPROVAL-GATED</span>
            </div>
            <h2>{agent.name || "ATLAS"}</h2>
            <p>
              {agent.site.name} · {agent.site.environment} · Fixtures, enrolled agents, and
              authorized website API telemetry
            </p>
          </div>
          <span className={`agent-status ${agent.enabled ? "enabled" : ""}`}>
            <span />
            {agent.status}
          </span>
        </div>
        <div className="patrol-controls">
          <label>
            Patrol frequency
            <select
              aria-label="Patrol frequency"
              value={interval}
              disabled={!!busy}
              onChange={(e) => {
                const seconds = Number(e.target.value);
                setIntervalValue(seconds);
                void settings(agent.enabled, seconds);
              }}
            >
              <option value={30}>Every 30 seconds</option>
              <option value={60}>Every minute</option>
              <option value={300}>Every 5 minutes</option>
              <option value={900}>Every 15 minutes</option>
              <option value={3600}>Every hour</option>
              {![30, 60, 300, 900, 3600].includes(interval) && (
                <option value={interval}>Every {interval} seconds</option>
              )}
            </select>
          </label>
          <button
            className="button subtle"
            disabled={!!busy}
            onClick={() => settings(!agent.enabled, interval)}
          >
            {agent.enabled ? <Pause size={15} /> : <Play size={15} />}{" "}
            {agent.enabled ? "Pause patrol" : "Resume patrol"}
          </button>
          <button
            className="button primary"
            disabled={!!busy}
            onClick={() =>
              act("patrol", async () => {
                const result = await api.current("/agent/patrol", {});
                if (result.status === "failed")
                  throw new Error(
                    result.error ||
                      "Patrol failed. Inspect agent activity for details.",
                  );
                setMessage(
                  "Patrol completed. Results recorded; no containment actions executed.",
                );
              })
            }
          >
            {busy === "patrol" ? (
              <Loader2 size={15} className="spin" />
            ) : (
              <Radio size={15} />
            )}
            Run patrol
          </button>
        </div>
        <div className="patrol-facts">
          <span>
            <Clock3 size={13} />
            Last scan <strong>{stamp(agent.last_run_at)} UTC</strong>
          </span>
          <span>
            <Timer size={13} />
            Next scheduled{" "}
            <strong>
              {agent.enabled ? `${stamp(agent.next_run_at)} UTC` : "Paused"}
            </strong>
          </span>
          <span>
            <ShieldCheck size={13} />
            Read-only investigation · approval-gated response
          </span>
        </div>
      </section>
      <div className="agent-toolbar">
        <div>
          <h2>Telemetry intelligence</h2>
          <p>
            Window anchored to the latest telemetry event, not wall-clock time.
          </p>
        </div>
        <div className="agent-toolbar-actions">
          <label className="window-select">
            Time window
            <select
              aria-label="Analytics time window"
              value={windowMinutes}
              onChange={(e) => setWindowMinutes(Number(e.target.value))}
            >
              <option value={15}>Last 15 minutes</option>
              <option value={60}>Last hour</option>
              <option value={1440}>Last 24 hours</option>
            </select>
          </label>
          <button className="text-button" onClick={review}>
            Review incidents <ArrowUpRight size={15} />
          </button>
        </div>
      </div>
      <div className="agent-kpis">
        <Kpi
          label="Events in window"
          value={analytics.totals.events.toLocaleString()}
          note={`${analytics.bucket_seconds}s aggregation buckets`}
          icon={<Activity size={17} />}
        />
        <Kpi
          label="Suspicious signals"
          value={String(analytics.totals.suspicious)}
          note="Event-level classifier findings"
          icon={<ShieldCheck size={17} />}
          warning
        />
        <Kpi
          label="Outbound traffic"
          value={bytes(analytics.totals.bytes_out)}
          note="Reported network-event bytes"
          icon={<Globe size={17} />}
        />
        <Kpi
          label="Latest patrol"
          value={
            latest ? `${latest.duration_ms.toFixed(1)} ms` : "No scans yet"
          }
          note={
            latest
              ? `${latest.events_analyzed} events analyzed`
              : "Run a patrol to measure duration"
          }
          icon={<Timer size={17} />}
        />
      </div>
      <div className="agent-chart-grid">
        <section className="panel telemetry-chart">
          <div className="panel-heading">
            <div>
              <h2>Event activity</h2>
              <p>Observed events and suspicious signals · UTC</p>
            </div>
            <div className="chart-legend">
              <span>
                <i />
                All events
              </span>
              <span>
                <i className="amber" />
                Suspicious
              </span>
            </div>
          </div>
          <SeriesChart points={analytics.series} kind="events" />
          <ChartData points={analytics.series} />
        </section>
        <section className="panel source-chart">
          <div className="panel-heading">
            <div>
              <h2>Source distribution</h2>
              <p>Coverage across collected event sources</p>
            </div>
          </div>
          <div className="source-bars">
            {analytics.sources.map((source) => (
              <div className="source-bar-row" key={source.source}>
                <div>
                  <span>
                    {source.source === "auth"
                      ? "Authentication"
                      : source.source === "email"
                        ? "Email gateway"
                        : "Network flows"}
                  </span>
                  <strong>{source.total}</strong>
                </div>
                <div className="source-track">
                  <span
                    style={{
                      width: `${(source.total / Math.max(1, analytics.totals.events)) * 100}%`,
                    }}
                  >
                    <i
                      style={{
                        width: `${(source.suspicious / Math.max(1, source.total)) * 100}%`,
                      }}
                    />
                  </span>
                </div>
                <small>
                  {source.suspicious} suspicious ·{" "}
                  {source.total
                    ? Math.round((source.suspicious / source.total) * 100)
                    : 0}
                  % of source
                </small>
              </div>
            ))}
          </div>
          <div className="chart-footnote">
            <i className="legend-dot amber" />
            Amber indicates suspicious events within each source.
          </div>
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Network egress</h2>
              <p>Outbound volume per {analytics.bucket_seconds}s bucket · MB</p>
            </div>
            <Globe size={17} />
          </div>
          <SeriesChart points={analytics.series} kind="network" />
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>Patrol execution time</h2>
              <p>Actual measured scans · most recent 12 runs</p>
            </div>
            <Timer size={17} />
          </div>
          <PatrolChart runs={agent.runs} />
        </section>
      </div>
      <div className="agent-detail-grid">
        <section className="panel">
          <div className="panel-heading">
            <h2>
              Observed hosts{" "}
              <span className="count">{analytics.hosts.length}</span>
            </h2>
            <span className="muted">Selected telemetry window</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Host / identities</th>
                  <th>Events</th>
                  <th>Signals</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {analytics.hosts.map((host) => (
                  <tr key={host.host}>
                    <td>
                      <code>{host.host}</code>
                      <small>{host.identities.join(", ")}</small>
                    </td>
                    <td>{host.events}</td>
                    <td>{host.suspicious}</td>
                    <td>
                      <span
                        className={`badge ${host.status === "attention" ? "high" : host.status === "isolated" ? "verified" : "neutral"}`}
                      >
                        {host.status}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!analytics.hosts.length && (
            <div className="chart-empty">
              No hosts in this window. Replay fixtures or collect events from a
              connected source.
            </div>
          )}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <h2>Signal categories</h2>
            <span className="muted">Evidence occurrences</span>
          </div>
          <div className="category-distribution">
            {analytics.categories.map((category) => (
              <div key={category.category}>
                <span>{category.category}</span>
                <div>
                  <i
                    style={{
                      width: `${(category.count / Math.max(1, ...analytics.categories.map((c) => c.count))) * 100}%`,
                    }}
                  />
                </div>
                <strong>{category.count}</strong>
              </div>
            ))}
            {!analytics.categories.length && (
              <p className="chart-empty">
                No suspicious evidence in this window.
              </p>
            )}
          </div>
        </section>
      </div>
      <section className="panel coverage-panel">
        <div className="panel-heading">
          <h2>Source coverage</h2>
          <span className="safe-pill">EVENT SOURCE COVERAGE</span>
        </div>
        <div className="coverage-grid">
          {agent.coverage.map((source) => (
            <div key={source.source}>
              <div>
                <Radio size={16} />
                <strong>{source.label}</strong>
                <span className="badge neutral">{source.status}</span>
              </div>
              <p>
                {source.events} events collected{" "}
                <span>Last event {stamp(source.last_event_at)} UTC</span>
              </p>
            </div>
          ))}
        </div>
      </section>
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>
              ATLAS activity <span className="count">{agent.runs.length}</span>
            </h2>
            <p>Persistent patrol history · latest first</p>
          </div>
          <span className="muted">
            Backend uptime {Math.floor(agent.uptime_seconds / 60)}m · not
            website uptime
          </span>
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Started · UTC</th>
                <th>Trigger</th>
                <th>Analyzed</th>
                <th>Suspicious</th>
                <th>Incidents</th>
                <th>Duration</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {agent.runs.slice(0, 12).map((run) => (
                <tr key={run.id}>
                  <td className="mono">{stamp(run.started_at)}</td>
                  <td>{run.trigger}</td>
                  <td>{run.events_analyzed}</td>
                  <td>{run.suspicious_events}</td>
                  <td>{run.incidents_found}</td>
                  <td className="mono">{run.duration_ms.toFixed(2)} ms</td>
                  <td>
                    <span
                      className={`badge ${run.status === "completed" ? "verified" : "critical"}`}
                    >
                      {run.status}
                    </span>
                    {run.error && <small>{run.error}</small>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!agent.runs.length && (
          <div className="chart-empty">
            No patrol runs yet. Select Run patrol to investigate the current
            telemetry.
          </div>
        )}
      </section>
      <p className="analytics-scope">
        {analytics.scope} Resource metrics for enrolled hosts are available in
        Servers. API connectivity does not measure website availability.
      </p>
    </div>
  );
}
function Kpi({
  label,
  value,
  note,
  icon,
  warning = false,
}: {
  label: string;
  value: string;
  note: string;
  icon: React.ReactNode;
  warning?: boolean;
}) {
  return (
    <div className={`agent-kpi ${warning ? "warning" : ""}`}>
      <div>
        {label}
        {icon}
      </div>
      <strong>{value}</strong>
      <small>{note}</small>
    </div>
  );
}

function SeriesChart({
  points,
  kind,
}: {
  points: Point[];
  kind: "events" | "network";
}) {
  const [focused, setFocused] = useState<number | null>(null);
  const W = 680,
    H = 220,
    left = 43,
    right = 18,
    top = 24,
    bottom = 36;
  const max = Math.max(
    1,
    ...points.map((p) => (kind === "events" ? p.events : p.bytes_out / 1e6)),
  );
  const ticks =
    kind === "events"
      ? Array.from(
          new Set([0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(max * f))),
        )
      : [0, 0.25, 0.5, 0.75, 1].map((f) => max * f);
  const x = (i: number) =>
    left + (i / Math.max(1, points.length - 1)) * (W - left - right);
  const y = (n: number) => H - bottom - (n / max) * (H - top - bottom);
  const line = (field: "events" | "suspicious") =>
    points.map((p, i) => `${i ? "L" : "M"}${x(i)},${y(p[field])}`).join(" ");
  const picked = focused !== null ? points[focused] : null;
  return (
    <div className="svg-chart">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        role="img"
        aria-label={
          kind === "events"
            ? "Events and suspicious signals over time. Focus a point for values, or open chart data below."
            : "Outbound network megabytes over time. Focus a bar for values."
        }
      >
        {ticks.map((tick) => (
          <g key={tick}>
            <line
              x1={left}
              y1={y(tick)}
              x2={W - right}
              y2={y(tick)}
              stroke="#263547"
              strokeDasharray="3 5"
            />
            <text
              x={left - 9}
              y={y(tick) + 4}
              textAnchor="end"
              fill="#7d93ad"
              fontSize="10"
            >
              {kind === "network" ? tick.toFixed(1) : tick}
            </text>
          </g>
        ))}
        {kind === "events" && points.length > 0 && (
          <>
            <path
              d={`${line("events")} L${x(points.length - 1)},${H - bottom} L${left},${H - bottom} Z`}
              fill="#58cbb4"
              opacity=".08"
            />
            <path
              d={line("events")}
              fill="none"
              stroke="#70d7c1"
              strokeWidth="2.3"
            />
            <path
              d={line("suspicious")}
              fill="none"
              stroke="#e0ad73"
              strokeWidth="2"
            />
          </>
        )}
        {points.map((p, i) => (
          <g key={p.timestamp}>
            {kind === "network" ? (
              <rect
                x={
                  x(i) -
                  Math.min(
                    8,
                    (W - left - right) / Math.max(points.length, 1) / 3,
                  )
                }
                y={y(p.bytes_out / 1e6)}
                width={Math.min(
                  16,
                  ((W - left - right) / Math.max(points.length, 1)) * 0.65,
                )}
                height={Math.max(0, H - bottom - y(p.bytes_out / 1e6))}
                rx="2"
                fill={focused === i ? "#b2f1e0" : "#65bcb0"}
                tabIndex={0}
                onFocus={() => setFocused(i)}
                onBlur={() => setFocused(null)}
                onMouseEnter={() => setFocused(i)}
                onMouseLeave={() => setFocused(null)}
                aria-label={`${stamp(p.timestamp)} UTC: ${bytes(p.bytes_out)} outbound`}
              >
                <title>
                  {stamp(p.timestamp)} UTC: {bytes(p.bytes_out)} outbound
                </title>
              </rect>
            ) : (
              <circle
                cx={x(i)}
                cy={y(p.events)}
                r={focused === i ? 5 : 3}
                fill="#73d6c0"
                stroke="#132129"
                strokeWidth="1.5"
                tabIndex={0}
                onFocus={() => setFocused(i)}
                onBlur={() => setFocused(null)}
                onMouseEnter={() => setFocused(i)}
                onMouseLeave={() => setFocused(null)}
                aria-label={`${stamp(p.timestamp)} UTC: ${p.events} events, ${p.suspicious} suspicious`}
              >
                <title>
                  {stamp(p.timestamp)} UTC: {p.events} events, {p.suspicious}{" "}
                  suspicious
                </title>
              </circle>
            )}
            {(i === 0 ||
              i === Math.floor((points.length - 1) / 2) ||
              i === points.length - 1) && (
              <text
                x={x(i)}
                y={H - 12}
                textAnchor={
                  i === 0 ? "start" : i === points.length - 1 ? "end" : "middle"
                }
                fill="#7d93ad"
                fontSize="10"
              >
                {stamp(p.timestamp).slice(0, 5)}
              </text>
            )}
          </g>
        ))}
      </svg>
      <div className="chart-tooltip" aria-live="polite">
        {picked
          ? `${stamp(picked.timestamp)} UTC · ${kind === "events" ? `${picked.events} events · ${picked.suspicious} suspicious` : `${bytes(picked.bytes_out)} outbound`}`
          : points.length
            ? "Hover or focus a data point to inspect its values."
            : "No telemetry in this window."}
      </div>
    </div>
  );
}
function ChartData({ points }: { points: Point[] }) {
  return (
    <details className="chart-data">
      <summary>View chart data</summary>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Time · UTC</th>
              <th>Events</th>
              <th>Suspicious</th>
              <th>Auth failures</th>
              <th>Bytes out</th>
            </tr>
          </thead>
          <tbody>
            {points.map((p) => (
              <tr key={p.timestamp}>
                <td>{stamp(p.timestamp)}</td>
                <td>{p.events}</td>
                <td>{p.suspicious}</td>
                <td>{p.auth_failures}</td>
                <td>{p.bytes_out}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
function PatrolChart({ runs }: { runs: Run[] }) {
  const selected = runs.slice(0, 12).reverse(),
    max = Math.max(1, ...selected.map((r) => r.duration_ms));
  if (!selected.length)
    return (
      <div className="chart-empty patrol-empty">
        <Timer size={25} />
        <strong>Waiting for the first patrol</strong>
        <span>Run a scan to chart actual execution duration.</span>
      </div>
    );
  return (
    <div className="svg-chart">
      <svg
        viewBox="0 0 560 220"
        role="img"
        aria-label="Measured patrol duration in milliseconds, oldest to newest"
      >
        <text x="20" y="20" fill="#7d93ad" fontSize="10">
          ms
        </text>
        {[0, 0.5, 1].map((f) => (
          <g key={f}>
            <line
              x1="45"
              x2="540"
              y1={180 - f * 140}
              y2={180 - f * 140}
              stroke="#263547"
              strokeDasharray="3 5"
            />
            <text
              x="36"
              y={184 - f * 140}
              textAnchor="end"
              fill="#7d93ad"
              fontSize="10"
            >
              {(max * f).toFixed(1)}
            </text>
          </g>
        ))}
        {selected.map((run, i) => {
          const x = 55 + (i * 475) / selected.length,
            h = (run.duration_ms / max) * 140;
          return (
            <g key={run.id}>
              <rect
                x={x}
                y={180 - h}
                width={Math.min(28, 350 / selected.length)}
                height={Math.max(2, h)}
                rx="3"
                fill="#8c9ed7"
                tabIndex={0}
                aria-label={`${stamp(run.started_at)} UTC: ${run.duration_ms.toFixed(2)} ms`}
              >
                <title>
                  {stamp(run.started_at)} UTC · {run.duration_ms.toFixed(2)} ms
                </title>
              </rect>
              <text
                x={x + 8}
                y="203"
                textAnchor="middle"
                fill="#7d93ad"
                fontSize="9"
              >
                {i + 1}
              </text>
            </g>
          );
        })}
      </svg>
      <div className="chart-tooltip">
        Patrol sequence · oldest to newest · hover or focus a bar for duration.
      </div>
    </div>
  );
}
