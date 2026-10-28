import { useEffect, useRef, useState } from "react";
import Modal from "./Modal";
import ConnectSource, { type Source, categoryLabel } from "./ConnectSource";
import WebsiteSource from "./WebsiteSource";
import {
  Server,
  Plus,
  Copy,
  Check,
  Cpu,
  MemoryStick,
  Activity,
  Clock3,
  Shield,
  RefreshCw,
  X,
  ArrowUpRight,
  KeyRound,
  Link2,
  Globe,
  FlaskConical,
} from "lucide-react";

type Metrics = {
  cpu_percent: number;
  memory_percent: number;
  memory_used_bytes: number;
  memory_total_bytes: number;
  load_1m: number;
  uptime_seconds: number;
};
type RegisteredServer = {
  id: string;
  name: string;
  hostname: string;
  website_url: string | null;
  mode: "simulated" | "real";
  status: "pending" | "online" | "offline" | "revoked";
  last_seen_at: string | null;
  metrics: Metrics | null;
  event_count: number;
  threat_count: number;
  incident_ids: string[];
  created_at: string;
};
type SecurityEvent = {
  id: string;
  timestamp: string;
  source: string;
  identity: string;
  host: string;
  suspicious: boolean;
  confidence: number;
  details: Record<string, unknown>;
  evidence?: { category: string; explanation: string }[];
};
type ServerDetail = {
  server: RegisteredServer;
  events: SecurityEvent[];
  incidents: {
    id: string;
    title: string;
    severity: string;
    status: string;
    confidence: number;
  }[];
  metric_history: (Metrics & { timestamp: string })[];
};
type Enrollment = {
  server: RegisteredServer;
  enrollment_token: string;
  expires_at: string;
};
type Props = {
  request: (path: string, body?: unknown) => Promise<any>;
  addRequest: number;
  reviewIncident: (id: string) => void;
};
const clock = (timestamp: string | null) =>
  timestamp
    ? new Date(timestamp).toLocaleString("en-GB", {
        timeZone: "UTC",
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
      }) + " UTC"
    : "No heartbeat received";
const memory = (value: number) => `${(value / 1024 ** 3).toFixed(2)} GiB`;
const shellQuote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
export default function Servers({
  request,
  addRequest,
  reviewIncident,
}: Props) {
  const [servers, setServers] = useState<RegisteredServer[]>([]);
  const [sources, setSources] = useState<Source[]>([]);
  const [selected, setSelected] = useState("");
  const [detail, setDetail] = useState<ServerDetail | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState("");
  const [adding, setAdding] = useState(false);
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [copied, setCopied] = useState(false);
  const [confirmation, setConfirmation] = useState<"revoke" | "rotate" | null>(
    null,
  );
  const api = useRef(request);
  api.current = request;
  const lastAddRequest = useRef(0);
  function openAdd() {
    setError("");
    setAdding(true);
  }
  useEffect(() => {
    if (addRequest > 0 && addRequest !== lastAddRequest.current) openAdd();
    lastAddRequest.current = addRequest;
  }, [addRequest]);
  async function load() {
    const [result, catalog] = await Promise.all([
      api.current("/servers"),
      api.current("/sources"),
    ]);
    setServers(result.servers);
    setSources(catalog.sources);
    setLoaded(true);
    if (
      selected &&
      result.servers.some((item: RegisteredServer) => item.id === selected)
    )
      setDetail(await api.current(`/servers/${selected}`));
  }
  useEffect(() => {
    let active = true;
    async function refresh() {
      try {
        const [result, catalog] = await Promise.all([
          api.current("/servers"),
          api.current("/sources"),
        ]);
        if (active) {
          setServers(result.servers);
          setSources(catalog.sources);
          setLoaded(true);
        }
        if (
          selected &&
          result.servers.some((item: RegisteredServer) => item.id === selected)
        ) {
          const next = await api.current(`/servers/${selected}`);
          if (active) setDetail(next);
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
  }, [selected]);
  useEffect(() => {
    if (sources.length && !selected) setSelected(sources[0].id);
  }, [sources, selected]);
  async function perform(key: string, work: () => Promise<void>) {
    setBusy(key);
    setError("");
    setNotice("");
    try {
      await work();
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  const server =
    detail?.server.id === selected
      ? detail.server
      : servers.find((s) => s.id === selected);
  const visibleDetail = detail?.server.id === selected ? detail : null;
  const selectedSource = sources.find((source) => source.id === selected);
  const connectionUrl =
    window.location.protocol === "https:"
      ? window.location.origin
      : "https://localhost:8443";
  const stateDirectory = enrollment
    ? `~/.local/state/ai-defense/${enrollment.server.id.replace(/[^A-Za-z0-9_-]/g, "")}-${Date.parse(enrollment.expires_at)}`
    : "";
  const command = enrollment
    ? `python3 agent/soc_agent.py enroll \\\n  --url ${shellQuote(connectionUrl)} \\\n  --ca-cert .local-tls/ca.crt \\\n  --state-dir ${stateDirectory} \\\n  --hostname ${shellQuote(enrollment.server.hostname)} \\\n  --mode ${enrollment.server.mode}`
    : "";
  return (
    <div className="servers-page">
      {error && !adding && !enrollment && !confirmation && (
        <div role="alert" className="banner error">
          {error}
          <button
            onClick={() =>
              load()
                .then(() => setError(""))
                .catch((e) => setError(e.message))
            }
          >
            Retry
          </button>
        </div>
      )}
      <section className="panel server-intro">
        <div>
          <div className="section-label">
            <Link2 size={15} />
            DATA SOURCE CONNECTIONS
          </div>
          <h2>Connect your infrastructure to the SOC</h2>
          <p>
            Connect an authorized website API, enroll a Linux agent, or run a
            clearly labeled synthetic demo. Each source keeps its own
            credentials, permissions, telemetry, and incident history.
          </p>
        </div>
        <button className="button primary" onClick={openAdd}>
          <Plus size={15} />
          Connect Data Source
        </button>
      </section>
      <div className="server-summary">
        <span>
          <span className="online-dot" />
          {sources.filter((s) => s.status === "connected").length} connected
        </span>
        <span>
          {sources.filter((s) => s.status === "pending").length} awaiting
          connection
        </span>
        <span>
          {sources.filter((s) => s.status === "offline").length} offline
        </span>
        <span>{sources.length} sources</span>
        <small>No SSH, remote commands, or automatic containment.</small>
      </div>
      {!loaded ? (
        <div className="panel chart-empty">Loading data sources…</div>
      ) : !sources.length ? (
        <section className="panel server-empty">
          <Server size={36} />
          <h2>No data sources connected yet</h2>
          <p>
            Choose an integration and authorize the telemetry you want to
            collect. Data appears only after a verified API fetch or agent
            heartbeat.
          </p>
          <button className="button primary" onClick={openAdd}>
            <Plus size={15} />
            Connect your first source
          </button>
        </section>
      ) : (
        <div className="server-workspace">
          <section className="panel server-list">
            <div className="panel-heading">
              <h2>
                Data sources <span className="count">{sources.length}</span>
              </h2>
            </div>
            {sources.map((s) => (
              <button
                key={s.id}
                className={`server-list-item ${selected === s.id ? "selected" : ""}`}
                onClick={() => {
                  setSelected(s.id);
                  setError("");
                }}
              >
                <div>
                  <span className="server-list-icon">
                    {s.type === "website" ? (
                      <Globe size={18} />
                    ) : s.type === "simulated" ? (
                      <FlaskConical size={18} />
                    ) : (
                      <Server size={18} />
                    )}
                  </span>
                  <span>
                    <strong>{s.name}</strong>
                    <small>{s.hostname || s.base_url}</small>
                  </span>
                  <span className={`server-status ${s.status}`}>
                    {s.status}
                  </span>
                </div>
                <p>
                  {s.type === "website"
                    ? `Website API${s.mode === "simulated" ? " · Simulated" : ""}`
                    : s.mode === "simulated"
                      ? "Simulated agent"
                      : "Linux agent"}
                  <span>{s.threat_count} signals</span>
                </p>
                <small>
                  {s.last_success_at
                    ? `Last connected ${clock(s.last_success_at)}`
                    : s.type === "website"
                      ? "Not yet verified"
                      : "Waiting for first heartbeat"}
                </small>
              </button>
            ))}
          </section>
          {selectedSource?.type === "website" && (
            <WebsiteSource
              key={selectedSource.id}
              source={selectedSource}
              request={request}
              refresh={load}
              reviewIncident={reviewIncident}
            />
          )}
          {server && selectedSource?.type !== "website" && (
            <div className="server-detail">
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <div className="detail-kicker">
                      <span className={`server-status ${server.status}`}>
                        {server.status}
                      </span>
                      <span>
                        {server.mode === "simulated"
                          ? "SIMULATED AGENT"
                          : "LINUX AGENT METRICS"}
                      </span>
                    </div>
                    <h2 className="server-title">{server.name}</h2>
                    <p>
                      <code>{server.hostname}</code> · {server.id}
                    </p>
                  </div>
                  <div className="server-admin-actions">
                    <button
                      className="button subtle"
                      disabled={!!busy || server.status === "revoked"}
                      onClick={() =>
                        perform("test", async () => {
                          const result = await api.current(
                            `/sources/${server.id}/test`,
                            {},
                          );
                          setNotice(result.verification);
                        })
                      }
                    >
                      <RefreshCw size={13} />
                      Test Connection
                    </button>
                    <button
                      className="button subtle"
                      disabled={!!busy}
                      onClick={() => {
                        setError("");
                        setConfirmation("rotate");
                      }}
                    >
                      <RefreshCw size={13} />
                      Rotate enrollment
                    </button>
                    <button
                      className="button subtle danger-text"
                      disabled={!!busy || server.status === "revoked"}
                      onClick={() => {
                        setError("");
                        setConfirmation("revoke");
                      }}
                    >
                      <X size={13} />
                      Revoke agent
                    </button>
                  </div>
                </div>
                <div className="server-connection">
                  <span>
                    <Clock3 size={13} />
                    Last heartbeat: {clock(server.last_seen_at)}
                  </span>
                  {server.website_url && (
                    <span className="server-url">
                      Website reference: {server.website_url}
                    </span>
                  )}
                  <p>
                    {server.mode === "simulated"
                      ? "All metrics and security signals from this agent are synthetic demonstration data."
                      : "Host metrics come from the enrolled Linux agent. Security events depend on explicitly configured local log files."}{" "}
                    {server.status === "offline"
                      ? "The last heartbeat is stale; displayed values are historical."
                      : server.status === "revoked"
                        ? "Credentials revoked. New telemetry is no longer accepted."
                        : ""}{" "}
                    Agent telemetry does not imply website availability.
                  </p>
                </div>
                {notice && (
                  <p role="status" className="source-notice">
                    {notice}
                  </p>
                )}
                <div className="source-permissions">
                  <div>
                    <h3>Granted permissions</h3>
                    <p>
                      {selectedSource?.granted_permissions.join(", ") ||
                        "Awaiting enrollment"}
                    </p>
                  </div>
                  <div>
                    <h3>Supported telemetry categories</h3>
                    <p>
                      {selectedSource?.enabled_categories
                        .map(categoryLabel)
                        .join(", ") || "No categories configured"}
                    </p>
                    <p>
                      Security log permissions and paths are configured locally
                      on the agent. Supported categories do not prove log access
                      is granted.
                    </p>
                  </div>
                  <div>
                    <h3>Last event received</h3>
                    <p>
                      {selectedSource?.last_event_received_at
                        ? clock(selectedSource.last_event_received_at)
                        : selectedSource?.event_count
                          ? "Receipt time unavailable for older events"
                          : "No events received"}
                    </p>
                  </div>
                </div>
                <div className="server-metrics">
                  <HostMetric
                    label="CPU utilization"
                    value={
                      server.metrics
                        ? `${server.metrics.cpu_percent.toFixed(1)}%`
                        : "—"
                    }
                    icon={<Cpu size={16} />}
                    percent={server.metrics?.cpu_percent}
                    detail={
                      server.metrics
                        ? `1m load: ${server.metrics.load_1m.toFixed(2)}`
                        : "Awaiting agent sample"
                    }
                  />
                  <HostMetric
                    label="Memory utilization"
                    value={
                      server.metrics
                        ? `${server.metrics.memory_percent.toFixed(1)}%`
                        : "—"
                    }
                    icon={<MemoryStick size={16} />}
                    percent={server.metrics?.memory_percent}
                    detail={
                      server.metrics
                        ? `${memory(server.metrics.memory_used_bytes)} / ${memory(server.metrics.memory_total_bytes)}`
                        : "Awaiting agent sample"
                    }
                  />
                  <HostMetric
                    label="Host uptime"
                    value={
                      server.metrics
                        ? `${Math.floor(server.metrics.uptime_seconds / 3600)}h ${Math.floor((server.metrics.uptime_seconds % 3600) / 60)}m`
                        : "—"
                    }
                    icon={<Clock3 size={16} />}
                    detail={
                      server.mode === "simulated"
                        ? "Synthetic uptime value"
                        : "Reported by Linux agent"
                    }
                  />
                  <HostMetric
                    label="Security events"
                    value={String(server.event_count)}
                    icon={<Activity size={16} />}
                    detail={`${server.threat_count} suspicious signals`}
                  />
                </div>
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <div>
                    <h2>Host resource history</h2>
                    <p>Agent-submitted CPU and memory samples · UTC</p>
                  </div>
                  <div className="chart-legend">
                    <span>
                      <i />
                      CPU
                    </span>
                    <span>
                      <i className="amber" />
                      Memory
                    </span>
                  </div>
                </div>
                <HostHistory samples={visibleDetail?.metric_history || []} />
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>
                    <Shield size={16} />
                    Related incidents{" "}
                    <span className="count">
                      {visibleDetail?.incidents.length || 0}
                    </span>
                  </h2>
                </div>
                {visibleDetail?.incidents.length ? (
                  visibleDetail.incidents.map((i) => (
                    <button
                      key={i.id}
                      className="server-incident"
                      onClick={() => reviewIncident(i.id)}
                    >
                      <span className={`badge ${i.severity}`}>
                        {i.severity}
                      </span>
                      <strong>{i.title}</strong>
                      <span>{i.status}</span>
                      <ArrowUpRight size={15} />
                    </button>
                  ))
                ) : (
                  <div className="chart-empty">
                    No correlated incidents for this host.
                  </div>
                )}
              </section>
              <section className="panel">
                <div className="panel-heading">
                  <h2>
                    Server security events{" "}
                    <span className="count">
                      {visibleDetail?.events.length || 0}
                    </span>
                  </h2>
                  <span className="muted">Agent-submitted telemetry</span>
                </div>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Timestamp · UTC</th>
                        <th>Source</th>
                        <th>Identity</th>
                        <th>Detection</th>
                        <th>Evidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visibleDetail?.events.map((event) => (
                        <tr key={event.id}>
                          <td>
                            {clock(event.timestamp)}
                            <small>{event.id}</small>
                          </td>
                          <td>{event.source}</td>
                          <td>{event.identity}</td>
                          <td>
                            <span
                              className={`badge ${event.suspicious ? "high" : "neutral"}`}
                            >
                              {event.suspicious ? "Suspicious" : "Normal"}
                            </span>
                          </td>
                          <td>
                            <details>
                              <summary>Inspect event</summary>
                              <pre>{JSON.stringify(event, null, 2)}</pre>
                            </details>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {!visibleDetail?.events.length && (
                  <div className="chart-empty">
                    No security events received. Heartbeat metrics do not imply
                    security log collection is configured.
                  </div>
                )}
              </section>
            </div>
          )}
        </div>
      )}
      <ConnectSource
        open={adding}
        onClose={() => setAdding(false)}
        request={request}
        onEnrollment={(result) => {
          setEnrollment(result);
          setSelected(result.server.id);
          setCopied(false);
          void load();
        }}
        onConnected={(id) => {
          setSelected(id);
          void load();
        }}
      />
      <Modal
        open={!!enrollment}
        onDismiss={() => setEnrollment(null)}
        labelledBy="enrollment-title"
        className="enrollment-dialog"
      >
        <div className="dialog-heading">
          <span className="dialog-icon">
            <KeyRound size={24} />
          </span>
          <button
            aria-label="Close enrollment instructions"
            onClick={() => setEnrollment(null)}
          >
            <X size={20} />
          </button>
        </div>
        <div className="eyebrow">ONE-TIME ENROLLMENT</div>
        <h2 id="enrollment-title">Connect {enrollment?.server.name}</h2>
        <p>
          Copy this token now. It is shown only in this session and expires at{" "}
          {clock(enrollment?.expires_at || null)}. Closing this dialog clears it
          from the interface.
        </p>
        <label>
          Enrollment token
          <div className="enrollment-token">
            <input
              readOnly
              value={enrollment?.enrollment_token || ""}
              aria-label="Enrollment token"
              autoComplete="off"
              spellCheck={false}
            />
            <button
              className="button subtle"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(
                    enrollment?.enrollment_token || "",
                  );
                  setCopied(true);
                } catch {
                  setError(
                    "Clipboard unavailable. Select and copy the token field manually.",
                  );
                }
              }}
            >
              {copied ? <Check size={15} /> : <Copy size={15} />}{" "}
              {copied ? "Copied" : "Copy token"}
            </button>
          </div>
        </label>
        <div className="source-validation" role="status">
          <h3>Agent verification</h3>
          <p>
            {servers.find((item) => item.id === enrollment?.server.id)
              ?.last_seen_at
              ? `Authenticated heartbeat received: ${clock(servers.find((item) => item.id === enrollment?.server.id)?.last_seen_at || null)}`
              : "Pending — no authenticated heartbeat received yet. Installing the agent alone does not establish a connection."}
          </p>
        </div>
        <div className="enrollment-steps">
          <h3>1. Start the trusted HTTPS endpoint</h3>
          <p>
            Stop the HTTP development server before running{" "}
            <code>./scripts/dev_https.sh</code> on the dashboard host. Use only
            one backend worker. Transfer the CA certificate to the agent host.
            For a remote host, replace the URL below with your reachable HTTPS
            dashboard address covered by its certificate.
          </p>
          <h3>2. Enroll on the agent host</h3>
          <p>
            Run this command and paste the token at the interactive prompt. The
            token is not included in shell history. Each enrollment uses a new
            state directory so existing credentials are not overwritten. When
            rotating credentials, stop the prior agent first; its old credential
            is revoked.
          </p>
          <pre>{command}</pre>
          <h3>3. Send the first heartbeat</h3>
          <pre>{`python3 agent/soc_agent.py run --state-dir ${stateDirectory} --once`}</pre>
          <p>
            After the first sample, remove <code>--once</code> to keep the agent
            running. Real security logs must be explicitly configured; see the
            README for supported options.
          </p>
        </div>
        {error && (
          <div role="alert" className="banner error">
            {error}
          </div>
        )}
        <div className="dialog-actions">
          <button
            className="button primary"
            onClick={() => setEnrollment(null)}
          >
            Close enrollment instructions
          </button>
        </div>
      </Modal>
      <Modal
        open={!!confirmation}
        onDismiss={() => setConfirmation(null)}
        labelledBy="server-confirmation-title"
      >
        <div className="dialog-heading">
          <span className="dialog-icon">
            <KeyRound size={24} />
          </span>
          <button
            type="button"
            aria-label="Close server confirmation"
            onClick={() => setConfirmation(null)}
          >
            <X size={20} />
          </button>
        </div>
        <h2 id="server-confirmation-title">
          {confirmation === "revoke"
            ? "Revoke this agent?"
            : "Rotate enrollment credentials?"}
        </h2>
        <p>
          {confirmation === "revoke"
            ? "This invalidates the agent credential and stops accepting new telemetry. It does not stop services, isolate the host, or run commands."
            : "The current agent credential will be revoked. A new one-time token will be shown, and the agent must enroll again before sending telemetry."}
        </p>
        <p>
          <strong>{server?.name}</strong> · {server?.hostname}
        </p>
        {error && (
          <div role="alert" className="banner error">
            {error}
          </div>
        )}
        <div className="dialog-actions">
          <button
            className="button subtle"
            onClick={() => setConfirmation(null)}
          >
            Cancel
          </button>
          <button
            className="button primary"
            disabled={!!busy}
            onClick={() =>
              perform("credentials", async () => {
                if (!server) return;
                if (confirmation === "revoke")
                  await api.current(`/servers/${server.id}/revoke`, {});
                else {
                  const result = await api.current(
                    `/servers/${server.id}/enrollment`,
                    {},
                  );
                  setEnrollment({ ...result, server });
                  setCopied(false);
                }
                setConfirmation(null);
              })
            }
          >
            {confirmation === "revoke"
              ? "Confirm revoke"
              : "Rotate credentials"}
          </button>
        </div>
      </Modal>
    </div>
  );
}
function HostMetric({
  label,
  value,
  detail,
  icon,
  percent,
}: {
  label: string;
  value: string;
  detail: string;
  icon: React.ReactNode;
  percent?: number;
}) {
  return (
    <div className="host-metric">
      <div>
        {label}
        {icon}
      </div>
      <strong>{value}</strong>
      {percent !== undefined && (
        <div className="host-meter">
          <span style={{ width: `${Math.max(0, Math.min(100, percent))}%` }} />
        </div>
      )}
      <small>{detail}</small>
    </div>
  );
}
function HostHistory({
  samples,
}: {
  samples: (Metrics & { timestamp: string })[];
}) {
  const rows = [...samples]
    .sort((a, b) => a.timestamp.localeCompare(b.timestamp))
    .slice(-60);
  if (!rows.length)
    return (
      <div className="chart-empty">
        Waiting for agent metric samples. No estimated health values are
        displayed.
      </div>
    );
  const x = (i: number) => 45 + (i / Math.max(1, rows.length - 1)) * 610,
    y = (v: number) => 175 - v * 1.4;
  const line = (key: "cpu_percent" | "memory_percent") =>
    rows.map((row, i) => `${i ? "L" : "M"}${x(i)},${y(row[key])}`).join(" ");
  return (
    <>
      <div className="svg-chart">
        <svg
          viewBox="0 0 680 215"
          role="img"
          aria-label="Agent CPU and memory percentage history"
        >
          <title>CPU and memory usage from submitted agent samples</title>
          {[0, 25, 50, 75, 100].map((n) => (
            <g key={n}>
              <line
                x1="45"
                x2="655"
                y1={y(n)}
                y2={y(n)}
                stroke="#263547"
                strokeDasharray="3 5"
              />
              <text
                x="36"
                y={y(n) + 4}
                fill="#7d93ad"
                fontSize="10"
                textAnchor="end"
              >
                {n}%
              </text>
            </g>
          ))}
          <path
            d={line("cpu_percent")}
            fill="none"
            stroke="#70d7c1"
            strokeWidth="2"
          />
          <path
            d={line("memory_percent")}
            fill="none"
            stroke="#e0ad73"
            strokeWidth="2"
          />
          {rows.map((row, i) => (
            <g key={`${row.timestamp}-${i}`}>
              <circle
                cx={x(i)}
                cy={y(row.cpu_percent)}
                r="3"
                fill="#70d7c1"
                tabIndex={0}
                aria-label={`${clock(row.timestamp)} CPU ${row.cpu_percent.toFixed(1)}%, memory ${row.memory_percent.toFixed(1)}%`}
              >
                <title>
                  {clock(row.timestamp)} · CPU {row.cpu_percent.toFixed(1)}% ·
                  Memory {row.memory_percent.toFixed(1)}%
                </title>
              </circle>
              <circle
                cx={x(i)}
                cy={y(row.memory_percent)}
                r="3"
                fill="#e0ad73"
                tabIndex={0}
                aria-label={`${clock(row.timestamp)} Memory ${row.memory_percent.toFixed(1)}%`}
              >
                <title>
                  {clock(row.timestamp)} · Memory{" "}
                  {row.memory_percent.toFixed(1)}%
                </title>
              </circle>
              {(i === 0 || i === rows.length - 1) && (
                <text
                  x={x(i)}
                  y="200"
                  fill="#7d93ad"
                  fontSize="10"
                  textAnchor={i === 0 ? "start" : "end"}
                >
                  {new Date(row.timestamp).toLocaleTimeString("en-GB", {
                    timeZone: "UTC",
                  })}
                </text>
              )}
            </g>
          ))}
        </svg>
      </div>
      <details className="chart-data">
        <summary>View resource samples</summary>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Timestamp · UTC</th>
                <th>CPU</th>
                <th>Memory</th>
                <th>Load 1m</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={`${row.timestamp}-${i}`}>
                  <td>{clock(row.timestamp)}</td>
                  <td>{row.cpu_percent.toFixed(1)}%</td>
                  <td>{row.memory_percent.toFixed(1)}%</td>
                  <td>{row.load_1m.toFixed(2)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>
    </>
  );
}
