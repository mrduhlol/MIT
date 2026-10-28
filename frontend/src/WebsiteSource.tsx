import { useEffect, useRef, useState } from "react";
import {
  ArrowUpRight,
  Download,
  Globe,
  KeyRound,
  RefreshCw,
  Shield,
  Unplug,
  X,
} from "lucide-react";
import Modal from "./Modal";
import { categoryLabel, type Source } from "./ConnectSource";
const date = (value: string | null) =>
  value
    ? new Date(value).toLocaleString("en-GB", { timeZone: "UTC" }) + " UTC"
    : "Not received";
type Detail = {
  source: Source;
  events: {
    id: string;
    timestamp: string;
    source: string;
    identity: string;
    suspicious: boolean;
    [key: string]: unknown;
  }[];
  incidents: { id: string; title: string; severity: string; status: string }[];
};
export default function WebsiteSource({
  source,
  request,
  refresh,
  reviewIncident,
}: {
  source: Source;
  request: (path: string, body?: unknown) => Promise<any>;
  refresh: () => Promise<void>;
  reviewIncident: (id: string) => void;
}) {
  const [detail, setDetail] = useState<Detail | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [dialog, setDialog] = useState<
    "permissions" | "disconnect" | "revoke" | null
  >(null);
  const [enabled, setEnabled] = useState<string[]>([]);
  const api = useRef(request);
  api.current = request;
  useEffect(() => {
    let active = true;
    setDetail(null);
    setError("");
    setNotice("");
    setDialog(null);
    const load = async () => {
      try {
        const result = await api.current(`/sources/${source.id}`);
        if (active) setDetail(result);
      } catch (e) {
        if (active) setError((e as Error).message);
      }
    };
    void load();
    const timer = window.setInterval(load, 3000);
    return () => {
      active = false;
      clearInterval(timer);
    };
  }, [source.id]);
  const current = detail?.source.id === source.id ? detail.source : source;
  const currentDetail = detail?.source.id === source.id ? detail : null;
  async function action(kind: string, body: unknown = {}) {
    setBusy(kind);
    setError("");
    setNotice("");
    try {
      await api.current(`/sources/${source.id}/${kind}`, body);
      setDetail(await api.current(`/sources/${source.id}`));
      await refresh();
      setDialog(null);
      setNotice(
        kind === "test"
          ? "Authentication and connection checks passed. Testing does not collect events or resume a disconnected source."
          : kind === "poll"
            ? "Event fetch completed. Authorized events were normalized and analyzed."
            : kind === "permissions"
              ? "Enabled event categories updated. Provider permissions remain limited by the API key."
              : kind === "resume"
                ? "Connection verified and source resumed. Fetch events to collect telemetry."
                : kind === "revoke"
                  ? "Stored credentials removed. This source no longer accepts collection requests."
                  : "Source disconnected. Collection is paused.",
      );
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy("");
    }
  }
  const revoked = current.status === "revoked";
  const disconnected = current.status === "disconnected";
  return (
    <div className="server-detail website-detail">
      <section className="panel">
        <div className="panel-heading">
          <div>
            <div className="detail-kicker">
              <span className={`server-status ${current.status}`}>
                {current.status}
              </span>
              <span>
                WEBSITE API ·{" "}
                {current.mode === "simulated"
                  ? "SIMULATED FEED"
                  : "AUTHORIZED TELEMETRY"}
              </span>
            </div>
            <h2 className="server-title">{current.name}</h2>
            <p className="source-endpoint">{current.base_url}</p>
          </div>
          <Globe size={24} className="muted" />
        </div>
        <div className="server-connection">
          <span>
            API endpoint: <code>{current.events_url}</code>
          </span>
          <p>
            {current.mode === "simulated"
              ? "This API connection is authenticated, but its events are explicitly synthetic demonstration data."
              : "Read-only collection from the authenticated application's security-events API."}{" "}
            Events are fetched manually. This does not measure website
            availability or permit remote commands. Checks become stale after 5
            minutes; offline may mean no recent check.
          </p>
        </div>
        <div className="source-facts">
          <div>
            <span>Last successful connection</span>
            <strong>{date(current.last_success_at)}</strong>
          </div>
          <div>
            <span>Last event received</span>
            <strong>
              {current.last_event_received_at
                ? date(current.last_event_received_at)
                : current.event_count
                  ? "Receipt time unavailable for older events"
                  : "Not received"}
            </strong>
          </div>
          <div>
            <span>Security events</span>
            <strong>
              {current.event_count}{" "}
              <small>· {current.threat_count} suspicious</small>
            </strong>
          </div>
        </div>
        <div className="source-permissions">
          <div>
            <h3>Granted permissions</h3>
            <p>
              {current.granted_permissions.join(", ") ||
                "No active permissions"}
            </p>
          </div>
          <div>
            <h3>Enabled event categories</h3>
            <div className="category-tags">
              {current.enabled_categories.map((category) => (
                <span key={category}>{categoryLabel(category)}</span>
              ))}
            </div>
          </div>
        </div>
        {current.error && (
          <div role="status" className="banner error">
            {current.error}
          </div>
        )}
        <div className="source-actions">
          <button
            className="button subtle"
            disabled={!!busy || revoked}
            onClick={() => void action("test")}
          >
            <RefreshCw size={14} />
            {busy === "test" ? "Testing…" : "Test Connection"}
          </button>
          <button
            className="button primary"
            disabled={!!busy || revoked || disconnected}
            onClick={() => void action("poll")}
          >
            <Download size={14} />
            {busy === "poll" ? "Fetching…" : "Fetch events"}
          </button>
          <button
            className="button subtle"
            disabled={!!busy || revoked}
            onClick={() => {
              setEnabled(current.enabled_categories);
              setError("");
              setDialog("permissions");
            }}
          >
            Edit Permissions
          </button>
          {disconnected ? (
            <button
              className="button subtle"
              disabled={!!busy}
              onClick={() => void action("resume")}
            >
              Resume connection
            </button>
          ) : (
            <button
              className="button subtle"
              disabled={!!busy || revoked}
              onClick={() => {
                setError("");
                setDialog("disconnect");
              }}
            >
              <Unplug size={14} />
              Disconnect
            </button>
          )}
          <button
            className="button subtle danger-text"
            disabled={!!busy || revoked}
            onClick={() => {
              setError("");
              setDialog("revoke");
            }}
          >
            <KeyRound size={14} />
            Revoke Credentials
          </button>
        </div>
        {notice && (
          <p role="status" className="source-notice">
            {notice}
          </p>
        )}
        {error && !dialog && (
          <div role="alert" className="banner error">
            {error}
          </div>
        )}
      </section>
      <section className="panel">
        <div className="panel-heading">
          <h2>
            <Shield size={16} /> Related incidents{" "}
            <span className="count">
              {currentDetail?.incidents.length || 0}
            </span>
          </h2>
        </div>
        {currentDetail?.incidents.length ? (
          currentDetail.incidents.map((incident) => (
            <button
              key={incident.id}
              className="server-incident"
              onClick={() => reviewIncident(incident.id)}
            >
              <span className={`badge ${incident.severity}`}>
                {incident.severity}
              </span>
              <strong>{incident.title}</strong>
              <span>{incident.status}</span>
              <ArrowUpRight size={15} />
            </button>
          ))
        ) : (
          <div className="chart-empty">
            No correlated incidents for this website source.
          </div>
        )}
      </section>
      <section className="panel">
        <div className="panel-heading">
          <h2>
            Website security events{" "}
            <span className="count">{currentDetail?.events.length || 0}</span>
          </h2>
          <span className="muted">
            {current.mode === "simulated"
              ? "Synthetic API feed"
              : "Authorized API telemetry"}
          </span>
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
              {currentDetail?.events.map((event) => (
                <tr key={event.id}>
                  <td>
                    {date(event.timestamp)}
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
        {!currentDetail?.events.length && (
          <div className="chart-empty">
            No events collected. Use Fetch events after connection; successful
            authentication alone does not create telemetry.
          </div>
        )}
      </section>
      <Modal
        open={!!dialog}
        onDismiss={() => {
          if (!busy) setDialog(null);
        }}
        labelledBy="source-action-title"
      >
        <div className="dialog-heading">
          <span className="dialog-icon">
            <KeyRound size={24} />
          </span>
          <button
            aria-label="Close source settings"
            disabled={!!busy}
            onClick={() => setDialog(null)}
          >
            <X size={20} />
          </button>
        </div>
        <h2 id="source-action-title">
          {dialog === "permissions"
            ? "Edit event permissions"
            : dialog === "revoke"
              ? "Revoke stored credentials?"
              : "Disconnect this source?"}
        </h2>
        <p>
          {dialog === "permissions"
            ? "Choose among categories made available by the authenticated API. These controls narrow collection; they cannot grant additional permissions at the provider."
            : dialog === "revoke"
              ? "Permanently delete this source's stored API key and stop collection. Revoke the key at your application too if it should no longer be valid there. Historical evidence is retained."
              : "Pause event collection while retaining encrypted credentials and historical evidence. Resume requires a fresh authentication check."}
        </p>
        <p>
          <strong>{current.name}</strong>
        </p>
        {dialog === "permissions" && (
          <fieldset className="source-categories" disabled={!!busy}>
            <legend>Available event categories</legend>
            {current.available_categories.map((category) => (
              <label key={category} className="checkbox-label">
                <input
                  type="checkbox"
                  checked={enabled.includes(category)}
                  onChange={(e) =>
                    setEnabled(
                      e.target.checked
                        ? [...enabled, category]
                        : enabled.filter((value) => value !== category),
                    )
                  }
                />
                {categoryLabel(category)}
              </label>
            ))}
            <p>Granted: {current.granted_permissions.join(", ") || "None"}</p>
          </fieldset>
        )}
        {error && (
          <div role="alert" className="banner error">
            {error}
          </div>
        )}
        <div className="dialog-actions">
          <button
            className="button subtle"
            disabled={!!busy}
            onClick={() => setDialog(null)}
          >
            Cancel
          </button>
          <button
            className="button primary"
            disabled={!!busy || (dialog === "permissions" && !enabled.length)}
            onClick={() =>
              void action(
                dialog || "",
                dialog === "permissions" ? { categories: enabled } : {},
              )
            }
          >
            {busy
              ? "Saving…"
              : dialog === "permissions"
                ? "Save permissions"
                : dialog === "revoke"
                  ? "Confirm revoke credentials"
                  : "Confirm disconnect"}
          </button>
        </div>
      </Modal>
    </div>
  );
}
