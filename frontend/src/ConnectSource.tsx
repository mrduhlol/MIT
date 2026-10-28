import { useEffect, useRef, useState } from "react";
import {
  ArrowLeft,
  ArrowRight,
  CheckCircle2,
  Cloud,
  FlaskConical,
  Globe,
  KeyRound,
  Server,
  ShieldCheck,
  Users,
  X,
} from "lucide-react";
import Modal from "./Modal";

export const categories = [
  ["authentication", "Authentication events"],
  ["suspicious_sessions", "Suspicious sessions"],
  ["account_changes", "Account changes"],
  ["application_security", "Application security events"],
] as const;
export const categoryLabel = (value: string) =>
  categories.find(([id]) => id === value)?.[1] || value;
export type Source = {
  id: string;
  name: string;
  type: "website" | "linux" | "simulated";
  mode: string;
  status: string;
  available_categories: string[];
  granted_permissions: string[];
  enabled_categories: string[];
  last_success_at: string | null;
  last_event_at: string | null;
  last_event_received_at?: string | null;
  last_heartbeat_at: string | null;
  event_count: number;
  threat_count: number;
  incident_ids: string[];
  error: string | null;
  base_url?: string;
  events_url?: string;
  hostname?: string;
};
type Kind = Source["type"] | "cloud" | "identity";
const integrations = [
  {
    id: "website",
    name: "Website / Web Application",
    icon: Globe,
    description:
      "Read authorized security events through your application's API.",
    telemetry: "Authentication · sessions · account changes",
    method: "API key",
  },
  {
    id: "linux",
    name: "Linux Server",
    icon: Server,
    description: "Enroll an outbound-only agent on a Linux host you manage.",
    telemetry: "CPU · memory · opt-in security logs",
    method: "One-time enrollment",
  },
  {
    id: "cloud",
    name: "Cloud Infrastructure",
    icon: Cloud,
    description: "Provider audit and infrastructure activity connectors.",
    telemetry: "AWS · Azure · Google Cloud",
    method: "Not available",
  },
  {
    id: "identity",
    name: "Identity Provider",
    icon: Users,
    description:
      "Provider sign-in, identity, and account lifecycle connectors.",
    telemetry: "Microsoft Entra ID · Okta",
    method: "Not available",
  },
  {
    id: "simulated",
    name: "Simulated Demo Source",
    icon: FlaskConical,
    description: "Exercise enrollment and detections with a synthetic agent.",
    telemetry: "Synthetic metrics and security events only",
    method: "Local demo",
  },
] as const;
export default function ConnectSource({
  open,
  onClose,
  request,
  onEnrollment,
  onConnected,
}: {
  open: boolean;
  onClose: () => void;
  request: (path: string, body?: unknown) => Promise<any>;
  onEnrollment: (result: any) => void;
  onConnected: (id: string) => void;
}) {
  const [kind, setKind] = useState<Kind | null>(null);
  const [name, setName] = useState("");
  const [hostname, setHostname] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [endpoint, setEndpoint] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [enabled, setEnabled] = useState<string[]>(["authentication"]);
  const [validation, setValidation] = useState<{
    available_categories: string[];
    granted_permissions: string[];
    event_count: number;
    mode: string;
  } | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const formRef = useRef<HTMLFormElement>(null);
  const backRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (open && kind)
      (
        formRef.current?.querySelector<HTMLInputElement>("input") ||
        backRef.current
      )?.focus({ preventScroll: true });
  }, [kind, open]);
  useEffect(() => {
    if (!open) {
      setKind(null);
      setApiKey("");
      setValidation(null);
      return;
    }
    setKind(null);
    setName("");
    setHostname("");
    setBaseUrl("");
    setEndpoint("");
    setApiKey("");
    setEnabled(["authentication"]);
    setValidation(null);
    setError("");
  }, [open]);
  function change(work: () => void) {
    work();
    setValidation(null);
    setError("");
  }
  const close = () => {
    if (!busy) {
      setApiKey("");
      onClose();
    }
  };
  const payload = () => ({
    name: name.trim(),
    base_url: baseUrl.trim(),
    events_url: endpoint.trim(),
    api_key: apiKey,
    categories: enabled,
  });
  async function run(action: "test" | "save" | "enroll") {
    if (
      !formRef.current?.reportValidity() ||
      (!enabled.length && kind === "website")
    )
      return;
    setBusy(action);
    setError("");
    try {
      if (action === "test")
        setValidation(await request("/sources/website/test", payload()));
      else if (action === "save") {
        const result = await request("/sources/website", payload());
        setApiKey("");
        onConnected(result.source.id);
        onClose();
      } else {
        const result = await request("/servers", {
          name: name.trim(),
          hostname: hostname.trim(),
          mode: kind === "simulated" ? "simulated" : "real",
        });
        onEnrollment(result);
        onClose();
      }
    } catch (e) {
      setError((e as Error).message);
      setValidation(null);
    } finally {
      setBusy("");
    }
  }
  const selected = integrations.find((item) => item.id === kind);
  return (
    <Modal
      open={open}
      onDismiss={close}
      labelledBy="add-server-title"
      className={`connect-source-dialog server-dialog ${kind ? "source-setup-dialog" : ""}`}
      dismissOnBackdrop={
        !name && !hostname && !baseUrl && !endpoint && !apiKey && !busy
      }
    >
      <div className="dialog-heading">
        {kind ? (
          <button
            type="button"
            className="source-back"
            ref={backRef}
            disabled={!!busy}
            onClick={() => {
              setKind(null);
              setApiKey("");
              setValidation(null);
              setError("");
            }}
          >
            <ArrowLeft size={16} /> All integrations
          </button>
        ) : (
          <span className="dialog-icon">
            <LinkIcon />
          </span>
        )}
        <button
          type="button"
          aria-label="Close Connect Data Source"
          disabled={!!busy}
          onClick={close}
        >
          <X size={20} />
        </button>
      </div>
      <h2 id="add-server-title">
        {selected ? selected.name : "Connect Data Source"}
      </h2>
      {!kind ? (
        <>
          <p>
            Choose what you want to monitor. Each source uses its own
            authorization and sends only supported telemetry.
          </p>
          <div className="integration-grid">
            {integrations.map(
              ({
                id,
                name: title,
                icon: Icon,
                description,
                telemetry,
                method,
              }) => (
                <button
                  type="button"
                  key={id}
                  className={`integration-option ${id === "simulated" ? "demo-option" : ""}`}
                  aria-label={title}
                  onClick={() => setKind(id)}
                >
                  <span className="integration-icon">
                    <Icon size={22} />
                  </span>
                  <span className="integration-copy">
                    <strong>{title}</strong>
                    <span>{description}</span>
                    <small>{telemetry}</small>
                    <span
                      className={`integration-method ${id === "cloud" || id === "identity" ? "unavailable" : ""}`}
                    >
                      {method}
                    </span>
                  </span>
                  <ArrowRight size={16} className="integration-arrow" />
                </button>
              ),
            )}
          </div>
          <p className="source-security-note">
            <ShieldCheck size={15} /> Read-only telemetry. Containment stays
            simulated and requires approval.
          </p>
        </>
      ) : kind === "cloud" || kind === "identity" ? (
        <div className="unsupported-source">
          <span className="server-status pending">Not implemented</span>
          <p>
            {kind === "cloud"
              ? "AWS, Azure, and Google Cloud connectors are not available in this build. No cloud account authorization or audit-log collection is configured."
              : "Microsoft Entra ID and Okta connectors are not available in this build. No OAuth application or identity-provider authorization is configured."}
          </p>
          <h3>Authorization must come from the provider</h3>
          <p>
            {kind === "cloud"
              ? "A future connector must use a provider-supported role or OAuth flow and request only the audit-log read scopes selected by the operator."
              : "A future connector must use the provider's official OAuth flow and request only the sign-in or identity-event read scopes selected by the operator."}
          </p>
          <p>
            No permissions are requested or granted here. Use a supported
            website API or Linux agent integration instead.
          </p>
          <button className="button primary" onClick={() => setKind(null)}>
            Choose a supported integration
          </button>
        </div>
      ) : (
        <form
          ref={formRef}
          onSubmit={(e) => {
            e.preventDefault();
            void run(
              kind === "website" ? (validation ? "save" : "test") : "enroll",
            );
          }}
        >
          <p>
            {kind === "website"
              ? "Connect an HTTPS security-events endpoint implementing the documented SOC API contract. A URL alone does not establish a connection."
              : kind === "linux"
                ? "Register this host, then install and enroll the read-only Linux agent. The source stays pending until an authenticated heartbeat arrives."
                : "Enroll a simulated agent to generate clearly labeled synthetic telemetry. It does not read host metrics or system logs."}
          </p>
          <fieldset disabled={!!busy} className="source-fields">
            <label>
              {kind === "website" ? "Website name" : "Server name"}
              <input
                required
                maxLength={80}
                value={name}
                onChange={(e) => change(() => setName(e.target.value))}
                placeholder={
                  kind === "website"
                    ? "Customer portal"
                    : kind === "simulated"
                      ? "SOC training host"
                      : "Production web server"
                }
              />
            </label>
            {kind !== "website" ? (
              <label>
                Hostname
                <input
                  required
                  maxLength={253}
                  pattern="[A-Za-z0-9][A-Za-z0-9._-]*"
                  value={hostname}
                  onChange={(e) => setHostname(e.target.value)}
                  placeholder={kind === "simulated" ? "demo-01" : "web-01"}
                />
                <small>Use the same hostname when enrolling the agent.</small>
              </label>
            ) : (
              <>
                <label>
                  Base URL
                  <input
                    required
                    type="url"
                    maxLength={2048}
                    value={baseUrl}
                    onChange={(e) => change(() => setBaseUrl(e.target.value))}
                    placeholder="https://app.example.com"
                  />
                </label>
                <label>
                  Security-events API endpoint
                  <input
                    required
                    type="url"
                    maxLength={2048}
                    value={endpoint}
                    onChange={(e) => change(() => setEndpoint(e.target.value))}
                    placeholder="https://app.example.com/api/security-events"
                  />
                  <small>
                    Must expose authenticated permissions and events in the SOC
                    connector format. Public HTML pages are not supported.
                  </small>
                </label>
                <div className="source-auth-method">
                  <KeyRound size={16} />
                  <span>
                    <strong>API key authentication</strong>
                    <small>
                      Sent as a Bearer token over verified HTTPS. Webhooks are
                      not supported.
                    </small>
                  </span>
                </div>
                <label>
                  API key
                  <input
                    required
                    type="password"
                    autoComplete="new-password"
                    spellCheck={false}
                    maxLength={2048}
                    value={apiKey}
                    onChange={(e) => change(() => setApiKey(e.target.value))}
                    placeholder="Paste a read-only API credential"
                  />
                  <small>
                    Encrypted on the backend after saving. Never included in
                    installation commands or URLs.
                  </small>
                </label>
                <fieldset className="source-categories">
                  <legend>Events to collect</legend>
                  {categories.map(([id, title]) => (
                    <label className="checkbox-label" key={id}>
                      <input
                        type="checkbox"
                        checked={enabled.includes(id)}
                        onChange={(e) =>
                          change(() =>
                            setEnabled(
                              e.target.checked
                                ? [...enabled, id]
                                : enabled.filter((value) => value !== id),
                            ),
                          )
                        }
                      />
                      {title}
                    </label>
                  ))}
                </fieldset>
                {!enabled.length && (
                  <p role="alert" className="danger-text">
                    Select at least one event category.
                  </p>
                )}
              </>
            )}
          </fieldset>
          {validation && (
            <div className="source-validation" role="status">
              <h3>
                <CheckCircle2 size={17} /> Authentication verified
              </h3>
              <p>
                The endpoint authenticated this credential. Saving performs a
                fresh validation; use Fetch events after connecting to collect
                telemetry.
              </p>
              <dl>
                <dt>Telemetry provenance</dt>
                <dd>
                  {validation.mode === "simulated"
                    ? "Simulated — synthetic API events"
                    : "Real — authorized application events"}
                </dd>
                <dt>Available categories</dt>
                <dd>
                  {validation.available_categories
                    .map(categoryLabel)
                    .join(", ") || "None"}
                </dd>
                <dt>Granted permissions</dt>
                <dd>{validation.granted_permissions.join(", ") || "None"}</dd>
              </dl>
            </div>
          )}
          {error && (
            <div role="alert" className="banner error">
              {error}
            </div>
          )}
          {kind !== "website" && (
            <p className="source-security-note">
              <ShieldCheck size={15} />{" "}
              {kind === "simulated"
                ? "Synthetic source · separate from real telemetry"
                : "No SSH credentials or remote shell access"}
            </p>
          )}
          <div className="dialog-actions">
            <button
              type="button"
              className="button subtle"
              disabled={!!busy}
              onClick={close}
            >
              Cancel
            </button>
            {kind === "website" ? (
              <>
                <button
                  type="button"
                  className="button subtle"
                  disabled={!!busy || !enabled.length}
                  onClick={() => void run("test")}
                >
                  {busy === "test" ? "Testing…" : "Test Connection"}
                </button>
                <button
                  type="submit"
                  className="button primary"
                  disabled={!!busy || !validation}
                >
                  {busy === "save" ? "Connecting…" : "Save integration"}
                </button>
              </>
            ) : (
              <button
                type="submit"
                className="button primary"
                disabled={!!busy}
              >
                {busy === "enroll" ? "Registering…" : "Create server"}
              </button>
            )}
          </div>
        </form>
      )}
    </Modal>
  );
}
function LinkIcon() {
  return <ShieldCheck size={24} />;
}
