# Defense operations design

The interface is an operational SOC workspace: investigation and individual approval lead the experience. Navy surfaces, muted slate borders, and restrained mint selection establish a calm dark environment; red and amber are reserved for severity. Evidence and timelines remain readable before decorative elements.

- Desktop: fixed navigation rail, summary metrics, incident queue beside an investigation detail pane, then response approvals and live telemetry.
- Mobile: compact top navigation, horizontally scrollable incident queue, stacked investigation and approval panels.
- Type: system sans-serif with monospace identifiers and timestamps. 30px page titles, 16px section headings, 11–14px working text.
- All simulated action approvals open a native modal dialog with an explicit checkbox, analyst identity, and decision reason. Rejection has a separate confirmation.
- Empty, loading, API error, pending, rejected, and verified response states are represented.
- Model outputs and holdout metrics are labeled synthetic and uncalibrated. No visual claims of production security or AI-authorship detection.

## Agent overview extension

The default overview adds a read-only synthetic patrol control surface while preserving the incident-first investigation and approval flow. All charts use backend analytics anchored to the latest fixture event; labels never imply a real website collector. Patrol duration and backend uptime are measured values, explicitly separated from website health.

- Four SVG chart views: event/suspicious activity, source distribution bars, network egress, and measured patrol duration. Interactive data points support pointer hover and keyboard focus; event and network values have a tabular alternative.
- Scheduling uses an interval select plus explicit pause/resume. Run patrol triggers an investigation, never automatic containment. Errors and failures remain visible.
- Log exploration adds severity filtering, a pauseable display snapshot, and JSON/CSV export of the filtered rows. CSV cells neutralize spreadsheet formula prefixes.
- Responsive overview stacks the chart panels and source coverage on smaller screens while keeping controls and tabular data usable.

## Connected server monitoring

Servers extends the same operational shell with outbound agent enrollment and host monitoring. Each registered host carries a visible Simulated agent or Linux agent label. CPU, memory, load, and uptime remain unknown until a sample arrives; stale/offline readings are explicitly historical. A website URL is only a reference and never implies an availability check.

- Add Server opens a native registration dialog. The returned enrollment token is held only in component state, displayed once, and cleared when instructions close. Commands use an interactive token prompt instead of embedding secrets.
- Host resource charts use only submitted history and include keyboard-focusable sample points plus a data table.
- Revoke and rotate require separate confirmations, explaining that they change ingestion credentials rather than running host commands or containment.
- Related incidents open the existing evidence/approval flow. Aggregate pages label their mixed fixture/agent inputs; benchmark accuracy remains explicitly synthetic.

## Shared modal interaction

All five dialogs use `Modal.tsx`: a native `showModal()` dialog portaled to `document.body`. Fixed viewport insets with explicit auto margins undo the Tailwind margin reset, while the browser top layer prevents dashboard clipping or stacking interference. Shared dynamic viewport height limits keep long content internally scrollable.

The backdrop dims independently with 5px blur and a translucent fallback; dialog fade/scale and backdrop fade take 200ms and are disabled for reduced motion. Native inertness plus a keyboard wrap keep focus within the active dialog. A shared lifecycle locks background scrolling, restores scroll/style/focus, and supports dialog handoffs without losing the original trigger. Untouched registration and idle reset dialogs allow backdrop dismissal; filled registration, one-time enrollment, and response/credential confirmations require an explicit close or Escape.

## Connect Data Source

The source-connection flow extends the existing SOC visual system. A centered, scrollable dialog opens on five integration choices; each identifies its telemetry and authorization method before requesting any inputs. Website API keys, Linux enrollment, and synthetic agents each have a distinct setup form. Cloud and identity-provider choices explicitly explain their unavailable state and never request credentials.

Website setup separates testing from saving and displays authenticated category capabilities and granted permissions. Changing connection settings invalidates the visible validation result. Secrets stay in transient input state and clear on dismissal or successful connection. The source workspace combines website APIs, Linux hosts, and synthetic agents in one selectable list while retaining the host charts and incident investigation flow. Website collection is explicitly manual; synthetic API feeds are labeled separately from real application events. Permission edits narrow available categories without implying additional provider grants.

## Simplified everyday controls

The overview leads with security status, a manual patrol, and incident review. Navigation uses Overview, Data sources, Incidents, Logs, Model results, and Action history. Demo replay/reset controls live in a disclosure instead of competing with everyday actions. Patrol scheduling and detailed activity charts/tables remain available in separately labeled disclosures, closed by default. Data sources omits the unrelated global incident metrics. Approval dialogs and source provenance remain intact.
