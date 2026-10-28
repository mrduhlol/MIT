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
