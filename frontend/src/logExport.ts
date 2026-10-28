/** Escape both CSV delimiters and spreadsheet formulas in untrusted telemetry. */
export function csvCell(value: unknown): string {
  const text =
    typeof value === "object" ? JSON.stringify(value) : String(value ?? "");
  const safe = /^[\s]*[=+@-]/.test(text) ? `'${text}` : text;
  return `"${safe.replaceAll('"', '""')}"`;
}
export function downloadLogs(
  rows: Record<string, unknown>[],
  format: "json" | "csv",
): void {
  const columns = [
    "id",
    "timestamp",
    "source",
    "identity",
    "host",
    "ip",
    "suspicious",
    "confidence",
    "details",
    "evidence",
  ];
  const content =
    format === "json"
      ? JSON.stringify(rows, null, 2)
      : [
          columns.map(csvCell).join(","),
          ...rows.map((row) =>
            columns.map((key) => csvCell(row[key])).join(","),
          ),
        ].join("\r\n");
  const url = URL.createObjectURL(
    new Blob([content], {
      type: format === "json" ? "application/json" : "text/csv;charset=utf-8",
    }),
  );
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `soc-telemetry-${new Date().toISOString().replaceAll(":", "-")}.${format}`;
  anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
