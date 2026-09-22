"""Экспорт результатов WebSocket-тестирования в JSON и HTML."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from typing import Any, Iterable


REPORTS_DIR = Path(__file__).resolve().parents[2] / "reports"


def build_report(
    results: Iterable[dict[str, Any]],
    connection: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
	"""Собрать сериализуемую структуру отчёта из результатов сканирования."""
	tests = [dict(result) for result in results]
	anomalies = [
		{
			"test": result.get("name", "unnamed"),
			"status": result.get("status", "unknown"),
			"details": result.get("error", "") or result.get("response_payload_text", ""),
		}
		for result in tests
		if result.get("status") not in {"response"}
	]
	return {
		"schema_version": "1.0",
		"generated_at": datetime.now(timezone.utc).isoformat(),
		"metadata": metadata or {},
		"connection": connection or {},
		"summary": {
			"total_tests": len(tests),
			"responses": sum(result.get("status") == "response" for result in tests),
			"anomalies": len(anomalies),
		},
		"tests": tests,
		"anomalies": anomalies,
	}


def _report_path(stem: str, suffix: str, output_dir: str | Path = REPORTS_DIR) -> Path:
	directory = Path(output_dir)
	directory.mkdir(parents=True, exist_ok=True)
	return directory / f"{stem}.{suffix}"


def export_json(report: dict[str, Any], stem: str = "ws-smuggler-report", output_dir: str | Path = REPORTS_DIR) -> Path:
	path = _report_path(stem, "json", output_dir)
	path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
	return path


def export_html(report: dict[str, Any], stem: str = "ws-smuggler-report", output_dir: str | Path = REPORTS_DIR) -> Path:
	"""Сохранить адаптивный HTML-отчёт с фильтрацией тестов."""
	path = _report_path(stem, "html", output_dir)
	rows = []
	for test in report.get("tests", []):
		status = escape(str(test.get("status", "unknown")))
		name = escape(str(test.get("name", "unnamed")))
		details = escape(str(test.get("error", "") or test.get("response_payload_text", "")))
		rows.append(
			f'<tr><td>{name}</td><td><span class="status status-{status}">{status}</span></td>'
			f"<td>{test.get('sent', 0)}</td><td>{test.get('received', 0)}</td><td>{details}</td></tr>"
		)
	connection = escape(json.dumps(report.get("connection", {}), ensure_ascii=False, indent=2))
	summary = report.get("summary", {})
	html = f'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>WS-Smuggler report</title><style>
:root {{ font-family: system-ui, sans-serif; background: #f4f7fb; color: #172033; }} body {{ margin: 0; padding: 2rem; }} main {{ max-width: 1100px; margin: auto; }}
.muted {{ color: #61708a; }} .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 1rem; margin: 1.5rem 0; }}
.card,.panel {{ background: white; border: 1px solid #d9e1ec; border-radius: 8px; padding: 1rem; margin-top: 1rem; }} .card strong {{ display: block; font-size: 1.8rem; }}
.panel {{ overflow-x: auto; }} input {{ width: min(100%, 360px); padding: .65rem; border: 1px solid #b8c5d8; border-radius: 6px; margin-bottom: 1rem; }}
table {{ border-collapse: collapse; width: 100%; }} th,td {{ text-align: left; padding: .7rem; border-bottom: 1px solid #e4e9f0; vertical-align: top; }} th {{ background: #edf3fa; }}
.status {{ font-weight: 700; }} .status-response {{ color: #137333; }} .status-closed,.status-timeout,.status-error {{ color: #b3261e; }} pre {{ white-space: pre-wrap; }}
@media (max-width: 600px) {{ body {{ padding: 1rem; }} th,td {{ padding: .5rem; font-size: .9rem; }} }}
</style></head><body><main><h1>WS-Smuggler scan report</h1>
<p class="muted">Generated: {escape(str(report.get('generated_at', '')))}</p><section class="cards">
<div class="card">Tests<strong>{summary.get('total_tests', 0)}</strong></div><div class="card">Responses<strong>{summary.get('responses', 0)}</strong></div><div class="card">Anomalies<strong>{summary.get('anomalies', 0)}</strong></div></section>
<section class="panel"><h2>Connection</h2><pre>{connection}</pre></section><section class="panel"><h2>Tests</h2>
<input id="filter" placeholder="Filter tests..." aria-label="Filter tests"><table><thead><tr><th>Test</th><th>Status</th><th>Sent</th><th>Received</th><th>Details</th></tr></thead><tbody id="tests">{''.join(rows)}</tbody></table></section>
</main><script>document.getElementById('filter').addEventListener('input', function () {{ const q = this.value.toLowerCase(); document.querySelectorAll('#tests tr').forEach(row => row.hidden = !row.textContent.toLowerCase().includes(q)); }});</script></body></html>'''
	path.write_text(html, encoding="utf-8")
	return path


def export_report(results: Iterable[dict[str, Any]], connection: dict[str, Any] | None = None, metadata: dict[str, Any] | None = None, stem: str = "ws-smuggler-report", output_dir: str | Path = REPORTS_DIR) -> tuple[Path, Path]:
	report = build_report(results, connection=connection, metadata=metadata)
	return export_json(report, stem, output_dir), export_html(report, stem, output_dir)
