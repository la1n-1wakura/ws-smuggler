"""Экспорт результатов WebSocket-тестирования в JSON и HTML."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
from typing import Any, Iterable
import re
import uuid


REPORTS_DIR = Path(__file__).resolve().parents[2] / "reports"


def build_report(
    results: Iterable[dict[str, Any]],
    connection: dict[str, Any] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
	"""Собрать сериализуемую структуру отчёта из результатов сканирования."""
	tests = [dict(result) for result in results]
	run_id = str((metadata or {}).get("run_id") or uuid.uuid4().hex)
	status_counts: dict[str, int] = {}
	for result in tests:
		status = str(result.get("actual_status", result.get("status", "unknown")))
		status_counts[status] = status_counts.get(status, 0) + 1
	anomalies = [
		{
			"test": result.get("name", "unnamed"),
			"status": result.get("status", "unknown"),
			"details": result.get("error", "") or result.get("response_payload_text", ""),
		}
		for result in tests
		if result.get("status") not in {"response"} or result.get("matches_expected") is False
	]
	return {
		"schema_version": "1.0",
		"run_id": run_id,
		"generated_at": datetime.now(timezone.utc).isoformat(),
		"metadata": metadata or {},
		"connection": connection or {},
		"summary": {
			"total_tests": len(tests),
			"status_counts": status_counts,
			"sent_bytes": sum(int(result.get("sent", 0)) for result in tests),
			"received_bytes": sum(int(result.get("received", 0)) for result in tests),
			"timeouts": status_counts.get("timeout", 0),
			"protocol_closes": sum(result.get("response_opcode") == 8 for result in tests),
			"successful_responses": status_counts.get("response", 0),
			"responses": status_counts.get("response", 0),
			"anomalies": len(anomalies),
			"anomaly_percentage": round(len(anomalies) / len(tests) * 100, 2) if tests else 0.0,
		},
		"tests": tests,
		"anomalies": anomalies,
	}


def _report_path(stem: str, suffix: str, output_dir: str | Path = REPORTS_DIR) -> Path:
	directory = Path(output_dir)
	directory.mkdir(parents=True, exist_ok=True)
	base_path = directory / f"{stem}.{suffix}"
	if not base_path.exists():
		return base_path
	for index in range(2, 10000):
		candidate = directory / f"{stem}-{index}.{suffix}"
		if not candidate.exists():
			return candidate
	raise FileExistsError("could not allocate a unique report filename")


def _safe_name(value: str) -> str:
	return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "report"


def report_stem(report: dict[str, Any]) -> str:
	generated = str(report.get("generated_at", ""))[:19].replace(":", "").replace("-", "")
	configuration = report.get("metadata", {}).get("configuration", {})
	config_name = "-".join(str(configuration.get(key, "all")) for key in ("host", "port", "mode"))
	return f"ws-smuggler-{_safe_name(generated or 'run')}-{_safe_name(config_name)}-{_safe_name(str(report.get('run_id', 'run'))[:12])}"


def export_json(report: dict[str, Any], stem: str | None = None, output_dir: str | Path = REPORTS_DIR) -> Path:
	stem = stem or report_stem(report)
	path = _report_path(stem, "json", output_dir)
	path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
	return path


def export_html(report: dict[str, Any], stem: str | None = None, output_dir: str | Path = REPORTS_DIR, json_path: str | Path | None = None) -> Path:
	"""Сохранить адаптивный HTML-отчёт с фильтрацией тестов."""
	stem = stem or report_stem(report)
	path = _report_path(stem, "html", output_dir)
	json_href = Path(json_path).name if json_path else f"{stem}.json"
	rows = []
	for test in report.get("tests", []):
		status = escape(str(test.get("status", "unknown")))
		name = escape(str(test.get("name", "unnamed")))
		details = escape(str(test.get("error", "") or test.get("response_payload_text", "")))
		rows.append(
			f'<tr><td>{escape(str(test.get("experiment_id", name)))}</td><td>{name}</td>'
			f'<td><span class="status status-{status}">{status}</span></td>'
			f"<td>{test.get('duration_ms', '')}</td><td>{test.get('handshake_duration_ms', '')}</td>"
			f"<td>{test.get('response_wait_duration_ms', '')}</td><td>{test.get('sent', 0)}</td>"
			f"<td>{test.get('received', 0)}</td><td>{details}</td></tr>"
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
<div class="card">Tests<strong>{summary.get('total_tests', 0)}</strong></div><div class="card">Responses<strong>{summary.get('successful_responses', 0)}</strong></div><div class="card">Anomalies<strong>{summary.get('anomaly_percentage', 0)}%</strong></div><div class="card">Sent / received<strong>{summary.get('sent_bytes', 0)} / {summary.get('received_bytes', 0)}</strong></div></section>
<section class="panel"><h2>Connection</h2><p><a href="{escape(json_href)}">Open source JSON</a></p><pre>{connection}</pre></section><section class="panel"><h2>Tests</h2>
<input id="filter" placeholder="Filter tests..." aria-label="Filter tests"><table><thead><tr><th>Experiment</th><th>Test</th><th>Status</th><th>Duration ms</th><th>Handshake ms</th><th>Wait ms</th><th>Sent</th><th>Received</th><th>Details</th></tr></thead><tbody id="tests">{''.join(rows)}</tbody></table></section>
</main><script>document.getElementById('filter').addEventListener('input', function () {{ const q = this.value.toLowerCase(); document.querySelectorAll('#tests tr').forEach(row => row.hidden = !row.textContent.toLowerCase().includes(q)); }});</script></body></html>'''
	path.write_text(html, encoding="utf-8")
	return path


def load_report(path: str | Path) -> dict[str, Any]:
	return json.loads(Path(path).read_text(encoding="utf-8"))


def _anomaly_key(anomaly: dict[str, Any]) -> str:
	return ":".join(str(anomaly.get(field, "")) for field in ("experiment_id", "target_id", "test"))


def compare_reports(report_a: dict[str, Any], report_b: dict[str, Any]) -> dict[str, Any]:
	"""Сравнить статусы, аномалии и summary двух запусков."""
	anomalies_a = {_anomaly_key(item): item for item in report_a.get("anomalies", [])}
	anomalies_b = {_anomaly_key(item): item for item in report_b.get("anomalies", [])}
	added = [anomalies_b[key] for key in sorted(anomalies_b.keys() - anomalies_a.keys())]
	removed = [anomalies_a[key] for key in sorted(anomalies_a.keys() - anomalies_b.keys())]
	changed = [
		{"key": key, "before": anomalies_a[key], "after": anomalies_b[key]}
		for key in sorted(anomalies_a.keys() & anomalies_b.keys())
		if anomalies_a[key] != anomalies_b[key]
	]
	metrics = {}
	for key in sorted(set(report_a.get("summary", {})) | set(report_b.get("summary", {}))):
		before = report_a.get("summary", {}).get(key)
		after = report_b.get("summary", {}).get(key)
		if before != after:
			metrics[key] = {"before": before, "after": after}
	return {
		"from_run_id": report_a.get("run_id"),
		"to_run_id": report_b.get("run_id"),
		"new_anomalies": added,
		"removed_anomalies": removed,
		"changed_anomalies": changed,
		"metric_changes": metrics,
	}


def export_report(results: Iterable[dict[str, Any]], connection: dict[str, Any] | None = None, metadata: dict[str, Any] | None = None, stem: str | None = None, output_dir: str | Path = REPORTS_DIR) -> tuple[Path, Path]:
	report = build_report(results, connection=connection, metadata=metadata)
	json_path = export_json(report, stem, output_dir)
	return json_path, export_html(report, json_path.stem, output_dir, json_path=json_path)
