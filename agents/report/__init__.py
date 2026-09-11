import json
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Template

from agents.base_agent import BaseAgent, Finding, Severity


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment Report - {{ target }}</title>
<style>
  :root {
    --critical: #dc2626; --high: #ea580c; --medium: #d97706;
    --low: #65a30d; --info: #2563eb; --bg: #0f172a; --card: #1e293b;
    --text: #e2e8f0; --muted: #94a3b8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; padding: 2rem; }
  h1 { font-size: 2rem; margin-bottom: 0.5rem; }
  .subtitle { color: var(--muted); margin-bottom: 2rem; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .meta-card { background: var(--card); border-radius: 8px; padding: 1rem; }
  .meta-card .label { color: var(--muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.1em; }
  .meta-card .value { font-size: 1.5rem; font-weight: bold; margin-top: 0.25rem; }
  .critical { color: var(--critical); } .high { color: var(--high); }
  .medium { color: var(--medium); } .low { color: var(--low); } .info { color: var(--info); }
  .badge {
    display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem;
    font-weight: bold; text-transform: uppercase;
  }
  .badge.Critical { background: #fee2e2; color: var(--critical); }
  .badge.High { background: #ffedd5; color: var(--high); }
  .badge.Medium { background: #fef3c7; color: var(--medium); }
  .badge.Low { background: #ecfccb; color: var(--low); }
  .badge.Info { background: #dbeafe; color: var(--info); }
  .section { margin-bottom: 2rem; }
  .section h2 { font-size: 1.25rem; margin-bottom: 1rem; border-bottom: 1px solid #334155; padding-bottom: 0.5rem; }
  .finding { background: var(--card); border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; border-left: 4px solid; }
  .finding.Critical { border-color: var(--critical); }
  .finding.High { border-color: var(--high); }
  .finding.Medium { border-color: var(--medium); }
  .finding.Low { border-color: var(--low); }
  .finding.Info { border-color: var(--info); }
  .finding-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
  .finding-title { font-weight: 600; font-size: 1rem; flex: 1; }
  .finding-agent { color: var(--muted); font-size: 0.8rem; background: #0f172a; padding: 0.2rem 0.5rem; border-radius: 4px; }
  .detail-label { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.75rem; margin-bottom: 0.25rem; }
  .detail-text { font-size: 0.9rem; line-height: 1.6; }
  .evidence { background: #0f172a; border-radius: 4px; padding: 0.75rem; font-family: monospace; font-size: 0.8rem; white-space: pre-wrap; word-break: break-all; max-height: 300px; overflow-y: auto; }
  .summary-analysis { background: var(--card); border-radius: 8px; padding: 1.5rem; line-height: 1.8; }
  .chart-bar { display: flex; align-items: center; gap: 1rem; margin-bottom: 0.5rem; }
  .chart-bar .label { width: 80px; font-size: 0.9rem; }
  .chart-bar .bar { height: 20px; border-radius: 3px; min-width: 4px; transition: width 0.3s; }
  .chart-bar .count { font-weight: bold; }
</style>
</head>
<body>
<h1>Security Assessment Report</h1>
<p class="subtitle">Target: <strong>{{ target }}</strong> &mdash; Generated {{ generated_at }}</p>

<div class="meta">
  <div class="meta-card"><div class="label">Total Findings</div><div class="value">{{ findings|length }}</div></div>
  <div class="meta-card"><div class="label">Critical</div><div class="value critical">{{ counts.Critical }}</div></div>
  <div class="meta-card"><div class="label">High</div><div class="value high">{{ counts.High }}</div></div>
  <div class="meta-card"><div class="label">Medium</div><div class="value medium">{{ counts.Medium }}</div></div>
  <div class="meta-card"><div class="label">Low / Info</div><div class="value info">{{ counts.Low + counts.Info }}</div></div>
  <div class="meta-card"><div class="label">Risk Score</div><div class="value {% if risk_score >= 80 %}critical{% elif risk_score >= 50 %}high{% elif risk_score >= 25 %}medium{% else %}low{% endif %}">{{ risk_score }}/100</div></div>
</div>

{% if counts.Critical > 0 or counts.High > 0 %}
<div class="section">
  <h2>Severity Distribution</h2>
  {% for sev, color in [("Critical","critical"),("High","high"),("Medium","medium"),("Low","low"),("Info","info")] %}
  {% if counts[sev] > 0 %}
  <div class="chart-bar">
    <div class="label {{ color }}">{{ sev }}</div>
    <div class="bar {{ color }}" style="width: {{ [counts[sev] * 30, 600]|min }}px; background: var(--{{ color }});"></div>
    <div class="count">{{ counts[sev] }}</div>
  </div>
  {% endif %}
  {% endfor %}
</div>
{% endif %}

{% if executive_summary %}
<div class="section">
  <h2>Executive Summary</h2>
  <div class="summary-analysis">{{ executive_summary | replace('\n', '<br>') }}</div>
</div>
{% endif %}

{% for sev in ["Critical", "High", "Medium", "Low", "Info"] %}
{% set sev_findings = findings | selectattr("severity", "equalto", sev) | list %}
{% if sev_findings %}
<div class="section">
  <h2>{{ sev }} Severity Findings ({{ sev_findings|length }})</h2>
  {% for f in sev_findings %}
  <div class="finding {{ sev }}">
    <div class="finding-header">
      <span class="badge {{ sev }}">{{ sev }}</span>
      <span class="finding-title">{{ f.title }}</span>
      <span class="finding-agent">{{ f.agent }}</span>
    </div>
    <div class="detail-label">Description</div>
    <div class="detail-text">{{ f.description }}</div>
    {% if f.url %}
    <div class="detail-label">URL</div>
    <div class="detail-text"><a href="{{ f.url }}" style="color: var(--info);">{{ f.url }}</a></div>
    {% endif %}
    <div class="detail-label">Evidence</div>
    <div class="evidence">{{ f.evidence[:1500] }}</div>
    <div class="detail-label">Remediation</div>
    <div class="detail-text">{{ f.remediation }}</div>
  </div>
  {% endfor %}
</div>
{% endif %}
{% endfor %}

<footer style="color: var(--muted); font-size: 0.8rem; margin-top: 3rem; text-align: center;">
  Generated by AI-Powered Penetration Testing Platform &middot; For authorized use only
</footer>
</body>
</html>"""


class ReportAgent(BaseAgent):
    name = "Report Generator"
    description = "Aggregates all findings into a comprehensive security report"

    def __init__(self, target: str, client, all_findings: list[Finding], output_dir: str = "."):
        super().__init__(target, client)
        self.all_findings = all_findings
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def run(self) -> list[Finding]:
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._run_sync)

    def _run_sync(self) -> list[Finding]:
        counts = {s.value: 0 for s in Severity}
        for f in self.all_findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        # Risk score: Critical=10pts, High=5pts, Medium=2pts, Low=1pt each (capped at 100)
        raw_score = (
            counts.get("Critical", 0) * 10 +
            counts.get("High", 0) * 5 +
            counts.get("Medium", 0) * 2 +
            counts.get("Low", 0) * 1
        )
        risk_score = min(raw_score, 100)

        # Ask Claude to write executive summary
        finding_summary = "\n".join(
            f"[{f.severity.value}] {f.agent}: {f.title}"
            for f in self.all_findings
            if f.severity.value in ["Critical", "High"]
        )

        executive_summary = self._ask_claude(
            system=(
                "You are a senior penetration tester writing an executive summary for a security audit report. "
                "Be clear, professional, and actionable. Write for a technical audience. "
                "Prioritize the most critical issues. Use plain text, no markdown."
            ),
            user=(
                f"Target: {self.target}\n"
                f"Total findings: {len(self.all_findings)}\n"
                f"Severity counts: {counts}\n"
                f"Risk score: {risk_score}/100\n\n"
                f"Critical and High findings:\n{finding_summary}\n\n"
                "Write a 3-5 paragraph executive summary that:\n"
                "1. Describes the overall security posture\n"
                "2. Highlights the most critical vulnerabilities and their business impact\n"
                "3. Provides prioritized remediation recommendations\n"
                "4. States the risk to the organization if issues are not addressed"
            ),
            max_tokens=2048,
        )

        generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        # Sort findings by severity
        sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        sorted_findings = sorted(
            self.all_findings,
            key=lambda f: sev_order.get(f.severity.value, 99)
        )

        # ---- Markdown report ----
        md_path = self.output_dir / f"report_{timestamp}.md"
        md = self._build_markdown(sorted_findings, counts, risk_score, executive_summary, generated_at)
        md_path.write_text(md, encoding="utf-8")

        # ---- JSON report ----
        json_path = self.output_dir / f"report_{timestamp}.json"
        json_data = {
            "target": self.target,
            "generated_at": generated_at,
            "risk_score": risk_score,
            "severity_counts": counts,
            "executive_summary": executive_summary,
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "agent": f.agent,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "url": f.url,
                    "parameter": f.parameter,
                    "extra": f.extra,
                }
                for f in sorted_findings
            ],
        }
        json_path.write_text(json.dumps(json_data, indent=2, default=str), encoding="utf-8")

        # ---- HTML report ----
        html_path = self.output_dir / f"report_{timestamp}.html"
        tmpl = Template(_HTML_TEMPLATE)
        html = tmpl.render(
            target=self.target,
            generated_at=generated_at,
            findings=[
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "agent": f.agent,
                    "description": f.description,
                    "evidence": f.evidence,
                    "remediation": f.remediation,
                    "url": f.url,
                }
                for f in sorted_findings
            ],
            counts=counts,
            risk_score=risk_score,
            executive_summary=executive_summary,
        )
        html_path.write_text(html, encoding="utf-8")

        return {
            "markdown": str(md_path),
            "json": str(json_path),
            "html": str(html_path),
            "risk_score": risk_score,
            "counts": counts,
            "executive_summary": executive_summary,
        }

    def _build_markdown(self, findings, counts, risk_score, summary, generated_at) -> str:
        lines = [
            f"# Security Assessment Report",
            f"",
            f"**Target:** {self.target}  ",
            f"**Generated:** {generated_at}  ",
            f"**Risk Score:** {risk_score}/100  ",
            f"",
            f"## Severity Summary",
            f"",
            f"| Severity | Count |",
            f"|----------|-------|",
        ]
        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            lines.append(f"| {sev} | {counts.get(sev, 0)} |")

        lines += ["", "## Executive Summary", "", summary, ""]

        for sev in ["Critical", "High", "Medium", "Low", "Info"]:
            sev_findings = [f for f in findings if f.severity.value == sev]
            if not sev_findings:
                continue
            lines.append(f"## {sev} Severity Findings ({len(sev_findings)})")
            lines.append("")
            for f in sev_findings:
                lines += [
                    f"### [{sev}] {f.title}",
                    f"",
                    f"**Agent:** {f.agent}  ",
                    f"**URL:** {f.url or 'N/A'}  ",
                    f"",
                    f"**Description:**  ",
                    f.description,
                    f"",
                    f"**Evidence:**",
                    f"```",
                    f.evidence[:1000],
                    f"```",
                    f"",
                    f"**Remediation:**  ",
                    f.remediation,
                    f"",
                    "---",
                    "",
                ]

        return "\n".join(lines)
