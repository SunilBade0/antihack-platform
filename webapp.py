"""
AntiHack Platform — Web Dashboard
FastAPI + WebSocket backend. Serves the browser UI with:
  - Scan launcher with authorization gate
  - Live scan output over WebSocket
  - Results viewer
  - Monaco-based code editor for all agent files
  - Scan history
"""
import asyncio
import json
import os
import sys
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

app = FastAPI(title="AntiHack Platform", description="AI-Powered Penetration Testing Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# In-memory scan history for this session
scan_history: list[dict] = []
active_scans: dict[str, dict] = {}  # scan_id -> {status, messages, result}


# ─────────────────────────── Static HTML ───────────────────────────────────

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AntiHack Platform</title>
<style>
  :root {
    --bg: #0f172a; --card: #1e293b; --card2: #263348;
    --accent: #6366f1; --accent2: #818cf8;
    --text: #e2e8f0; --muted: #94a3b8;
    --critical: #dc2626; --high: #ea580c; --medium: #d97706;
    --low: #65a30d; --info: #2563eb;
    --success: #16a34a; --danger: #dc2626;
    --border: #334155;
    --font-mono: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: system-ui, sans-serif; display: flex; flex-direction: column; min-height: 100vh; }
  a { color: var(--accent2); text-decoration: none; }
  a:hover { text-decoration: underline; }

  /* NAV */
  nav {
    background: var(--card); border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 0; padding: 0 1.5rem; height: 56px;
  }
  .nav-brand { font-weight: 700; font-size: 1.1rem; color: var(--accent2); margin-right: 2rem; }
  .nav-brand span { color: var(--text); }
  .nav-link {
    padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer;
    color: var(--muted); font-size: 0.9rem; transition: all 0.15s; border: none;
    background: none; display: flex; align-items: center; gap: 0.4rem;
  }
  .nav-link:hover, .nav-link.active { background: var(--card2); color: var(--text); }
  .nav-link.active { color: var(--accent2); }
  .nav-spacer { flex: 1; }
  .nav-badge { background: var(--accent); color: #fff; border-radius: 999px; font-size: 0.7rem; padding: 0.1rem 0.5rem; margin-left: 0.25rem; }

  /* PAGES */
  .page { display: none; flex: 1; padding: 2rem; max-width: 1200px; width: 100%; margin: 0 auto; }
  .page.active { display: block; }

  /* CARDS */
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; }
  .card-title { font-size: 1rem; font-weight: 600; margin-bottom: 1rem; color: var(--text); }

  /* FORMS */
  label { display: block; font-size: 0.85rem; color: var(--muted); margin-bottom: 0.35rem; }
  input[type="text"], input[type="password"], select {
    width: 100%; padding: 0.65rem 0.9rem; border-radius: 8px;
    background: var(--bg); border: 1px solid var(--border); color: var(--text);
    font-size: 0.95rem; transition: border-color 0.15s;
  }
  input:focus, select:focus { outline: none; border-color: var(--accent); }
  input::placeholder { color: var(--muted); }
  .form-row { margin-bottom: 1rem; }
  .form-hint { color: var(--muted); font-size: 0.78rem; margin-top: 0.35rem; }

  /* BUTTONS */
  .btn {
    padding: 0.65rem 1.4rem; border-radius: 8px; font-size: 0.95rem;
    cursor: pointer; border: none; font-weight: 600; transition: all 0.15s;
    display: inline-flex; align-items: center; gap: 0.5rem;
  }
  .btn-primary { background: var(--accent); color: #fff; }
  .btn-primary:hover { background: var(--accent2); }
  .btn-danger { background: var(--danger); color: #fff; }
  .btn-danger:hover { background: #b91c1c; }
  .btn-ghost { background: transparent; color: var(--muted); border: 1px solid var(--border); }
  .btn-ghost:hover { background: var(--card2); color: var(--text); }
  .btn:disabled { opacity: 0.5; cursor: not-allowed; }

  /* AUTH GATE */
  .auth-gate {
    background: #1a0f0f; border: 2px solid var(--high); border-radius: 12px;
    padding: 1.5rem; margin-bottom: 1.5rem;
  }
  .auth-gate-title { color: #fb923c; font-weight: 700; font-size: 1rem; margin-bottom: 0.75rem; display: flex; align-items: center; gap: 0.5rem; }
  .auth-gate ul { list-style: none; padding: 0; margin: 0.5rem 0; }
  .auth-gate li { color: var(--muted); font-size: 0.88rem; padding: 0.2rem 0; padding-left: 1.2rem; position: relative; }
  .auth-gate li::before { content: '•'; position: absolute; left: 0; color: #fb923c; }
  .auth-confirm-row { display: flex; gap: 0.75rem; margin-top: 1rem; align-items: center; }
  .auth-confirm-row input { flex: 1; }

  /* TERMINAL */
  .terminal-box {
    background: #000; border: 1px solid var(--border); border-radius: 8px;
    font-family: var(--font-mono); font-size: 0.82rem; line-height: 1.6;
    padding: 1rem; height: 420px; overflow-y: auto; white-space: pre-wrap; word-break: break-all;
  }
  .t-green { color: #4ade80; }
  .t-red { color: #f87171; }
  .t-yellow { color: #fbbf24; }
  .t-blue { color: #60a5fa; }
  .t-cyan { color: #22d3ee; }
  .t-muted { color: #6b7280; }
  .t-bold { font-weight: 700; }
  .t-critical { color: #dc2626; }
  .t-high { color: #ea580c; }

  /* SEVERITY BADGES */
  .badge {
    display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
    font-size: 0.72rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
  }
  .badge-Critical { background: #fee2e2; color: #dc2626; }
  .badge-High { background: #ffedd5; color: #ea580c; }
  .badge-Medium { background: #fef3c7; color: #d97706; }
  .badge-Low { background: #ecfccb; color: #65a30d; }
  .badge-Info { background: #dbeafe; color: #2563eb; }

  /* FINDINGS */
  .finding-card { background: var(--card); border-radius: 8px; padding: 1rem; margin-bottom: 0.75rem; border-left: 4px solid; }
  .finding-card.Critical { border-color: var(--critical); }
  .finding-card.High { border-color: var(--high); }
  .finding-card.Medium { border-color: var(--medium); }
  .finding-card.Low { border-color: var(--low); }
  .finding-card.Info { border-color: var(--info); }
  .finding-header { display: flex; align-items: center; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.5rem; cursor: pointer; }
  .finding-title { font-weight: 600; font-size: 0.95rem; flex: 1; }
  .finding-agent { color: var(--muted); font-size: 0.75rem; background: var(--bg); padding: 0.15rem 0.4rem; border-radius: 4px; }
  .finding-body { font-size: 0.88rem; line-height: 1.6; color: var(--muted); }
  .finding-body .detail-label { color: var(--accent2); font-size: 0.72rem; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.75rem; margin-bottom: 0.2rem; }
  .finding-body .evidence { background: #000; border-radius: 4px; padding: 0.6rem; font-family: var(--font-mono); font-size: 0.78rem; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; }
  .collapsed .finding-body { display: none; }

  /* META GRID */
  .meta-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
  .meta-card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1rem; }
  .meta-label { color: var(--muted); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.08em; }
  .meta-value { font-size: 1.6rem; font-weight: 700; margin-top: 0.25rem; }
  .meta-value.critical { color: var(--critical); }
  .meta-value.high { color: var(--high); }
  .meta-value.medium { color: var(--medium); }
  .meta-value.low { color: var(--low); }
  .meta-value.info { color: var(--info); }
  .meta-value.green { color: var(--success); }

  /* HISTORY TABLE */
  table { width: 100%; border-collapse: collapse; }
  th, td { padding: 0.6rem 1rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.88rem; }
  th { color: var(--muted); font-size: 0.78rem; text-transform: uppercase; letter-spacing: 0.06em; }
  tr:hover td { background: var(--card2); }
  .status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; }
  .status-dot.running { background: #fbbf24; animation: pulse 1.5s infinite; }
  .status-dot.done { background: var(--success); }
  .status-dot.error { background: var(--danger); }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.3} }

  /* CODE EDITOR */
  #editor-container { height: 600px; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
  .file-tree { list-style: none; padding: 0; }
  .file-tree li { padding: 0.35rem 0.75rem; cursor: pointer; border-radius: 6px; font-size: 0.85rem; font-family: var(--font-mono); color: var(--muted); }
  .file-tree li:hover { background: var(--card2); color: var(--text); }
  .file-tree li.active { background: var(--accent); color: #fff; }
  .editor-toolbar { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; flex-wrap: wrap; }
  .editor-path { font-family: var(--font-mono); font-size: 0.82rem; color: var(--muted); flex: 1; }
  .save-status { font-size: 0.8rem; color: var(--muted); }
  .save-status.saved { color: var(--success); }
  .save-status.unsaved { color: #fbbf24; }

  /* PROGRESS */
  .progress-bar { height: 6px; background: var(--card2); border-radius: 3px; overflow: hidden; margin-top: 0.5rem; }
  .progress-fill { height: 100%; background: var(--accent); border-radius: 3px; transition: width 0.5s; }

  /* Risk score */
  .risk-score { font-size: 2.5rem; font-weight: 800; }
  .risk-score.low { color: var(--success); }
  .risk-score.medium { color: var(--medium); }
  .risk-score.high { color: var(--high); }
  .risk-score.critical { color: var(--critical); }

  /* SCAN STATUS TOP */
  .scan-status-bar {
    background: var(--card); border: 1px solid var(--border); border-radius: 8px;
    padding: 0.75rem 1rem; display: flex; align-items: center; gap: 1rem;
    margin-bottom: 1rem;
  }
  .scan-status-label { flex: 1; font-size: 0.9rem; }
  .scan-status-sub { color: var(--muted); font-size: 0.78rem; }

  /* TABS */
  .tabs { display: flex; gap: 0.25rem; margin-bottom: 1.25rem; background: var(--card); border-radius: 8px; padding: 0.25rem; }
  .tab { padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; font-size: 0.88rem; color: var(--muted); border: none; background: none; transition: all 0.15s; }
  .tab.active { background: var(--accent); color: #fff; font-weight: 600; }

  /* RESPONSIVE */
  .two-col { display: grid; grid-template-columns: 220px 1fr; gap: 1.5rem; }
  @media (max-width: 700px) { .two-col { grid-template-columns: 1fr; } .page { padding: 1rem; } }

  .spinner { width: 14px; height: 14px; border: 2px solid var(--accent); border-top-color: transparent; border-radius: 50%; animation: spin 0.8s linear infinite; display: inline-block; }
  @keyframes spin { to { transform: rotate(360deg); } }
  .hidden { display: none !important; }
</style>
</head>
<body>

<nav>
  <div class="nav-brand">Anti<span>Hack</span></div>
  <button class="nav-link active" onclick="showPage('scan')" id="nav-scan">🛡️ New Scan</button>
  <button class="nav-link" onclick="showPage('results')" id="nav-results">📊 Results</button>
  <button class="nav-link" onclick="showPage('history')" id="nav-history">📜 History</button>
  <button class="nav-link" onclick="showPage('editor')" id="nav-editor">✏️ Code Editor</button>
  <div class="nav-spacer"></div>
  <span style="color:var(--muted);font-size:0.78rem">AI Penetration Testing Platform</span>
</nav>

<!-- ===================== PAGE: SCAN ===================== -->
<div class="page active" id="page-scan">
  <div class="card">
    <div class="card-title">🎯 Configure Security Scan</div>
    <div class="form-row">
      <label>Target URL</label>
      <input type="text" id="target-url" placeholder="https://example.com" />
      <div class="form-hint">Enter the full URL of the target. You must own this target or have written authorization.</div>
    </div>
    <div class="form-row">
      <label>Anthropic API Key</label>
      <input type="password" id="api-key" placeholder="sk-ant-..." />
      <div class="form-hint">Your API key is used only for this scan and never stored on disk.</div>
    </div>
  </div>

  <div class="auth-gate">
    <div class="auth-gate-title">⚠️ Authorization Required</div>
    <p style="color:var(--muted);font-size:0.88rem;margin-bottom:0.5rem">This platform performs active security testing including:</p>
    <ul>
      <li>Port scanning and service fingerprinting</li>
      <li>HTTP probing, form submission, and injection testing</li>
      <li>Authentication bypass attempts</li>
      <li>Directory enumeration and secrets detection</li>
    </ul>
    <p style="color:var(--muted);font-size:0.88rem;margin-top:0.75rem">
      <strong style="color:#fb923c">By proceeding you confirm</strong> that you own this target
      OR have written permission from the target owner to perform this security test.
      Unauthorized testing is illegal and unethical.
    </p>
    <div class="auth-confirm-row">
      <input type="text" id="auth-confirm" placeholder="Type exactly: I CONFIRM" />
      <button class="btn btn-primary" id="start-btn" onclick="startScan()">▶ Start Scan</button>
    </div>
  </div>

  <div id="scan-running" class="hidden">
    <div class="scan-status-bar">
      <div class="spinner"></div>
      <div class="scan-status-label">
        <div id="scan-status-text">Initializing scan...</div>
        <div class="scan-status-sub" id="scan-status-sub"></div>
      </div>
      <button class="btn btn-ghost" onclick="stopScan()">⏹ Stop</button>
    </div>
    <div class="card">
      <div class="card-title">Live Output</div>
      <div class="terminal-box" id="terminal"></div>
    </div>
  </div>
</div>

<!-- ===================== PAGE: RESULTS ===================== -->
<div class="page" id="page-results">
  <div id="results-empty" style="text-align:center;padding:4rem;color:var(--muted)">
    <div style="font-size:3rem;margin-bottom:1rem">📊</div>
    <div style="font-size:1.1rem;margin-bottom:0.5rem">No results yet</div>
    <div style="font-size:0.9rem">Run a scan first to see results here.</div>
  </div>
  <div id="results-content" class="hidden">
    <div class="meta-grid" id="results-meta"></div>
    <div class="card">
      <div class="card-title">Executive Summary</div>
      <div id="exec-summary" style="font-size:0.9rem;line-height:1.8;color:var(--muted)"></div>
    </div>
    <div class="card">
      <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
        Findings
        <div style="display:flex;gap:0.5rem;flex-wrap:wrap" id="findings-filter"></div>
      </div>
      <div id="findings-list"></div>
    </div>
  </div>
</div>

<!-- ===================== PAGE: HISTORY ===================== -->
<div class="page" id="page-history">
  <div class="card">
    <div class="card-title">Scan History</div>
    <div id="history-empty" style="text-align:center;padding:2rem;color:var(--muted)">No scans run yet in this session.</div>
    <table id="history-table" class="hidden">
      <thead><tr>
        <th>Status</th><th>Target</th><th>Started</th>
        <th>Findings</th><th>Risk</th><th>Reports</th>
      </tr></thead>
      <tbody id="history-tbody"></tbody>
    </table>
  </div>
</div>

<!-- ===================== PAGE: EDITOR ===================== -->
<div class="page" id="page-editor">
  <div class="two-col">
    <div>
      <div class="card">
        <div class="card-title">Agent Files</div>
        <ul class="file-tree" id="file-tree"></ul>
      </div>
    </div>
    <div>
      <div class="card">
        <div class="editor-toolbar">
          <span class="editor-path" id="editor-path">Select a file</span>
          <span class="save-status" id="save-status"></span>
          <button class="btn btn-primary btn-sm" onclick="saveFile()" id="save-btn" style="padding:0.4rem 0.85rem;font-size:0.82rem" disabled>💾 Save</button>
        </div>
        <div id="editor-container"></div>
      </div>
    </div>
  </div>
</div>

<!-- ═══ SCRIPTS ═══ -->
<script>
// ── State ──
let currentScanId = null;
let scanWs = null;
let currentResults = null;
let monacoEditor = null;
let currentFilePath = null;

// ── Navigation ──
function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(n => n.classList.remove('active'));
  document.getElementById('page-' + name).classList.add('active');
  document.getElementById('nav-' + name).classList.add('active');
  if (name === 'editor' && !monacoEditor) initMonaco();
  if (name === 'editor') loadFileTree();
  if (name === 'history') renderHistory();
}

// ── Scan ──
function startScan() {
  const target = document.getElementById('target-url').value.trim();
  const apiKey = document.getElementById('api-key').value.trim();
  const confirm = document.getElementById('auth-confirm').value.trim();

  if (!target) return alert('Please enter a target URL.');
  if (!apiKey) return alert('Please enter your Anthropic API key.');
  if (confirm !== 'I CONFIRM') { alert('You must type exactly "I CONFIRM" to proceed.'); return; }

  const normalizedTarget = target.startsWith('http') ? target : 'https://' + target;
  const scanId = crypto.randomUUID();
  currentScanId = scanId;

  const entry = { scanId, target: normalizedTarget, startedAt: new Date().toISOString(), status: 'running', findings: [], riskScore: 0, reports: {} };
  window._scanHistory = window._scanHistory || [];
  window._scanHistory.unshift(entry);

  document.getElementById('scan-running').classList.remove('hidden');
  document.getElementById('start-btn').disabled = true;
  const terminal = document.getElementById('terminal');
  terminal.innerHTML = '';
  appendTerminal(`<span class="t-cyan t-bold">AntiHack Platform — Starting Scan</span>\n`);
  appendTerminal(`<span class="t-muted">Target: </span><span class="t-green">${normalizedTarget}</span>\n`);
  appendTerminal(`<span class="t-muted">Scan ID: ${scanId}</span>\n\n`);
  document.getElementById('scan-status-text').textContent = 'Connecting to scan engine...';

  const ws = new WebSocket(`ws://${location.host}/ws/scan`);
  scanWs = ws;

  ws.onopen = () => {
    ws.send(JSON.stringify({ target: normalizedTarget, api_key: apiKey, scan_id: scanId }));
    document.getElementById('scan-status-text').textContent = 'Scan running...';
  };

  ws.onmessage = (evt) => {
    const msg = JSON.parse(evt.data);
    handleScanMessage(msg, entry);
  };

  ws.onclose = () => {
    document.getElementById('start-btn').disabled = false;
    if (entry.status === 'running') {
      entry.status = 'done';
      appendTerminal(`\n<span class="t-muted">— Connection closed —</span>\n`);
    }
    document.getElementById('scan-status-text').textContent = 'Scan complete.';
  };

  ws.onerror = () => {
    appendTerminal(`\n<span class="t-red">WebSocket error — check server is running</span>\n`);
    entry.status = 'error';
  };
}

function handleScanMessage(msg, entry) {
  if (msg.type === 'log') {
    appendTerminal(formatLog(msg));
  } else if (msg.type === 'phase') {
    appendTerminal(`\n<span class="t-cyan t-bold">━━ ${msg.name} ━━</span>\n`);
    document.getElementById('scan-status-sub').textContent = msg.name;
  } else if (msg.type === 'agent_start') {
    appendTerminal(`<span class="t-muted">  ○ ${msg.agent}...</span>\n`);
  } else if (msg.type === 'agent_done') {
    const icon = msg.crits > 0 ? '🔴' : msg.highs > 0 ? '🟠' : '✅';
    let extra = '';
    if (msg.crits > 0) extra = ` <span class="t-critical">[${msg.crits} CRITICAL]</span>`;
    else if (msg.highs > 0) extra = ` <span class="t-high">[${msg.highs} HIGH]</span>`;
    appendTerminal(`  ${icon} <span class="t-green">${msg.agent}</span>${extra}\n`);
  } else if (msg.type === 'agent_error') {
    appendTerminal(`  ✗ <span class="t-red">${msg.agent}: ${msg.error}</span>\n`);
  } else if (msg.type === 'complete') {
    entry.status = 'done';
    entry.findings = msg.findings || [];
    entry.riskScore = msg.risk_score || 0;
    entry.reports = msg.reports || {};
    entry.executiveSummary = msg.executive_summary || '';
    currentResults = entry;
    appendTerminal(`\n<span class="t-green t-bold">✔ Scan complete! Risk score: ${msg.risk_score}/100</span>\n`);
    appendTerminal(`<span class="t-muted">Switch to Results tab to view findings.</span>\n`);
    document.getElementById('scan-status-text').textContent = `Scan complete — Risk Score: ${msg.risk_score}/100`;
    renderResults(entry);
  } else if (msg.type === 'error') {
    entry.status = 'error';
    appendTerminal(`\n<span class="t-red">ERROR: ${msg.message}</span>\n`);
    document.getElementById('scan-status-text').textContent = 'Scan failed.';
  }
}

function formatLog(msg) {
  const cls = msg.level === 'error' ? 't-red' : msg.level === 'warn' ? 't-yellow' : 't-muted';
  return `<span class="${cls}">  ${escHtml(msg.text)}</span>\n`;
}

function appendTerminal(html) {
  const t = document.getElementById('terminal');
  t.innerHTML += html;
  t.scrollTop = t.scrollHeight;
}

function stopScan() {
  if (scanWs) { scanWs.close(); scanWs = null; }
  document.getElementById('start-btn').disabled = false;
  document.getElementById('scan-status-text').textContent = 'Scan stopped.';
}

// ── Results ──
function renderResults(entry) {
  document.getElementById('results-empty').classList.add('hidden');
  document.getElementById('results-content').classList.remove('hidden');

  const counts = {};
  for (const f of (entry.findings || [])) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  const riskClass = entry.riskScore >= 80 ? 'critical' : entry.riskScore >= 50 ? 'high' : entry.riskScore >= 25 ? 'medium' : 'low';

  document.getElementById('results-meta').innerHTML = `
    <div class="meta-card"><div class="meta-label">Risk Score</div><div class="meta-value ${riskClass}">${entry.riskScore}/100</div></div>
    <div class="meta-card"><div class="meta-label">Total Findings</div><div class="meta-value">${(entry.findings || []).length}</div></div>
    <div class="meta-card"><div class="meta-label">Critical</div><div class="meta-value critical">${counts.Critical || 0}</div></div>
    <div class="meta-card"><div class="meta-label">High</div><div class="meta-value high">${counts.High || 0}</div></div>
    <div class="meta-card"><div class="meta-label">Medium</div><div class="meta-value medium">${counts.Medium || 0}</div></div>
    <div class="meta-card"><div class="meta-label">Low / Info</div><div class="meta-value info">${(counts.Low || 0) + (counts.Info || 0)}</div></div>
  `;

  document.getElementById('exec-summary').textContent = entry.executiveSummary || 'No executive summary available.';

  const severities = ['Critical', 'High', 'Medium', 'Low', 'Info'];
  const filterEl = document.getElementById('findings-filter');
  filterEl.innerHTML = severities.map(s =>
    `<button class="btn btn-ghost" style="padding:0.3rem 0.75rem;font-size:0.78rem" onclick="filterFindings('${s}')">${s} (${counts[s]||0})</button>`
  ).join('') + `<button class="btn btn-ghost" style="padding:0.3rem 0.75rem;font-size:0.78rem" onclick="filterFindings('all')">All</button>`;

  renderFindingsList(entry.findings, 'all');
}

function filterFindings(sev) {
  if (!currentResults) return;
  renderFindingsList(currentResults.findings, sev);
}

function renderFindingsList(findings, sev) {
  const filtered = sev === 'all' ? findings : findings.filter(f => f.severity === sev);
  const el = document.getElementById('findings-list');
  if (!filtered || filtered.length === 0) {
    el.innerHTML = '<div style="text-align:center;padding:2rem;color:var(--muted)">No findings in this category.</div>';
    return;
  }
  el.innerHTML = filtered.map((f, i) => `
    <div class="finding-card ${f.severity} collapsed" id="finding-${i}">
      <div class="finding-header" onclick="toggleFinding(${i})">
        <span class="badge badge-${f.severity}">${f.severity}</span>
        <span class="finding-title">${escHtml(f.title)}</span>
        <span class="finding-agent">${escHtml(f.agent || '')}</span>
        <span style="color:var(--muted);font-size:0.8rem">▼</span>
      </div>
      <div class="finding-body">
        <div class="detail-label">Description</div>
        <div>${escHtml(f.description || '')}</div>
        ${f.url ? `<div class="detail-label">URL</div><div><a href="${escHtml(f.url)}" target="_blank">${escHtml(f.url)}</a></div>` : ''}
        <div class="detail-label">Evidence</div>
        <div class="evidence">${escHtml((f.evidence || '').slice(0, 1200))}</div>
        <div class="detail-label">Remediation</div>
        <div>${escHtml(f.remediation || '')}</div>
      </div>
    </div>
  `).join('');
}

function toggleFinding(i) {
  const el = document.getElementById(`finding-${i}`);
  el.classList.toggle('collapsed');
}

// ── History ──
function renderHistory() {
  const history = window._scanHistory || [];
  if (history.length === 0) {
    document.getElementById('history-empty').classList.remove('hidden');
    document.getElementById('history-table').classList.add('hidden');
    return;
  }
  document.getElementById('history-empty').classList.add('hidden');
  document.getElementById('history-table').classList.remove('hidden');
  document.getElementById('history-tbody').innerHTML = history.map(s => {
    const riskClass = s.riskScore >= 80 ? 'critical' : s.riskScore >= 50 ? 'high' : s.riskScore >= 25 ? 'medium' : 'green';
    const statusColor = s.status === 'running' ? 'running' : s.status === 'done' ? 'done' : 'error';
    const reports = Object.entries(s.reports || {}).map(([k, p]) =>
      p ? `<a href="/report/${encodeURIComponent(p)}" target="_blank">${k.toUpperCase()}</a>` : ''
    ).filter(Boolean).join(' ');
    return `<tr>
      <td><span class="status-dot ${statusColor}"></span>${s.status}</td>
      <td>${escHtml(s.target)}</td>
      <td style="color:var(--muted)">${new Date(s.startedAt).toLocaleString()}</td>
      <td>${(s.findings || []).length}</td>
      <td><span style="color:var(--${riskClass})">${s.riskScore}/100</span></td>
      <td>${reports || '—'}</td>
    </tr>`;
  }).join('');
}

// ── Monaco Editor ──
function initMonaco() {
  require.config({ paths: { 'vs': 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs' } });
  require(['vs/editor/editor.main'], function() {
    monacoEditor = monaco.editor.create(document.getElementById('editor-container'), {
      value: '// Select a file from the left panel to start editing',
      language: 'python',
      theme: 'vs-dark',
      fontSize: 13,
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      minimap: { enabled: false },
      scrollBeyondLastLine: false,
      automaticLayout: true,
      lineNumbers: 'on',
      renderLineHighlight: 'all',
      bracketPairColorization: { enabled: true },
    });
    monacoEditor.onDidChangeModelContent(() => {
      document.getElementById('save-status').textContent = '● Unsaved';
      document.getElementById('save-status').className = 'save-status unsaved';
    });
  });
}

function loadFileTree() {
  fetch('/api/files')
    .then(r => r.json())
    .then(files => {
      const ul = document.getElementById('file-tree');
      ul.innerHTML = files.map(f =>
        `<li onclick="openFile('${f.path}')" id="ft-${btoa(f.path).replace(/=/g,'')}">${escHtml(f.label)}</li>`
      ).join('');
    });
}

function openFile(path) {
  fetch(`/api/file?path=${encodeURIComponent(path)}`)
    .then(r => r.json())
    .then(data => {
      if (!monacoEditor) { alert('Monaco editor not ready yet.'); return; }
      currentFilePath = path;
      monacoEditor.setValue(data.content);
      document.getElementById('editor-path').textContent = path;
      document.getElementById('save-btn').disabled = false;
      document.getElementById('save-status').textContent = 'Saved';
      document.getElementById('save-status').className = 'save-status saved';
      document.querySelectorAll('.file-tree li').forEach(li => li.classList.remove('active'));
      const id = 'ft-' + btoa(path).replace(/=/g, '');
      const el = document.getElementById(id);
      if (el) el.classList.add('active');
    });
}

function saveFile() {
  if (!currentFilePath || !monacoEditor) return;
  const content = monacoEditor.getValue();
  fetch('/api/file', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path: currentFilePath, content })
  })
  .then(r => r.json())
  .then(d => {
    document.getElementById('save-status').textContent = d.ok ? '✓ Saved' : '✗ Save failed';
    document.getElementById('save-status').className = 'save-status ' + (d.ok ? 'saved' : '');
  });
}

// ── Utilities ──
function escHtml(s) {
  if (!s) return '';
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
</script>

<!-- Monaco CDN loader -->
<script src="https://cdnjs.cloudflare.com/ajax/libs/require.js/2.3.6/require.min.js"></script>

</body>
</html>"""


# ─────────────────────────── API endpoints ─────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index():
    return DASHBOARD_HTML


@app.get("/api/files")
async def list_files():
    """List all editable agent/orchestrator files."""
    agent_files = []
    for pattern in ["agents/**/*.py", "orchestrator.py", "main.py"]:
        for p in sorted(BASE_DIR.glob(pattern)):
            if "__pycache__" in str(p):
                continue
            rel = str(p.relative_to(BASE_DIR))
            agent_files.append({"path": rel, "label": rel})
    return agent_files


@app.get("/api/file")
async def read_file(path: str):
    safe = _safe_path(path)
    if not safe.exists():
        raise HTTPException(404, "File not found")
    return {"content": safe.read_text(encoding="utf-8"), "path": path}


@app.post("/api/file")
async def write_file(body: dict = Body(...)):
    path = body.get("path", "")
    content = body.get("content", "")
    safe = _safe_path(path)
    if not safe.exists():
        raise HTTPException(404, "File not found — cannot create new files here")
    try:
        safe.write_text(content, encoding="utf-8")
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def _safe_path(path: str) -> Path:
    """Resolve path safely within BASE_DIR."""
    resolved = (BASE_DIR / path).resolve()
    if not str(resolved).startswith(str(BASE_DIR.resolve())):
        raise HTTPException(403, "Access denied")
    return resolved


@app.get("/report/{file_path:path}")
async def serve_report(file_path: str):
    """Serve generated report files."""
    safe = _safe_path(file_path)
    if not safe.exists():
        raise HTTPException(404, "Report not found")
    content_type = "text/html" if file_path.endswith(".html") else (
        "application/json" if file_path.endswith(".json") else "text/plain"
    )
    from fastapi.responses import Response
    return Response(content=safe.read_bytes(), media_type=content_type)


# ─────────────────────────── WebSocket Scan ────────────────────────────────

@app.websocket("/ws/scan")
async def ws_scan(ws: WebSocket):
    await ws.accept()
    try:
        raw = await ws.receive_text()
        data = json.loads(raw)
    except Exception:
        await ws.close()
        return

    target = data.get("target", "").strip()
    api_key = data.get("api_key", "").strip()
    scan_id = data.get("scan_id", str(uuid.uuid4()))

    if not target or not api_key:
        await ws.send_json({"type": "error", "message": "Missing target or API key."})
        await ws.close()
        return

    await _run_scan(ws, target, api_key, scan_id)


async def _run_scan(ws: WebSocket, target: str, api_key: str, scan_id: str):
    """Run the full scan orchestrator, streaming events back over WebSocket."""
    import anthropic as _anthropic

    try:
        client = _anthropic.Anthropic(api_key=api_key)
    except Exception as e:
        await ws.send_json({"type": "error", "message": f"Failed to init Anthropic client: {e}"})
        return

    # Import agents
    try:
        from agents.base_agent import Finding, Severity
        from agents.recon import DNSReconAgent, WHOISAgent, PortScannerAgent
        from agents.web import (
            SQLInjectionAgent, XSSAgent, CSRFAgent, SSRFAgent,
            AuthAgent, APIAgent, DirectoryTraversalAgent, SecretsAgent,
        )
        from agents.infra import SSLAgent, TechFingerprintAgent
        from agents.report import ReportAgent
    except ImportError as e:
        await ws.send_json({"type": "error", "message": f"Import error: {e}"})
        return

    phases = {
        "Recon Phase": [
            DNSReconAgent(target, client),
            WHOISAgent(target, client),
            PortScannerAgent(target, client),
        ],
        "Web Security Phase": [
            SSLAgent(target, client),
            TechFingerprintAgent(target, client),
            SQLInjectionAgent(target, client),
            XSSAgent(target, client),
            CSRFAgent(target, client),
            SSRFAgent(target, client),
            AuthAgent(target, client),
            APIAgent(target, client),
            DirectoryTraversalAgent(target, client),
            SecretsAgent(target, client),
        ],
    }

    all_findings: list[Finding] = []

    async def run_agent(agent):
        await ws.send_json({"type": "agent_start", "agent": agent.name})
        try:
            findings = await agent.run()
            all_findings.extend(findings)
            crits = sum(1 for f in findings if f.severity == Severity.CRITICAL)
            highs = sum(1 for f in findings if f.severity == Severity.HIGH)
            await ws.send_json({"type": "agent_done", "agent": agent.name, "crits": crits, "highs": highs, "count": len(findings)})
        except Exception as e:
            await ws.send_json({"type": "agent_error", "agent": agent.name, "error": str(e)})

    for phase_name, agents in phases.items():
        await ws.send_json({"type": "phase", "name": phase_name})
        await asyncio.gather(*[run_agent(a) for a in agents])

    # Report
    await ws.send_json({"type": "log", "level": "info", "text": "Generating comprehensive report..."})
    output_dir = str(REPORTS_DIR)
    report_agent = ReportAgent(target=target, client=client, all_findings=all_findings, output_dir=output_dir)

    try:
        result = await report_agent.run()
    except Exception as e:
        result = {"risk_score": 0, "counts": {}, "executive_summary": "", "markdown": "", "json": "", "html": ""}
        await ws.send_json({"type": "log", "level": "error", "text": f"Report generation failed: {e}"})

    # Serialize findings
    def finding_to_dict(f: Finding) -> dict:
        return {
            "title": f.title,
            "severity": f.severity.value,
            "agent": f.agent,
            "description": f.description,
            "evidence": f.evidence,
            "remediation": f.remediation,
            "url": f.url,
            "parameter": f.parameter,
        }

    await ws.send_json({
        "type": "complete",
        "risk_score": result.get("risk_score", 0),
        "executive_summary": result.get("executive_summary", ""),
        "findings": [finding_to_dict(f) for f in all_findings],
        "reports": {
            "markdown": result.get("markdown", ""),
            "json": result.get("json", ""),
            "html": result.get("html", ""),
        },
    })
    await ws.close()


# ─────────────────────────── Entry Point ───────────────────────────────────

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AntiHack Web Dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7070)
    parser.add_argument("--reload", action="store_true")
    args = parser.parse_args()

    print(f"\n  AntiHack Platform")
    print(f"  Dashboard → http://{args.host}:{args.port}")
    print(f"  Press Ctrl+C to stop\n")

    uvicorn.run(
        "webapp:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="warning",
    )
