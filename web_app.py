"""
Cisco IOS Log Analyzer - interfejs HTML w stylu NMS
---------------------------------------------------
Samodzielny serwer HTTP (bez zewnętrznych zależności - używa wyłącznie
standardowej biblioteki Pythona), który udostępnia przejrzysty dashboard
do przeglądania wyników analizatora logów Cisco IOS.

Funkcje:
  - Dashboard w stylu NMS (ciemny motyw, liczniki KPI, wykresy),
  - Lista zdarzeń z filtrowaniem (typ, IP, użytkownik),
  - Strona "Alerts" z potencjalnym brute-force i IP spoza whitelisty,
  - Zakładka z top źródłami ruchu i użytkownikami,
  - JSON API pod /api/stats do integracji lub auto-odświeżania.

Uruchomienie:
    python web_app.py
    python web_app.py --log Sample_Logs/Cisco_ios.log
    python web_app.py --log Sample_Logs/Cisco_ios.log --port 8080 --host 0.0.0.0

Po uruchomieniu otwórz w przeglądarce: http://127.0.0.1:8000
"""
from __future__ import annotations

import argparse
import html
import json
import os
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
import urllib.error
import urllib.request
from urllib.parse import parse_qs, urlparse

from Cisco_Log_Analyzer import (
    AnalysisResult,
    analyze,
    analyze_lines,
    load_allowed_networks,
    detect_anomalies_kmeans,
)
from ai_client import AIClient


# ---------------------------------------------------------------------------
# Stan globalny (ustawiany w main() przed startem serwera)
# ---------------------------------------------------------------------------

_STATE: dict[str, Any] = {
    "log_paths": [],
    "allowed_path": Path("Allowed_IPS"),
    "allowed_networks": [],
    "bf_threshold": 3,
    "port_failure_threshold": 3,
    "use_db": False,
    "db_config": {
        "host": "127.0.0.1",
        "port": 5432,
        "dbname": "cisco_logs",
        "user": "postgres",
        "password": "ZAQ!2wsx",
    },
    "ai_config": {
        "provider": "ollama",  # "gemini" | "ollama" | "openai"
        "api_key": os.environ.get("GEMINI_API_KEY", ""),
        "api_url": "http://localhost:11434",  # domyślnie dla Ollama
        "model": "llama3",  # domyślnie dla Ollama
    },
}


# ---------------------------------------------------------------------------
# Integracja AI (Google Gemini / Local LLM)
# ---------------------------------------------------------------------------

SYSTEM_EXPLAIN = (
    "Jesteś ekspertem ds. cyberbezpieczeństwa i administratorem sieci (NMS Assistant). "
    "Przeanalizuj pojedynczy wpis z logu systemowego i dostarcz zwięzły raport w formacie Markdown "
    "(używaj pogrubień, wypunktowań i tabel, ale unikaj nagłówków H1/H2). "
    "Raport musi zawierać:\n"
    "1. **Wyjaśnienie**: Co dokładnie oznacza ten log i dlaczego się pojawił.\n"
    "2. **Poziom zagrożenia**: (Niski, Średni, Wysoki, Krytyczny) wraz z krótkim uzasadnieniem.\n"
    "3. **Sugerowane działania**: Krok po kroku co administrator powinien zrobić."
)

SYSTEM_SUMMARY = (
    "Jesteś ekspertem ds. cyberbezpieczeństwa i analizy logów w systemach sieciowych (NMS Assistant). "
    "Otrzymujesz statystyki z analizatora logów (Cisco oraz Linux). "
    "Przeanalizuj te dane pod kątem bezpieczeństwa, wykryj anomalie lub potencjalne ataki (np. brute-force, skanowanie portów, próby nieautoryzowanego dostępu) "
    "i sporządź zwięzły raport w formacie Markdown (bez nagłówków H1/H2).\n"
    "Skup się na kluczowych zagrożeniach, podejrzanych adresach IP i celach ataków."
)

SYSTEM_CHAT = (
    "Jesteś pomocnym asystentem AI wbudowanym w konsolę NMS (Network Management System). "
    "Pomagasz administratorowi sieci w analizie logów i diagnozowaniu problemów.\n"
    "Poniżej znajdują się aktualne statystyki oraz ostatnie zdarzenia z analizatora logów jako kontekst.\n"
    "Odpowiadaj rzeczowo, profesjonalnie i zwięźle w języku polskim, używając formatowania Markdown.\n\n"
    "Oto kontekst logów:\n{context}"
)



# ---------------------------------------------------------------------------
# Analiza i agregacja wyników
# ---------------------------------------------------------------------------


def fetch_logs_from_db() -> AnalysisResult:
    """Pobiera logi z bazy PostgreSQL i analizuje je."""
    import psycopg2

    cfg = _STATE["db_config"]
    dsn = (
        f"dbname={cfg['dbname']} user={cfg['user']} "
        f"password={cfg['password']} host={cfg['host']} port={cfg['port']}"
    )
    conn = psycopg2.connect(dsn)
    cur = conn.cursor()
    cur.execute("SELECT log_line, device FROM logs ORDER BY created_at DESC")
    lines = [(row[0], row[1]) for row in cur.fetchall()]
    cur.close()
    conn.close()

    return analyze_lines(
        lines,
        _STATE["allowed_networks"],
        brute_force_threshold=_STATE["bf_threshold"],
        port_failure_threshold=_STATE["port_failure_threshold"],
    )


def run_analysis() -> dict[str, AnalysisResult]:
    """Uruchamia analizę na plikach logów lub bazie danych."""
    results: dict[str, AnalysisResult] = {}

    if _STATE["use_db"]:
        results["PostgreSQL: " + _STATE["db_config"]["dbname"]] = fetch_logs_from_db()
    else:
        for p in _STATE["log_paths"]:
            if p.exists():
                results[str(p)] = analyze(
                    p,
                    _STATE["allowed_networks"],
                    brute_force_threshold=_STATE["bf_threshold"],
                    port_failure_threshold=_STATE["port_failure_threshold"],
                )
    return results


def aggregate(results: dict[str, AnalysisResult]) -> dict[str, Any]:
    """Zbiera wyniki z wielu plików w jeden słownik (na potrzeby dashboardu)."""
    events: list[dict[str, Any]] = []
    failed: Counter = Counter()
    success: Counter = Counter()
    acl: Counter = Counter()
    unknown_ips: set[str] = set()
    total_lines = 0

    failed_by_device: Counter = Counter()
    port_down_by_device: Counter = Counter()
    port_down_by_port: Counter = Counter()
    port_down_total = 0

    for path, r in results.items():
        total_lines += r.total_lines
        for e in r.events:
            d = asdict(e)
            d["source_file"] = path
            events.append(d)
        failed.update(r.failed_by_ip)
        success.update(r.success_by_ip)
        acl.update(r.acl_by_ip)
        unknown_ips.update(r.unknown_ips)

        failed_by_device.update(r.failed_by_device)
        port_down_by_device.update(r.port_down_by_device)
        port_down_by_port.update(r.port_down_by_port)
        port_down_total += sum(r.port_down_by_ip.values())

    brute_force = [
        (ip, c) for ip, c in failed.most_common()
        if c >= _STATE["bf_threshold"]
    ]

    frequent_port_failures = [
        (port, c) for port, c in port_down_by_port.most_common()
        if c >= _STATE["port_failure_threshold"]
    ]

    # Pobieramy wszystkie urządzenia z logów
    all_devices = set(e["device"] for e in events if e.get("device"))
    anomalous_devices = detect_anomalies_kmeans(port_down_by_device, all_devices)

    targeted_users = Counter(
        e["user"] for e in events
        if e["kind"] == "login_failed" and e.get("user")
    )

    system_total = sum(1 for e in events if e["kind"] == "system_event")

    return {
        "total_files": len(results),
        "total_lines": total_lines,
        "total_events": len(events),
        "events": events,
        "failed_total": sum(failed.values()),
        "success_total": sum(success.values()),
        "acl_total": sum(acl.values()),
        "system_total": system_total,
        "port_down_total": port_down_total,
        "failed_by_ip": failed.most_common(),
        "success_by_ip": success.most_common(),
        "acl_by_ip": acl.most_common(),
        "failed_by_device": failed_by_device.most_common(),
        "port_down_by_device": port_down_by_device.most_common(),
        "port_down_by_port": port_down_by_port.most_common(),
        "unknown_ips": sorted(unknown_ips),
        "brute_force_suspects": brute_force,
        "frequent_port_failures": frequent_port_failures,
        "anomalous_devices": anomalous_devices,
        "targeted_users": targeted_users.most_common(10),
    }


# ---------------------------------------------------------------------------
# Szablon HTML (jeden "layout" + funkcje renderujące poszczególne strony)
# ---------------------------------------------------------------------------

BASE_CSS = """
:root {
  --bg: #0b1220;
  --bg-panel: #121a2c;
  --bg-panel-2: #172138;
  --border: #233251;
  --text: #e6edf7;
  --muted: #8a97b3;
  --accent: #4aa8ff;
  --ok: #3ddc84;
  --warn: #ffb020;
  --bad: #ff5c7a;
  --chip: #1f2b46;
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0; background: var(--bg); color: var(--text);
  font-family: -apple-system, Segoe UI, Roboto, Ubuntu, sans-serif;
  font-size: 14px;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

.app { display: grid; grid-template-columns: 220px 1fr; min-height: 100vh; }
.sidebar {
  background: #0a1020; border-right: 1px solid var(--border);
  padding: 20px 0;
}
.brand {
  font-weight: 700; font-size: 15px; padding: 0 20px 18px 20px;
  letter-spacing: 0.4px; color: var(--accent);
  border-bottom: 1px solid var(--border); margin-bottom: 12px;
}
.brand small { display: block; color: var(--muted); font-weight: 400;
  font-size: 11px; letter-spacing: 0; margin-top: 2px; }
.nav a {
  display: block; padding: 10px 20px; color: var(--text);
  border-left: 3px solid transparent;
}
.nav a:hover { background: var(--bg-panel); text-decoration: none; }
.nav a.active {
  background: var(--bg-panel); border-left-color: var(--accent);
  color: #fff;
}

.main { padding: 22px 28px 40px 28px; }
.topbar {
  display: flex; justify-content: space-between; align-items: center;
  margin-bottom: 22px;
}
.topbar h1 { font-size: 20px; margin: 0; }
.topbar .meta { color: var(--muted); font-size: 12px; }
.btn {
  background: var(--bg-panel-2); color: var(--text);
  border: 1px solid var(--border); padding: 7px 12px; border-radius: 6px;
  cursor: pointer; font-size: 12px;
}
.btn:hover { background: var(--bg-panel); }

.btn-ai {
  background: linear-gradient(135deg, #a855f7 0%, #4f46e5 100%);
  color: #fff; border: none; padding: 4px 8px; border-radius: 4px;
  font-size: 11px; cursor: pointer; display: inline-flex; align-items: center;
  gap: 4px; font-weight: 600;
}
.btn-ai:hover { opacity: 0.9; box-shadow: 0 0 10px rgba(168, 85, 247, 0.4); }

.btn-ai-large {
  background: linear-gradient(135deg, #a855f7 0%, #4f46e5 100%);
  color: #fff; border: none; padding: 8px 16px; border-radius: 6px;
  font-size: 13px; cursor: pointer; display: inline-flex; align-items: center;
  gap: 6px; font-weight: 600;
}
.btn-ai-large:hover { opacity: 0.9; box-shadow: 0 0 12px rgba(168, 85, 247, 0.5); }

.grid { display: grid; gap: 16px; }
.grid.kpi { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
.grid.two { grid-template-columns: 1fr 1fr; }
@media (max-width: 1000px) { .grid.two { grid-template-columns: 1fr; } }

.card {
  background: var(--bg-panel); border: 1px solid var(--border);
  border-radius: 10px; padding: 16px 18px;
}
.card h2 {
  font-size: 13px; font-weight: 600; color: var(--muted);
  margin: 0 0 12px 0; letter-spacing: 0.6px; text-transform: uppercase;
}
.kpi .card .value { font-size: 26px; font-weight: 700; }
.kpi .card .label { color: var(--muted); font-size: 12px; margin-top: 4px; }
.kpi .card.accent .value { color: var(--accent); }
.kpi .card.ok .value     { color: var(--ok); }
.kpi .card.warn .value   { color: var(--warn); }
.kpi .card.bad .value    { color: var(--bad); }

table { width: 100%; border-collapse: collapse; }
th, td {
  padding: 9px 10px; text-align: left; border-bottom: 1px solid var(--border);
  font-size: 13px;
}
th { color: var(--muted); font-weight: 600; text-transform: uppercase;
  font-size: 11px; letter-spacing: 0.5px; }
tr:hover td { background: var(--bg-panel-2); }

.tag {
  display: inline-block; padding: 2px 8px; border-radius: 999px;
  font-size: 11px; font-weight: 600; background: var(--chip);
  color: var(--text);
}
.tag.ok   { background: rgba(61,220,132,0.15); color: var(--ok); }
.tag.warn { background: rgba(255,176,32,0.15); color: var(--warn); }
.tag.bad  { background: rgba(255,92,122,0.15); color: var(--bad); }
.tag.info { background: rgba(74,168,255,0.15); color: var(--accent); }

.device-tag {
  display: inline-block; padding: 1px 5px; border-radius: 4px;
  font-size: 10px; font-weight: 700; text-transform: uppercase;
  margin-right: 6px;
}
.device-tag.cisco { background: rgba(74,168,255,0.15); color: var(--accent); border: 1px solid rgba(74,168,255,0.3); }
.device-tag.linux { background: rgba(255,176,32,0.15); color: var(--warn); border: 1px solid rgba(255,176,32,0.3); }

form.filters { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 14px; }
form.filters input, form.filters select {
  background: var(--bg-panel-2); color: var(--text);
  border: 1px solid var(--border); padding: 7px 10px; border-radius: 6px;
  font-size: 13px;
}
.empty { color: var(--muted); text-align: center; padding: 20px; }
.small { color: var(--muted); font-size: 12px; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
.alert-banner {
  background: rgba(255,92,122,0.1); border: 1px solid rgba(255,92,122,0.4);
  color: var(--bad); padding: 10px 14px; border-radius: 8px;
  margin-bottom: 16px; font-size: 13px;
}

/* AI Modal styles */
.ai-modal-overlay {
  position: fixed; top: 0; left: 0; right: 0; bottom: 0;
  background: rgba(11, 18, 32, 0.85); display: none;
  justify-content: center; align-items: center; z-index: 1000;
  backdrop-filter: blur(4px);
}
.ai-modal {
  background: var(--bg-panel); border: 1px solid var(--border);
  border-radius: 12px; width: 95%; max-width: 700px; max-height: 85vh;
  display: flex; flex-direction: column;
  box-shadow: 0 10px 25px -5px rgba(0,0,0,0.5);
}
.ai-modal-header {
  padding: 16px 20px; border-bottom: 1px solid var(--border);
  display: flex; justify-content: space-between; align-items: center;
}
.ai-modal-header h2 { margin: 0; font-size: 16px; color: #fff; display: flex; align-items: center; gap: 8px; }
.ai-modal-body { padding: 20px; overflow-y: auto; font-size: 13.5px; line-height: 1.6; color: var(--text); }
.ai-modal-footer { padding: 12px 20px; border-top: 1px solid var(--border); display: flex; justify-content: flex-end; gap: 10px; }
.close-modal-btn { background: transparent; border: none; color: var(--muted); font-size: 20px; cursor: pointer; }
.close-modal-btn:hover { color: #fff; }

.loading-dots { display: inline-flex; align-items: center; gap: 4px; }
.loading-dots span {
  width: 8px; height: 8px; background-color: var(--accent); border-radius: 50%;
  display: inline-block; animation: bounce 1.4s infinite ease-in-out both;
}
.loading-dots span:nth-child(1) { animation-delay: -0.32s; }
.loading-dots span:nth-child(2) { animation-delay: -0.16s; }
@keyframes bounce {
  0%, 80%, 100% { transform: scale(0); }
  40% { transform: scale(1.0); }
}
"""

LAYOUT_JS = r"""
function openAiModal(logLine) {
  const overlay = document.getElementById('aiModalOverlay');
  const body = document.getElementById('aiModalBody');
  overlay.style.display = 'flex';
  body.innerHTML = '<div style="text-align:center;padding:40px;"><div class="loading-dots"><span></span><span></span><span></span></div><p style="margin-top:15px;color:var(--muted)">Generowanie analizy przez AI...</p></div>';
  
  fetch('/api/ai-explain', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ log_line: logLine })
  })
  .then(res => res.json())
  .then(data => {
    if (data.error) {
      body.innerHTML = '<div class="alert-banner"><b>Błąd:</b> ' + data.error + '</div>';
    } else {
      body.innerHTML = renderMarkdown(data.analysis);
    }
  })
  .catch(err => {
    body.innerHTML = '<div class="alert-banner"><b>Błąd połączenia:</b> ' + err + '</div>';
  });
}

function closeAiModal() {
  document.getElementById('aiModalOverlay').style.display = 'none';
}

function copyAiModalText() {
  const body = document.getElementById('aiModalBody');
  navigator.clipboard.writeText(body.innerText).then(() => {
    alert('Raport skopiowany do schowka!');
  });
}

function renderMarkdown(md) {
  if (!md) return '';
  let html = md;
  // Escapowanie znaków HTML w celach bezpieczeństwa
  html = html.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  
  // Code blocks: ```content```
  html = html.replace(/```(?:[a-zA-Z]+)?\n([\s\S]*?)```/g, '<pre class="mono" style="background:var(--bg-panel-2);padding:12px;border-radius:6px;border:1px solid var(--border);overflow-x:auto;color:#fff;margin:10px 0;white-space:pre-wrap;">$1</pre>');
  // Inline code: `content`
  html = html.replace(/`([^`\n]+)`/g, '<code class="mono" style="background:var(--bg-panel-2);padding:2px 5px;border-radius:4px;color:var(--accent);font-size:12px;">$1</code>');
  // Bold: **content**
  html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  // Headers: ## content
  html = html.replace(/^##\s+(.+)$/gm, '<h3 style="margin-top:18px;margin-bottom:8px;color:var(--accent);border-bottom:1px solid var(--border);padding-bottom:4px;">$1</h3>');
  // Headers: ### content
  html = html.replace(/^###\s+(.+)$/gm, '<h4 style="margin-top:14px;margin-bottom:6px;color:#fff;">$1</h4>');
  // Lists: - item or * item
  html = html.replace(/^\s*[-*]\s+(.+)$/gm, '<li style="margin-left:20px;margin-bottom:5px;">$1</li>');
  
  // Akapity (dzielenie po podwójnej nowej linii)
  html = html.split('\n\n').map(p => {
    let trimmed = p.trim();
    if (!trimmed) return '';
    if (trimmed.startsWith('<li') || trimmed.startsWith('<pre') || trimmed.startsWith('<h3') || trimmed.startsWith('<h4')) {
      return trimmed;
    }
    return '<p style="margin-top:0;margin-bottom:12px;">' + trimmed + '</p>';
  }).join('\n');
  
  return html;
}
"""


def layout(title: str, active: str, body: str) -> str:
    """Wspólny 'chrome' wszystkich podstron."""
    nav_items = [
        ("/", "Dashboard"),
        ("/events", "Events"),
        ("/alerts", "Alerts"),
        ("/sources", "Sources & Users"),
        ("/chat", "AI Assistant"),
        ("/settings", "Settings"),
        ("/about", "About"),
    ]
    nav_html = "".join(
        f'<a href="{href}" class="{"active" if active == href else ""}">{name}</a>'
        for href, name in nav_items
    )
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db_active = _STATE.get("use_db", False)
    db_label = "✅ Baza aktywna" if db_active else "Pobierz z bazy"
    db_btn_style = "background:#1a5c3a;border-color:#2a8a5a;" if db_active else ""
    return f"""<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<title>{html.escape(title)} &middot; Cisco & System Log NMS</title>
<style>{BASE_CSS}</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">CISCO & SYSTEM NMS<small>Hybrid Log Analyzer Dashboard</small></div>
    <nav class="nav">{nav_html}</nav>
  </aside>
  <main class="main">
    <div class="topbar">
      <h1>{html.escape(title)}</h1>
      <div>
        <span class="meta">Ostatnie odświeżenie: {now}</span>
        &nbsp;
        <form method="post" action="/api/fetch-db" style="display:inline">
          <button class="btn" type="submit" style="{db_btn_style}">{db_label}</button>
        </form>
        &nbsp;
        <button class="btn" onclick="location.reload()">Odśwież</button>
      </div>
    </div>
    {body}
  </main>
</div>

<!-- AI Analysis Modal -->
<div id="aiModalOverlay" class="ai-modal-overlay">
  <div class="ai-modal">
    <div class="ai-modal-header">
      <h2>&#10024; Analiza AI Zdarzenia</h2>
      <button class="close-modal-btn" onclick="closeAiModal()">&times;</button>
    </div>
    <div id="aiModalBody" class="ai-modal-body">
      <!-- Zawartość ładowana dynamicznie -->
    </div>
    <div class="ai-modal-footer">
      <button class="btn" onclick="copyAiModalText()">Kopiuj raport</button>
      <button class="btn" onclick="closeAiModal()">Zamknij</button>
    </div>
  </div>
</div>

<script>
{LAYOUT_JS}
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Strony
# ---------------------------------------------------------------------------


def render_dashboard(stats: dict[str, Any]) -> str:
    brute_count = len(stats["brute_force_suspects"])
    unknown_count = len(stats["unknown_ips"])

    alert_banner = ""
    if brute_count or unknown_count:
        parts = []
        if brute_count:
            parts.append(f"{brute_count} potencjalnych ataków brute-force")
        if unknown_count:
            parts.append(f"{unknown_count} IP spoza listy dozwolonych")
        alert_banner = (
            f'<div class="alert-banner"><b>UWAGA:</b> wykryto '
            f'{" oraz ".join(parts)}. Zobacz zakładkę '
            f'<a href="/alerts">Alerts</a>.</div>'
        )

    kpis = f"""
    <div class="grid kpi">
      <div class="card accent">
        <div class="value">{stats['total_events']}</div>
        <div class="label">Wykryte zdarzenia</div>
      </div>
      <div class="card bad" style="border-color: rgba(239, 68, 68, 0.4);">
        <div class="value" style="color:#ef4444;">{stats.get('port_down_total', 0)}</div>
        <div class="label">Awarie portów</div>
      </div>
      <div class="card info" style="border-color: rgba(168, 85, 247, 0.4);">
        <div class="value" style="color:#a855f7;">{stats.get('system_total', 0)}</div>
        <div class="label">Zdarzenia Linux</div>
      </div>
      <div class="card bad">
        <div class="value">{stats['failed_total']}</div>
        <div class="label">Nieudane logowania</div>
      </div>
      <div class="card ok">
        <div class="value">{stats['success_total']}</div>
        <div class="label">Udane logowania</div>
      </div>
      <div class="card warn">
        <div class="value">{stats['acl_total']}</div>
        <div class="label">Odrzucone przez ACL</div>
      </div>
      <div class="card">
        <div class="value">{stats['total_lines']}</div>
        <div class="label">Linie logów</div>
      </div>
    </div>
    """

    top_failed_rows = "".join(
        f"<tr><td class='mono'>{html.escape(ip)}</td>"
        f"<td><span class='tag bad'>{c}</span></td></tr>"
        for ip, c in stats["failed_by_ip"][:8]
    ) or "<tr><td colspan='2' class='empty'>Brak danych</td></tr>"

    top_acl_rows = "".join(
        f"<tr><td class='mono'>{html.escape(ip)}</td>"
        f"<td><span class='tag warn'>{c}</span></td></tr>"
        for ip, c in stats["acl_by_ip"][:8]
    ) or "<tr><td colspan='2' class='empty'>Brak danych</td></tr>"

    top_failed_device_rows = "".join(
        f"<tr><td>{html.escape(dev)}</td>"
        f"<td><span class='tag bad'>{c}</span></td></tr>"
        for dev, c in stats.get("failed_by_device", [])[:8]
    ) or "<tr><td colspan='2' class='empty'>Brak danych</td></tr>"

    top_port_down_device_rows = "".join(
        f"<tr><td>{html.escape(dev)}</td>"
        f"<td><span class='tag bad'>{c}</span></td></tr>"
        for dev, c in stats.get("port_down_by_device", [])[:8]
    ) or "<tr><td colspan='2' class='empty'>Brak danych</td></tr>"

    # Dane dla wykresów Chart.js
    chart_data = {
        "types": {
            "labels": ["Login Failed", "Login Success", "ACL Denied", "System Event", "Port Down"],
            "data": [
                stats["failed_total"],
                stats["success_total"],
                stats["acl_total"],
                stats.get("system_total", 0),
                stats.get("port_down_total", 0),
            ],
        },
        "top_failed": {
            "labels": [ip for ip, _ in stats["failed_by_ip"][:8]],
            "data":   [c  for _, c in stats["failed_by_ip"][:8]],
        },
    }

    ai_action_bar = """
    <div style="display:flex; justify-content:flex-end; margin-bottom:16px;">
      <button class="btn-ai-large" onclick="openAiSummary()">
        <span>&#10024;</span> Generuj Raport Bezpieczeństwa AI
      </button>
    </div>
    """

    body = alert_banner + ai_action_bar + kpis + f"""
    <div class="grid two" style="margin-top:16px">
      <div class="card">
        <h2>Rozkład typów zdarzeń</h2>
        <canvas id="chartTypes" height="180"></canvas>
      </div>
      <div class="card">
        <h2>Top źródła nieudanych logowań</h2>
        <canvas id="chartFailed" height="180"></canvas>
      </div>
    </div>
    <div class="grid two" style="margin-top:16px">
      <div class="card">
        <h2>Top IP: nieudane logowania</h2>
        <table><thead><tr><th>IP</th><th>liczba</th></tr></thead>
        <tbody>{top_failed_rows}</tbody></table>
      </div>
      <div class="card">
        <h2>Top IP: odrzucone przez ACL</h2>
        <table><thead><tr><th>IP</th><th>liczba</th></tr></thead>
        <tbody>{top_acl_rows}</tbody></table>
      </div>
    </div>
    <div class="grid two" style="margin-top:16px">
      <div class="card">
        <h2>Top Urządzenia: nieudane logowania</h2>
        <table><thead><tr><th>Urządzenie</th><th>liczba</th></tr></thead>
        <tbody>{top_failed_device_rows}</tbody></table>
      </div>
      <div class="card">
        <h2>Top Urządzenia: awarie portów</h2>
        <table><thead><tr><th>Urządzenie</th><th>liczba</th></tr></thead>
        <tbody>{top_port_down_device_rows}</tbody></table>
      </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <script>
      var DATA = {json.dumps(chart_data)};
      var textColor = '#8a97b3';
      if (window.Chart) {{
        Chart.defaults.color = textColor;
        Chart.defaults.borderColor = '#233251';
        new Chart(document.getElementById('chartTypes'), {{
          type: 'doughnut',
          data: {{
            labels: DATA.types.labels,
            datasets: [{{
              data: DATA.types.data,
              backgroundColor: ['#ff5c7a','#3ddc84','#ffb020','#a855f7','#ef4444'],
              borderColor: '#121a2c'
            }}]
          }},
          options: {{ plugins: {{ legend: {{ position: 'bottom' }} }} }}
        }});
        new Chart(document.getElementById('chartFailed'), {{
          type: 'bar',
          data: {{
            labels: DATA.top_failed.labels,
            datasets: [{{
              label: 'Nieudane logowania',
              data: DATA.top_failed.data,
              backgroundColor: '#4aa8ff'
            }}]
          }},
          options: {{
            plugins: {{ legend: {{ display: false }} }},
            scales: {{
              x: {{ ticks: {{ color: textColor }} }},
              y: {{ beginAtZero: true, ticks: {{ color: textColor }} }}
            }}
          }}
        }});
      }}
      
      function openAiSummary() {{
        const overlay = document.getElementById('aiModalOverlay');
        const body = document.getElementById('aiModalBody');
        overlay.style.display = 'flex';
        body.innerHTML = '<div style="text-align:center;padding:40px;"><div class="loading-dots"><span></span><span></span><span></span></div><p style="margin-top:15px;color:var(--muted)">Generowanie raportu podsumowującego przez AI...</p></div>';
        
        fetch('/api/ai-summary', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }}
        }})
        .then(res => res.json())
        .then(data => {{
          if (data.error) {{
            body.innerHTML = '<div class="alert-banner"><b>Błąd:</b> ' + data.error + '</div>';
          }} else {{
            body.innerHTML = renderMarkdown(data.analysis);
          }}
        }})
        .catch(err => {{
          body.innerHTML = '<div class="alert-banner"><b>Błąd połączenia:</b> ' + err + '</div>';
        }});
      }}
    </script>
    """
    return layout("Dashboard", "/", body)


def _kind_tag(kind: str) -> str:
    classes = {
        "login_failed":  "bad",
        "login_success": "ok",
        "acl_denied":    "warn",
        "system_event":  "info",
        "port_down":     "bad",
    }
    label = {
        "login_failed":  "LOGIN FAILED",
        "login_success": "LOGIN SUCCESS",
        "acl_denied":    "ACL DENIED",
        "system_event":  "SYSTEM EVENT",
        "port_down":     "PORT DOWN",
    }
    cls = classes.get(kind, "info")
    text = label.get(kind, kind.upper())
    return f"<span class='tag {cls}'>{text}</span>"


def render_events(stats: dict[str, Any], query: dict[str, list[str]]) -> str:
    kind_filter = (query.get("kind", [""])[0] or "").strip()
    ip_filter = (query.get("ip", [""])[0] or "").strip()
    user_filter = (query.get("user", [""])[0] or "").strip().lower()

    events = stats["events"]
    if kind_filter:
        events = [e for e in events if e["kind"] == kind_filter]
    if ip_filter:
        events = [e for e in events if ip_filter in e["ip"]]
    if user_filter:
        events = [
            e for e in events
            if e.get("user") and user_filter in e["user"].lower()
        ]

    def opt(v: str, label: str) -> str:
        sel = " selected" if v == kind_filter else ""
        return f'<option value="{v}"{sel}>{label}</option>'

    filters = f"""
    <form class="filters" method="get" action="/events">
      <select name="kind">
        <option value="">-- typ zdarzenia --</option>
        {opt("login_failed", "Login failed")}
        {opt("login_success", "Login success")}
        {opt("acl_denied", "ACL denied")}
        {opt("system_event", "System Event")}
        {opt("port_down", "Port Down")}
      </select>
      <input type="text" name="ip" placeholder="IP zawiera..."
             value="{html.escape(ip_filter)}">
      <input type="text" name="user" placeholder="użytkownik zawiera..."
             value="{html.escape(user_filter)}">
      <button class="btn" type="submit">Filtruj</button>
      <a class="btn" href="/events">Reset</a>
    </form>
    """

    if not events:
        rows = "<tr><td colspan='7' class='empty'>Brak zdarzeń pasujących do filtra</td></tr>"
    else:
        rows_list = []
        for e in events[:500]:
            timestamp = e.get('timestamp') or '-'
            kind_tag = _kind_tag(e['kind'])
            ip = e.get('ip') or '-'
            user = e.get('user') or '-'
            device_name = e.get("device") or "-"
            device_type = e.get("device_type", "cisco")
            dev_tag = f"<span class='device-tag {device_type}'>{device_type}</span> {html.escape(device_name)}"
            raw_text = e.get('raw') or ''
            js_escaped_raw = raw_text.replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').replace("\n", " ").replace("\r", " ")
            
            ai_btn = f"""<button class="btn-ai" onclick="openAiModal('{js_escaped_raw}')"><span>&#10024;</span> Analizuj</button>"""
            
            rows_list.append(
                f"<tr>"
                f"<td class='mono'>{html.escape(timestamp)}</td>"
                f"<td>{kind_tag}</td>"
                f"<td>{dev_tag}</td>"
                f"<td class='mono'>{html.escape(ip)}</td>"
                f"<td>{html.escape(user)}</td>"
                f"<td class='mono small'>{html.escape(raw_text[:140])}</td>"
                f"<td>{ai_btn}</td>"
                f"</tr>"
            )
        rows = "".join(rows_list)

    shown = min(len(events), 500)
    more = (
        f"<div class='small' style='margin-top:10px'>"
        f"Pokazano {shown} z {len(events)} zdarzeń "
        f"(limit listy 500).</div>"
        if len(events) > 500 else
        f"<div class='small' style='margin-top:10px'>Łącznie: {len(events)}</div>"
    )

    body = f"""
    {filters}
    <div class="card">
      <table>
        <thead><tr>
          <th>Timestamp</th><th>Typ</th><th>Urządzenie</th><th>Source IP</th>
          <th>User</th><th>Raw Log</th><th>Akcje AI</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
      {more}
    </div>
    """
    return layout("Events", "/events", body)


def render_alerts(stats: dict[str, Any]) -> str:
    bf_rows = "".join(
        f"<tr><td class='mono'>{html.escape(ip)}</td>"
        f"<td><span class='tag bad'>{c}</span></td>"
        f"<td><div style='display:flex; gap:12px; align-items:center;'>"
        f"<a href='/events?kind=login_failed&ip={html.escape(ip)}'>zobacz zdarzenia &rsaquo;</a>"
        f"<button class='btn-ai' onclick=\"openAiModal('Analiza IP: {html.escape(ip)}. Ten adres wykonał {c} nieudanych prób logowania (podejrzenie brute-force).')\"><span>&#10024;</span> Analizuj IP</button>"
        f"</div></td></tr>"
        for ip, c in stats["brute_force_suspects"]
    ) or "<tr><td colspan='3' class='empty'>Brak podejrzeń brute-force</td></tr>"

    device_rows = "".join(
        f"<tr><td class='mono'><b>{html.escape(dev)}</b></td>"
        f"<td><span class='tag bad'>{val}</span></td>"
        f"<td><span class='tag warning'>{score}x średniej</span></td>"
        f"<td><span class='tag bad' style='background-color:#fed7d7; color:#c53030;'>&#9888; Wymagany przegląd fizyczny</span></td>"
        f"<td><div style='display:flex; gap:12px; align-items:center;'>"
        f"<a href='/events?device={html.escape(dev)}&kind=port_down'>zobacz zdarzenia &rsaquo;</a>"
        f"<button class='btn-ai' onclick=\"openAiModal('Analiza Urządzenia: {html.escape(dev)}. Algorytm ML K-Means wykrył anomalną awaryjność tego urządzenia ({val} awarii portów, co stanowi {score}x średniej floty). Zarekomenduj kroki diagnostyczne i fizyczne dla administratora sieci.')\"><span>&#10024;</span> Analizuj AI</button>"
        f"</div></td></tr>"
        for dev, val, score in stats.get("anomalous_devices", [])
    ) or "<tr><td colspan='5' class='empty'>&#9989; Wszystkie urządzenia pracują w normie (brak anomalii awaryjności we flocie)</td></tr>"

    unknown_rows = "".join(
        f"<tr><td class='mono'>{html.escape(ip)}</td>"
        f"<td><div style='display:flex; gap:12px; align-items:center;'>"
        f"<a href='/events?ip={html.escape(ip)}'>zobacz zdarzenia &rsaquo;</a>"
        f"<button class='btn-ai' onclick=\"openAiModal('Analiza IP: {html.escape(ip)}. Ten adres pojawił się w logach, ale jest spoza listy zdefiniowanych bezpiecznych sieci (Allowed_IPS).')\"><span>&#10024;</span> Analizuj IP</button>"
        f"</div></td></tr>"
        for ip in stats["unknown_ips"]
    ) or "<tr><td colspan='2' class='empty'>Wszystkie IP są na whiteliscie</td></tr>"

    body = f"""
    <div class="card" style="margin-bottom:16px">
      <h2>Potencjalne ataki brute-force (&ge; {_STATE['bf_threshold']} nieudanych logowań)</h2>
      <table>
        <thead><tr><th>Source IP</th><th>Nieudane</th><th>Akcje</th></tr></thead>
        <tbody>{bf_rows}</tbody>
      </table>
    </div>
    <div class="card" style="margin-bottom:16px">
      <h2>Diagnostyka urządzeń (Dynamiczna detekcja anomalii ML K-Means)</h2>
      <p style="font-size:0.9rem; color:#a0aec0; margin-bottom:12px;">
        Algorytm K-Means (K=2) analizuje rozkład awarii interfejsów w całej flocie przełączników i routerów Cisco, automatycznie flagując urządzenia o statystycznie podwyższonej awaryjności bez stosowania sztywnych limitów ilościowych.
      </p>
      <table>
        <thead><tr><th>Urządzenie</th><th>Suma awarii</th><th>ML Score</th><th>Rekomendacja</th><th>Akcje</th></tr></thead>
        <tbody>{device_rows}</tbody>
      </table>
    </div>
    <div class="card">
      <h2>Adresy IP spoza whitelisty</h2>
      <table>
        <thead><tr><th>IP</th><th>Akcje</th></tr></thead>
        <tbody>{unknown_rows}</tbody>
      </table>
    </div>
    """
    return layout("Alerts", "/alerts", body)


def render_sources(stats: dict[str, Any]) -> str:
    success_rows = "".join(
        f"<tr><td class='mono'>{html.escape(ip)}</td>"
        f"<td><span class='tag ok'>{c}</span></td></tr>"
        for ip, c in stats["success_by_ip"][:20]
    ) or "<tr><td colspan='2' class='empty'>Brak danych</td></tr>"

    users_rows = "".join(
        f"<tr><td>{html.escape(u)}</td>"
        f"<td><span class='tag bad'>{c}</span></td></tr>"
        for u, c in stats["targeted_users"]
    ) or "<tr><td colspan='2' class='empty'>Brak danych</td></tr>"

    body = f"""
    <div class="grid two">
      <div class="card">
        <h2>Top IP: udane logowania</h2>
        <table>
          <thead><tr><th>IP</th><th>liczba</th></tr></thead>
          <tbody>{success_rows}</tbody>
        </table>
      </div>
      <div class="card">
        <h2>Najczęściej atakowani użytkownicy</h2>
        <table>
          <thead><tr><th>Użytkownik</th><th>nieudane logowania</th></tr></thead>
          <tbody>{users_rows}</tbody>
        </table>
      </div>
    </div>
    """
    return layout("Sources & Users", "/sources", body)


def render_settings() -> str:
    cfg = _STATE.get("ai_config", {})
    provider = cfg.get("provider", "ollama")
    api_key = cfg.get("api_key", "")
    api_url = cfg.get("api_url", "")
    model = cfg.get("model", "")

    # Mask API key if set
    masked_key = ""
    if api_key:
        masked_key = "*" * 12

    opt_gemini = " selected" if provider == "gemini" else ""
    opt_ollama = " selected" if provider == "ollama" else ""
    opt_openai = " selected" if provider == "openai" else ""

    body = f"""
    <div class="grid two">
      <div class="card">
        <h2>Konfiguracja AI (Generative AI Settings)</h2>
        <form method="post" action="/api/ai-config" id="configForm" style="display:flex; flex-direction:column; gap:12px;">
          <div>
            <label style="display:block; margin-bottom:4px; font-weight:600; font-size:12px;">Dostawca LLM</label>
            <select id="provider" name="provider" style="width:100%; padding:8px; background:var(--bg-panel-2); color:var(--text); border:1px solid var(--border); border-radius:6px;" onchange="onProviderChange()">
              <option value="gemini"{opt_gemini}>Google Gemini API</option>
              <option value="ollama"{opt_ollama}>Ollama (Local LLM)</option>
              <option value="openai"{opt_openai}>Local / OpenAI-compatible API</option>
            </select>
          </div>
          <div>
            <label style="display:block; margin-bottom:4px; font-weight:600; font-size:12px;">Adres URL Interfejsu API</label>
            <input type="text" id="apiUrl" name="api_url" value="{html.escape(api_url)}" style="width:100%; padding:8px; background:var(--bg-panel-2); color:var(--text); border:1px solid var(--border); border-radius:6px;">
            <small style="color:var(--muted); font-size:11px;" id="urlHint">Dla Ollama np. http://localhost:11434</small>
          </div>
          <div>
            <label style="display:block; margin-bottom:4px; font-weight:600; font-size:12px;">Nazwa Modelu</label>
            <input type="text" id="model" name="model" value="{html.escape(model)}" style="width:100%; padding:8px; background:var(--bg-panel-2); color:var(--text); border:1px solid var(--border); border-radius:6px;">
            <small style="color:var(--muted); font-size:11px;" id="modelHint">np. llama3, mistral, gemma dla Ollama; gemini-2.5-flash dla Gemini</small>
          </div>
          <div>
            <label style="display:block; margin-bottom:4px; font-weight:600; font-size:12px;">Klucz API (API Key)</label>
            <input type="password" id="apiKey" name="api_key" value="{html.escape(masked_key)}" placeholder="Pozostaw puste aby nie zmieniać" style="width:100%; padding:8px; background:var(--bg-panel-2); color:var(--text); border:1px solid var(--border); border-radius:6px;">
            <small style="color:var(--muted); font-size:11px;">Wymagany dla Gemini API. Wyszukiwany w zmiennej środowiskowej GEMINI_API_KEY lub podany tutaj.</small>
          </div>
          
          <div style="display:flex; gap:10px; margin-top:10px;">
            <button class="btn" type="submit" style="background:#1a5c3a; border-color:#2a8a5a; font-weight:600; flex:1;">Zapisz Konfigurację</button>
            <button class="btn" type="button" id="testBtn" onclick="testConnection()" style="flex:1;">Testuj Połączenie</button>
          </div>
        </form>
      </div>

      <div class="card">
        <h2>Przewodnik po Integracji AI</h2>
        <div style="line-height:1.6; font-size:13px; color:var(--muted);">
          <p><b style="color:#fff;">1. Local LLM (Ollama) [Zalecane]:</b><br>
          Zainstaluj i uruchom Ollama na swoim komputerze, a następnie pobierz model:<br>
          <code style="background:var(--bg-panel-2); padding:2px 6px; border-radius:4px; color:var(--accent);">ollama run llama3</code> lub <code style="background:var(--bg-panel-2); padding:2px 6px; border-radius:4px; color:var(--accent);">ollama run mistral</code>.<br>
          Upewnij się, że usługa działa pod adresem <code style="color:#fff;">http://localhost:11434</code> (jest to domyślne zachowanie).</p>
          
          <p><b style="color:#fff;">2. Google Gemini API:</b><br>
          Wymaga dostępu do Internetu oraz klucza API Gemini (możesz go wygenerować w Google AI Studio).<br>
          Domyślny model to <code style="color:#fff;">gemini-2.5-flash</code>. Adres URL API dla Gemini jest ignorowany (klient automatycznie łączy się z oficjalnym serwerem).</p>

          <p><b style="color:#fff;">3. Inny lokalny serwer (np. LM Studio):</b><br>
          Wybierz opcję <i>Local / OpenAI-compatible API</i>, wprowadź pełny adres (np. <code style="color:#fff;">http://localhost:1234</code>) oraz właściwą nazwę modelu załadowanego w aplikacji.</p>
        </div>
      </div>
    </div>
    <div id="testResult" style="margin-top:16px;"></div>

    <script>
    function onProviderChange() {{
      const provider = document.getElementById('provider').value;
      const urlInput = document.getElementById('apiUrl');
      const modelInput = document.getElementById('model');
      const urlHint = document.getElementById('urlHint');
      const modelHint = document.getElementById('modelHint');
      
      if (provider === 'gemini') {{
        urlInput.value = 'https://generativelanguage.googleapis.com';
        urlInput.disabled = true;
        modelInput.value = 'gemini-2.5-flash';
        urlHint.innerText = 'Dla Gemini URL jest stały (https://generativelanguage.googleapis.com).';
        modelHint.innerText = 'Sugerowane modele: gemini-2.5-flash, gemini-2.5-pro';
      }} else if (provider === 'ollama') {{
        urlInput.value = 'http://localhost:11434';
        urlInput.disabled = false;
        modelInput.value = 'llama3';
        urlHint.innerText = 'Domyślny adres Ollama to http://localhost:11434';
        modelHint.innerText = 'Sugerowane modele: llama3, mistral, gemma, codellama';
      }} else {{
        urlInput.value = 'http://localhost:1234';
        urlInput.disabled = false;
        modelInput.value = 'local-model';
        urlHint.innerText = 'Wprowadź adres API kompatybilnego z OpenAI (np. LM Studio, LocalAI)';
        modelHint.innerText = 'Wprowadź nazwę modelu załadowanego w serwerze';
      }}
    }}

    function testConnection() {{
      const btn = document.getElementById('testBtn');
      const resultDiv = document.getElementById('testResult');
      
      const provider = document.getElementById('provider').value;
      const apiKey = document.getElementById('apiKey').value;
      const apiUrl = document.getElementById('apiUrl').value;
      const model = document.getElementById('model').value;
      
      btn.disabled = true;
      btn.innerText = 'Testowanie...';
      resultDiv.innerHTML = '<div style="text-align:center;padding:20px;"><div class="loading-dots"><span></span><span></span><span></span></div><p style="margin-top:10px;color:var(--muted)">Testowanie połączenia z LLM...</p></div>';
      resultDiv.className = '';
      resultDiv.style = '';
      
      fetch('/api/ai-test', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ provider, api_key: apiKey, api_url: apiUrl, model }})
      }})
      .then(res => res.json())
      .then(data => {{
        btn.disabled = false;
        btn.innerText = 'Testuj Połączenie';
        if (data.success) {{
          resultDiv.innerHTML = '<b>Sukces!</b> ' + data.message;
          resultDiv.className = 'alert-banner';
          resultDiv.style.background = 'rgba(61,220,132,0.1)';
          resultDiv.style.borderColor = 'rgba(61,220,132,0.4)';
          resultDiv.style.color = 'var(--ok)';
        }} else {{
          resultDiv.innerHTML = '<b>Błąd połączenia:</b> ' + data.error;
          resultDiv.className = 'alert-banner';
          resultDiv.style.background = 'rgba(255,92,122,0.1)';
          resultDiv.style.borderColor = 'rgba(255,92,122,0.4)';
          resultDiv.style.color = 'var(--bad)';
        }}
      }})
      .catch(err => {{
        btn.disabled = false;
        btn.innerText = 'Testuj Połączenie';
        resultDiv.innerHTML = '<b>Błąd połączenia:</b> ' + err;
        resultDiv.className = 'alert-banner';
        resultDiv.style.background = 'rgba(255,92,122,0.1)';
        resultDiv.style.borderColor = 'rgba(255,92,122,0.4)';
        resultDiv.style.color = 'var(--bad)';
      }});
    }}
    
    // Uruchom na starcie, aby zsynchronizować stan pól
    document.addEventListener("DOMContentLoaded", () => {{
      const provider = document.getElementById('provider').value;
      if (provider === 'gemini') {{
        document.getElementById('apiUrl').disabled = true;
      }}
    }});
    </script>
    """
    return layout("AI Settings", "/settings", body)


def render_chat() -> str:
    body = """
    <div style="display:flex; flex-direction:column; height:calc(100vh - 120px); max-height:800px; background:var(--bg-panel); border:1px solid var(--border); border-radius:10px; overflow:hidden;">
      <!-- Nagłówek czatu -->
      <div style="padding:14px 20px; border-bottom:1px solid var(--border); background:rgba(0,0,0,0.1); display:flex; justify-content:space-between; align-items:center;">
        <div style="display:flex; align-items:center; gap:8px;">
          <span style="font-size:16px;">🤖</span>
          <b style="color:#fff;">Czat z Asystentem NMS</b>
          <span style="font-size:11px; padding:2px 6px; background:rgba(168, 85, 247, 0.2); color:#a855f7; border-radius:4px; font-weight:600;">AI ACTIVE</span>
        </div>
        <button class="btn" onclick="clearChat()" style="padding:4px 8px; font-size:11px;">Wyczyść historię</button>
      </div>
      
      <!-- Sugestie pytań -->
      <div id="suggestions" style="padding:10px 15px; border-bottom:1px solid var(--border); background:rgba(0,0,0,0.05); display:flex; gap:8px; flex-wrap:wrap; font-size:12px;">
        <span style="color:var(--muted); align-self:center; margin-right:4px;">Zaproponuj pytanie:</span>
        <button class="btn" style="padding:3px 8px; border-radius:15px; background:var(--bg-panel-2);" onclick="useSuggestion('Jakie zagrożenia wykryłeś w logach w ciągu ostatnich 7 dni?')">Zagrożenia w logach?</button>
        <button class="btn" style="padding:3px 8px; border-radius:15px; background:var(--bg-panel-2);" onclick="useSuggestion('Przeanalizuj udane logowania użytkownika root. Czy są podejrzane?')">Logowania użytkownika root?</button>
        <button class="btn" style="padding:3px 8px; border-radius:15px; background:var(--bg-panel-2);" onclick="useSuggestion('Czy w logach widać zablokowane pakiety przez zapory (UFW)?')">Blokady firewall (UFW)?</button>
        <button class="btn" style="padding:3px 8px; border-radius:15px; background:var(--bg-panel-2);" onclick="useSuggestion('Jak zapobiegać atakom brute-force na SSH na podstawie tych logów?')">Zalecenia brute-force?</button>
      </div>

      <!-- Wiadomości -->
      <div id="chatMessages" style="flex:1; padding:20px; overflow-y:auto; display:flex; flex-direction:column; gap:16px;">
        <!-- Pierwsza powitalna wiadomość -->
        <div style="display:flex; gap:12px;">
          <div style="width:30px; height:30px; border-radius:50%; background:linear-gradient(135deg, #a855f7, #4f46e5); display:flex; align-items:center; justify-content:center; font-size:14px; flex-shrink:0;">🤖</div>
          <div style="background:var(--bg-panel-2); padding:12px 16px; border-radius:12px; border-top-left-radius:2px; max-width:80%; line-height:1.5;">
            Cześć! Jestem Twoim wbudowanym asystentem bezpieczeństwa NMS. 
            Automatycznie analizuję zaimportowane logi sieciowe Cisco oraz logi systemowe Linux.<br><br>
            Możesz mnie zapytać o konkretne IP, użytkowników, ataki brute-force lub poprosić o ogólne porady bezpieczeństwa dla wykrytych zdarzeń. W czym mogę pomóc?
          </div>
        </div>
      </div>

      <!-- Obszar wprowadzania wiadomości -->
      <div style="padding:15px 20px; border-top:1px solid var(--border); background:rgba(0,0,0,0.1); display:flex; gap:10px;">
        <input type="text" id="chatInput" placeholder="Napisz do asystenta AI..." onkeydown="if(event.key==='Enter') sendMessage()" style="flex:1; padding:10px 14px; background:var(--bg-panel-2); color:var(--text); border:1px solid var(--border); border-radius:8px; font-size:13.5px; outline:none;" autofocus>
        <button class="btn-ai-large" onclick="sendMessage()" style="padding:0 20px; height:38px; border-radius:8px;">Wyślij</button>
      </div>
    </div>

    <script>
    let chatHistory = [];

    function clearChat() {
      const messagesDiv = document.getElementById('chatMessages');
      messagesDiv.innerHTML = `
        <div style="display:flex; gap:12px;">
          <div style="width:30px; height:30px; border-radius:50%; background:linear-gradient(135deg, #a855f7, #4f46e5); display:flex; align-items:center; justify-content:center; font-size:14px; flex-shrink:0;">🤖</div>
          <div style="background:var(--bg-panel-2); padding:12px 16px; border-radius:12px; border-top-left-radius:2px; max-width:80%; line-height:1.5;">
            Czat wyczyszczony. W czym mogę pomóc?
          </div>
        </div>
      `;
      chatHistory = [];
    }

    function useSuggestion(text) {
      document.getElementById('chatInput').value = text;
      sendMessage();
    }

    function sendMessage() {
      const input = document.getElementById('chatInput');
      const text = input.value.trim();
      if (!text) return;

      input.value = '';
      const messagesDiv = document.getElementById('chatMessages');

      // 1. Dodaj wiadomość użytkownika do UI
      const userMsgHtml = `
        <div style="display:flex; gap:12px; justify-content:flex-end;">
          <div style="background:var(--accent); color:#000; padding:12px 16px; border-radius:12px; border-top-right-radius:2px; max-width:80%; line-height:1.5; font-weight:550;">
            ${escapeHtml(text)}
          </div>
          <div style="width:30px; height:30px; border-radius:50%; background:var(--border); display:flex; align-items:center; justify-content:center; font-size:12px; flex-shrink:0; font-weight:bold; color:var(--text);">TY</div>
        </div>
      `;
      messagesDiv.innerHTML += userMsgHtml;
      messagesDiv.scrollTop = messagesDiv.scrollHeight;

      // 2. Dodaj placeholder dla odpowiedzi AI
      const aiResponseId = 'ai-resp-' + Date.now();
      const aiPlaceholderHtml = `
        <div style="display:flex; gap:12px;" id="${aiResponseId}">
          <div style="width:30px; height:30px; border-radius:50%; background:linear-gradient(135deg, #a855f7, #4f46e5); display:flex; align-items:center; justify-content:center; font-size:14px; flex-shrink:0;">🤖</div>
          <div style="background:var(--bg-panel-2); padding:12px 16px; border-radius:12px; border-top-left-radius:2px; max-width:80%; line-height:1.5;">
            <div class="loading-dots"><span></span><span></span><span></span></div>
          </div>
        </div>
      `;
      messagesDiv.innerHTML += aiPlaceholderHtml;
      messagesDiv.scrollTop = messagesDiv.scrollHeight;

      // 3. Przygotuj dane do wysłania
      const payload = {
        message: text,
        history: chatHistory
      };

      // Zapisz w lokalnej historii
      chatHistory.push({ role: 'user', content: text });

      // 4. Pobierz odpowiedź z serwera
      fetch('/api/ai-chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      })
      .then(res => res.json())
      .then(data => {
        const responseDiv = document.getElementById(aiResponseId);
        const textContainer = responseDiv.querySelector('div:nth-child(2)');
        
        if (data.error) {
          textContainer.innerHTML = `<div class="alert-banner" style="margin:0;"><b>Błąd:</b> ${data.error}</div>`;
        } else {
          textContainer.innerHTML = renderMarkdown(data.reply);
          chatHistory.push({ role: 'assistant', content: data.reply });
        }
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
      })
      .catch(err => {
        const responseDiv = document.getElementById(aiResponseId);
        const textContainer = responseDiv.querySelector('div:nth-child(2)');
        textContainer.innerHTML = `<div class="alert-banner" style="margin:0;"><b>Błąd połączenia:</b> ${err}</div>`;
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
      });
    }

    function escapeHtml(unsafe) {
      return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }
    </script>
    """
    return layout("AI Assistant", "/chat", body)


def render_about() -> str:
    ok_tag = "<span class='tag ok'>OK</span>"
    missing_tag = "<span class='tag bad'>MISSING</span>"
    log_list = "".join(
        f"<li class='mono'>{html.escape(str(p))} "
        f"{ok_tag if p.exists() else missing_tag}"
        f"</li>"
        for p in _STATE["log_paths"]
    ) or "<li class='empty'>Brak skonfigurowanych plików</li>"

    allowed = _STATE["allowed_networks"]
    allowed_list = "".join(
        f"<li class='mono'>{html.escape(str(n))}</li>" for n in allowed
    ) or "<li class='empty'>Brak (każde IP traktowane jako 'spoza listy')</li>"

    body = f"""
    <div class="grid two">
      <div class="card">
        <h2>Skonfigurowane pliki logów</h2>
        <ul>{log_list}</ul>
        <div class="small">Analiza uruchamiana na żądanie przy każdym odświeżeniu.</div>
      </div>
      <div class="card">
        <h2>Whitelista (Allowed IPs)</h2>
        <div class="small">Plik: {html.escape(str(_STATE['allowed_path']))}</div>
        <ul>{allowed_list}</ul>
      </div>
    </div>
    <div class="card" style="margin-top:16px">
      <h2>Integracja</h2>
      <p>Wyniki analizy w formacie JSON dostępne są pod adresem
        <a href="/api/stats"><span class="mono">/api/stats</span></a>.</p>
      <p class="small">Próg brute-force: <b>{_STATE['bf_threshold']}</b> nieudanych logowań z jednego IP.</p>
    </div>
    """
    return layout("About", "/about", body)


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


class Handler(BaseHTTPRequestHandler):
    # cichsze logowanie requestów
    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {self.address_string()} - "
              f"{format % args}")

    def _send_html(self, body: str, status: int = 200) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, payload: Any, status: int = 200) -> None:
        data = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        route = parsed.path.rstrip("/") or "/"

        try:
            stats = aggregate(run_analysis())
        except Exception as exc:  # pragma: no cover - obrona przed zepsutym logiem
            self._send_html(
                layout(
                    "Error", "/",
                    f"<div class='alert-banner'>Błąd analizy: "
                    f"{html.escape(str(exc))}</div>",
                ),
                status=500,
            )
            return

        if route == "/":
            self._send_html(render_dashboard(stats))
        elif route == "/events":
            self._send_html(render_events(stats, query))
        elif route == "/alerts":
            self._send_html(render_alerts(stats))
        elif route == "/sources":
            self._send_html(render_sources(stats))
        elif route == "/chat":
            self._send_html(render_chat())
        elif route == "/settings":
            self._send_html(render_settings())
        elif route == "/about":
            self._send_html(render_about())
        elif route == "/api/stats":
            # lekka wersja bez pełnych 'raw' linii
            light = {k: v for k, v in stats.items() if k != "events"}
            light["event_count"] = len(stats["events"])
            self._send_json(light)
        elif route == "/api/events":
            self._send_json(stats["events"])
        else:
            self._send_html(
                layout("Not found", "/",
                       "<div class='card empty'>404 - strona nie istnieje</div>"),
                status=404,
            )

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"

        if route == "/api/fetch-db":
            _STATE["use_db"] = True
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()
        elif route == "/api/ai-config":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            content_type = self.headers.get('Content-Type', '')
            if 'application/json' in content_type:
                data = json.loads(body)
            else:
                params = parse_qs(body)
                data = {k: v[0] for k, v in params.items()}
            
            provider = data.get("provider", "ollama")
            api_url = data.get("api_url", "")
            model = data.get("model", "")
            api_key = data.get("api_key", "")
            
            # Jeśli wprowadzono masked key lub puste, nie nadpisuj
            if api_key == "************" or not api_key:
                api_key = _STATE["ai_config"]["api_key"]
                
            _STATE["ai_config"] = {
                "provider": provider,
                "api_url": api_url,
                "model": model,
                "api_key": api_key
            }
            AIClient.set_config(_STATE["ai_config"])
            
            if 'application/json' in content_type:
                self._send_json({"success": True, "message": "Konfiguracja zapisana."})
            else:
                self.send_response(303)
                self.send_header("Location", "/settings")
                self.end_headers()
        elif route == "/api/ai-test":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body)
            
            provider = data.get("provider", "ollama")
            api_url = data.get("api_url", "")
            model = data.get("model", "")
            api_key = data.get("api_key", "")
            
            if api_key == "************" or not api_key:
                api_key = _STATE["ai_config"]["api_key"]
                
            old_config = _STATE["ai_config"]
            _STATE["ai_config"] = {
                "provider": provider,
                "api_url": api_url,
                "model": model,
                "api_key": api_key
            }
            AIClient.set_config(_STATE["ai_config"])
            
            try:
                test_prompt = "Say only: 'NMS assistant connection success!'"
                response = AIClient.generate(test_prompt, system_instruction="Odpowiedz krótko i po angielsku.")
                if "connection success" in response.lower() or len(response.strip()) > 0:
                    self._send_json({"success": True, "message": f"LLM odpowiedział poprawnie: {html.escape(response[:100])}"})
                else:
                    self._send_json({"success": False, "error": f"LLM zwrócił nieoczekiwaną odpowiedź: {response}"})
            except Exception as e:
                self._send_json({"success": False, "error": str(e)})
            finally:
                _STATE["ai_config"] = old_config
                AIClient.set_config(old_config)
        elif route == "/api/ai-explain":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body)
            log_line = data.get("log_line", "")
            
            if not log_line:
                self._send_json({"error": "Brak wpisu logu do przeanalizowania."}, status=400)
                return
                
            try:
                analysis = AIClient.generate(log_line, system_instruction=SYSTEM_EXPLAIN)
                self._send_json({"analysis": analysis})
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        elif route == "/api/ai-summary":
            try:
                stats = aggregate(run_analysis())
                brute_force_ips = [ip for ip, _ in stats.get("brute_force_suspects", [])]
                unknown_ips = stats.get("unknown_ips", [])
                top_failed = stats.get("failed_by_ip", [])[:5]
                top_users = stats.get("targeted_users", [])[:5]
                
                stats_prompt = (
                    f"Oto podsumowanie statystyk z ostatniego skanowania:\n"
                    f"- Łącznie zdarzeń: {stats.get('total_events', 0)}\n"
                    f"- Logi systemowe Linux: {stats.get('system_total', 0)}\n"
                    f"- Nieudane logowania: {stats.get('failed_total', 0)}\n"
                    f"- Udane logowania: {stats.get('success_total', 0)}\n"
                    f"- Blokady ACL: {stats.get('acl_total', 0)}\n"
                    f"- Wykryte adresy IP podejrzane o ataki brute-force: {', '.join(brute_force_ips) or 'Brak'}\n"
                    f"- Adresy IP spoza whitelisty: {', '.join(unknown_ips) or 'Brak'}\n"
                    f"- Najczęstsze źródła nieudanych logowań: {top_failed}\n"
                    f"- Najczęściej atakowane konta użytkowników: {top_users}\n"
                )
                
                analysis = AIClient.generate(stats_prompt, system_instruction=SYSTEM_SUMMARY)
                self._send_json({"analysis": analysis})
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        elif route == "/api/ai-chat":
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            data = json.loads(body)
            message = data.get("message", "")
            history = data.get("history", [])
            
            if not message:
                self._send_json({"error": "Pusta wiadomość."}, status=400)
                return
                
            try:
                stats = aggregate(run_analysis())
                recent_events = stats.get("events", [])[:15]
                recent_events_str = "\n".join(
                    f"[{e.get('timestamp') or '-'}] {e.get('device', '-')}({e.get('device_type', 'cisco')}): {e.get('raw', '')}"
                    for e in recent_events
                )
                
                context = (
                    f"Statystyki NMS:\n"
                    f"- Łącznie linii logów: {stats.get('total_lines', 0)}\n"
                    f"- Zdarzenia: {stats.get('total_events', 0)} (Cisco Login Failed: {stats.get('failed_total', 0)}, Success: {stats.get('success_total', 0)}, ACL: {stats.get('acl_total', 0)}, Linux: {stats.get('system_total', 0)})\n"
                    f"- Ataki brute-force z IP: {', '.join(ip for ip, _ in stats.get('brute_force_suspects', [])) or 'Brak'}\n"
                    f"- IP spoza whitelisty: {', '.join(stats.get('unknown_ips', [])) or 'Brak'}\n\n"
                    f"Ostatnie 15 zdarzeń w logach:\n"
                    f"{recent_events_str}"
                )
                
                system_instruction = SYSTEM_CHAT.format(context=context)
                prompt = message
                
                if history:
                    history_list = []
                    for h in history[-8:]:
                        role = "Użytkownik" if h["role"] == "user" else "Asystent AI"
                        history_list.append(f"{role}: {h['content']}")
                    history_text = "\n".join(history_list)
                    prompt = f"Oto historia poprzedniej rozmowy:\n{history_text}\n\nNajnowsza wiadomość od Użytkownika:\n{message}"
                
                reply = AIClient.generate(prompt, system_instruction=system_instruction)
                self._send_json({"reply": reply})
            except Exception as e:
                self._send_json({"error": str(e)}, status=500)
        else:
            self._send_html(
                layout("Not found", "/",
                       "<div class='card empty'>404</div>"),
                status=404,
            )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Interfejs HTML (NMS) dla analizatora logów Cisco IOS",
    )
    parser.add_argument(
        "--log",
        action="append",
        default=None,
        help="Ścieżka do pliku z logami (można podać wielokrotnie). "
             "Domyślnie: Sample_Logs/Cisco_ios.log",
    )
    parser.add_argument(
        "--allowed",
        default="Allowed_IPS",
        help="Plik z dozwolonymi IP/podsieciami (domyślnie: Allowed_IPS)",
    )
    parser.add_argument(
        "--bf-threshold", type=int, default=3,
        help="Próg brute-force (domyślnie: 3)",
    )
    parser.add_argument(
        "--port-failure-threshold", type=int, default=3,
        help="Próg częstych awarii portu (domyślnie: 3)",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)

    # PostgreSQL
    parser.add_argument(
        "--db", action="store_true", default=True,
        help="Pobieraj logi z bazy PostgreSQL (domyślnie włączone)",
    )
    parser.add_argument(
        "--no-db", action="store_true", default=False,
        help="Wyłącz tryb bazy danych, czytaj z plików logów",
    )
    parser.add_argument("--db-host", default="127.0.0.1")
    parser.add_argument("--db-port", type=int, default=5432)
    parser.add_argument("--db-name", default="cisco_logs")
    parser.add_argument("--db-user", default="postgres")
    parser.add_argument("--db-password", default="ZAQ!2wsx")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    log_args = args.log or ["Sample_Logs/Cisco_ios.log"]
    _STATE["log_paths"] = [Path(p) for p in log_args]
    _STATE["allowed_path"] = Path(args.allowed)
    _STATE["allowed_networks"] = load_allowed_networks(_STATE["allowed_path"])
    _STATE["bf_threshold"] = args.bf_threshold
    _STATE["port_failure_threshold"] = args.port_failure_threshold

    # PostgreSQL
    _STATE["use_db"] = args.db and not args.no_db
    _STATE["db_config"] = {
        "host": args.db_host,
        "port": args.db_port,
        "dbname": args.db_name,
        "user": args.db_user,
        "password": args.db_password,
    }

    # Inicjalizacja konfiguracji AI
    AIClient.set_config(_STATE["ai_config"])

    if args.db:
        print(f"[i] Tryb bazy danych: {args.db_name}@{args.db_host}:{args.db_port}")
    else:
        missing = [p for p in _STATE["log_paths"] if not p.exists()]
        if missing:
            for p in missing:
                print(f"[!] Ostrzeżenie: plik logu nie istnieje: {p}")

    httpd = HTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"[i] Cisco Log NMS dashboard uruchomiony: {url}")
    if args.db:
        print(f"[i] Źródło danych: PostgreSQL ({args.db_name})")
    else:
        print(f"[i] Analizowane pliki: {', '.join(str(p) for p in _STATE['log_paths'])}")
    print(f"[i] Whitelista: {_STATE['allowed_path']} "
          f"({len(_STATE['allowed_networks'])} wpisów)")
    print("[i] Zatrzymanie: Ctrl+C")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[i] Zatrzymano.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
