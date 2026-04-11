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
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from Cisco_Log_Analyzer import (
    AnalysisResult,
    analyze,
    load_allowed_networks,
)


# ---------------------------------------------------------------------------
# Stan globalny (ustawiany w main() przed startem serwera)
# ---------------------------------------------------------------------------

_STATE: dict[str, Any] = {
    "log_paths": [],
    "allowed_path": Path("Allowed_IPS"),
    "allowed_networks": [],
    "bf_threshold": 3,
}


# ---------------------------------------------------------------------------
# Analiza i agregacja wyników
# ---------------------------------------------------------------------------


def run_analysis() -> dict[str, AnalysisResult]:
    """Uruchamia analizę na wszystkich skonfigurowanych plikach logów."""
    results: dict[str, AnalysisResult] = {}
    for p in _STATE["log_paths"]:
        if p.exists():
            results[str(p)] = analyze(
                p,
                _STATE["allowed_networks"],
                brute_force_threshold=_STATE["bf_threshold"],
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

    brute_force = [
        (ip, c) for ip, c in failed.most_common()
        if c >= _STATE["bf_threshold"]
    ]

    targeted_users = Counter(
        e["user"] for e in events
        if e["kind"] == "login_failed" and e.get("user")
    )

    return {
        "total_files": len(results),
        "total_lines": total_lines,
        "total_events": len(events),
        "events": events,
        "failed_total": sum(failed.values()),
        "success_total": sum(success.values()),
        "acl_total": sum(acl.values()),
        "failed_by_ip": failed.most_common(),
        "success_by_ip": success.most_common(),
        "acl_by_ip": acl.most_common(),
        "unknown_ips": sorted(unknown_ips),
        "brute_force_suspects": brute_force,
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

.grid { display: grid; gap: 16px; }
.grid.kpi { grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); }
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
"""


def layout(title: str, active: str, body: str) -> str:
    """Wspólny 'chrome' wszystkich podstron."""
    nav_items = [
        ("/", "Dashboard"),
        ("/events", "Events"),
        ("/alerts", "Alerts"),
        ("/sources", "Sources & Users"),
        ("/about", "About"),
    ]
    nav_html = "".join(
        f'<a href="{href}" class="{"active" if active == href else ""}">{name}</a>'
        for href, name in nav_items
    )
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return f"""<!doctype html>
<html lang="pl">
<head>
<meta charset="utf-8">
<title>{html.escape(title)} &middot; Cisco Log NMS</title>
<style>{BASE_CSS}</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
    <div class="brand">CISCO LOG NMS<small>Log Analyzer Dashboard</small></div>
    <nav class="nav">{nav_html}</nav>
  </aside>
  <main class="main">
    <div class="topbar">
      <h1>{html.escape(title)}</h1>
      <div>
        <span class="meta">Ostatnie odświeżenie: {now}</span>
        &nbsp;
        <button class="btn" onclick="location.reload()">Odśwież</button>
      </div>
    </div>
    {body}
  </main>
</div>
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
        <div class="label">Przeanalizowane linie</div>
      </div>
      <div class="card">
        <div class="value">{stats['total_files']}</div>
        <div class="label">Pliki logów</div>
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

    # Dane dla wykresów Chart.js
    chart_data = {
        "types": {
            "labels": ["Login Failed", "Login Success", "ACL Denied"],
            "data": [
                stats["failed_total"],
                stats["success_total"],
                stats["acl_total"],
            ],
        },
        "top_failed": {
            "labels": [ip for ip, _ in stats["failed_by_ip"][:8]],
            "data":   [c  for _, c in stats["failed_by_ip"][:8]],
        },
    }

    body = alert_banner + kpis + f"""
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
              backgroundColor: ['#ff5c7a','#3ddc84','#ffb020'],
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
    </script>
    """
    return layout("Dashboard", "/", body)


def _kind_tag(kind: str) -> str:
    classes = {
        "login_failed":  "bad",
        "login_success": "ok",
        "acl_denied":    "warn",
    }
    label = {
        "login_failed":  "LOGIN FAILED",
        "login_success": "LOGIN SUCCESS",
        "acl_denied":    "ACL DENIED",
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
        rows = "<tr><td colspan='5' class='empty'>Brak zdarzeń pasujących do filtra</td></tr>"
    else:
        rows = "".join(
            f"<tr>"
            f"<td class='mono'>{html.escape(e.get('timestamp') or '-')}</td>"
            f"<td>{_kind_tag(e['kind'])}</td>"
            f"<td class='mono'>{html.escape(e.get('ip') or '-')}</td>"
            f"<td>{html.escape(e.get('user') or '-')}</td>"
            f"<td class='mono small'>"
            f"{html.escape((e.get('raw') or '')[:180])}</td>"
            f"</tr>"
            for e in events[:500]
        )

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
          <th>Timestamp</th><th>Typ</th><th>Source IP</th>
          <th>User</th><th>Raw</th>
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
        f"<td><a href='/events?kind=login_failed&ip={html.escape(ip)}'>"
        f"zobacz zdarzenia &rsaquo;</a></td></tr>"
        for ip, c in stats["brute_force_suspects"]
    ) or "<tr><td colspan='3' class='empty'>Brak podejrzeń brute-force</td></tr>"

    unknown_rows = "".join(
        f"<tr><td class='mono'>{html.escape(ip)}</td>"
        f"<td><a href='/events?ip={html.escape(ip)}'>zobacz zdarzenia &rsaquo;</a></td></tr>"
        for ip in stats["unknown_ips"]
    ) or "<tr><td colspan='2' class='empty'>Wszystkie IP są na whiteliscie</td></tr>"

    body = f"""
    <div class="card" style="margin-bottom:16px">
      <h2>Potencjalne ataki brute-force (&ge; {_STATE['bf_threshold']} nieudanych logowań)</h2>
      <table>
        <thead><tr><th>Source IP</th><th>Nieudane</th><th></th></tr></thead>
        <tbody>{bf_rows}</tbody>
      </table>
    </div>
    <div class="card">
      <h2>Adresy IP spoza whitelisty</h2>
      <table>
        <thead><tr><th>IP</th><th></th></tr></thead>
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
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    log_args = args.log or ["Sample_Logs/Cisco_ios.log"]
    _STATE["log_paths"] = [Path(p) for p in log_args]
    _STATE["allowed_path"] = Path(args.allowed)
    _STATE["allowed_networks"] = load_allowed_networks(_STATE["allowed_path"])
    _STATE["bf_threshold"] = args.bf_threshold

    missing = [p for p in _STATE["log_paths"] if not p.exists()]
    if missing:
        for p in missing:
            print(f"[!] Ostrzeżenie: plik logu nie istnieje: {p}")

    httpd = HTTPServer((args.host, args.port), Handler)
    url = f"http://{args.host}:{args.port}"
    print(f"[i] Cisco Log NMS dashboard uruchomiony: {url}")
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
