"""
Cisco IOS Log Analyzer
----------------------
Prosty analizator logów z urządzeń Cisco IOS.

Funkcje:
  - wczytuje plik z logami (lub listę plików),
  - wczytuje listę dozwolonych adresów IP / podsieci (allowed_ips.txt),
  - wykrywa nieudane próby logowania (%SEC_LOGIN-4-LOGIN_FAILED),
  - wykrywa udane logowania (%SEC_LOGIN-5-LOGIN_SUCCESS),
  - wykrywa pakiety zablokowane przez ACL (%SEC-6-IPACCESSLOGP),
  - oznacza adresy IP, które nie znajdują się na liście dozwolonych,
  - wskazuje potencjalne ataki brute-force (wiele nieudanych logowań
    z tego samego źródła w krótkim czasie),
  - generuje zwięzły raport na konsolę.

Użycie:
    python cisco_log_analyzer.py sample_logs/cisco_ios.log
    python cisco_log_analyzer.py sample_logs/cisco_ios.log --allowed allowed_ips.txt
"""

from __future__ import annotations

import argparse
import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable


# ---------------------------------------------------------------------------
# Wyrażenia regularne dopasowujące typowe wpisy z Cisco IOS
# ---------------------------------------------------------------------------

# %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 203.0.113.45] ...
RE_LOGIN_FAILED = re.compile(
    r"%SEC_LOGIN-4-LOGIN_FAILED:.*?\[user:\s*(?P<user>[^\]]+)\].*?"
    r"\[Source:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\]"
)

# %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 192.168.1.10] ...
RE_LOGIN_SUCCESS = re.compile(
    r"%SEC_LOGIN-5-LOGIN_SUCCESS:.*?\[user:\s*(?P<user>[^\]]+)\].*?"
    r"\[Source:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\]"
)

# %SEC-6-IPACCESSLOGP: list 101 denied tcp 45.77.12.9(51234) -> 10.0.0.1(22), 3 packets
RE_ACL_DENIED = re.compile(
    r"%SEC-6-IPACCESSLOGP:.*?denied\s+\w+\s+"
    r"(?P<ip>\d+\.\d+\.\d+\.\d+)\(\d+\)\s*->\s*"
    r"(?P<dst>\d+\.\d+\.\d+\.\d+)\((?P<dport>\d+)\)"
)

# Znacznik czasu typowy dla Cisco IOS: "*Apr  1 08:14:45.128:"
RE_TIMESTAMP = re.compile(r"^\*?(?P<ts>\w+\s+\d+\s+\d+:\d+:\d+(?:\.\d+)?)")


# ---------------------------------------------------------------------------
# Struktury danych
# ---------------------------------------------------------------------------


@dataclass
class LogEvent:
    """Pojedyncze zdarzenie wyciągnięte z logu."""

    kind: str           # "login_failed" | "login_success" | "acl_denied"
    timestamp: str
    ip: str
    user: str | None = None
    destination: str | None = None
    dest_port: str | None = None
    raw: str = ""


@dataclass
class AnalysisResult:
    events: list[LogEvent] = field(default_factory=list)
    failed_by_ip: Counter = field(default_factory=Counter)
    success_by_ip: Counter = field(default_factory=Counter)
    acl_by_ip: Counter = field(default_factory=Counter)
    unknown_ips: set[str] = field(default_factory=set)
    brute_force_suspects: list[tuple[str, int]] = field(default_factory=list)
    total_lines: int = 0


# ---------------------------------------------------------------------------
# Logika
# ---------------------------------------------------------------------------


def load_allowed_networks(path: Path) -> list[ipaddress.IPv4Network]:
    """Wczytuje plik z dozwolonymi IP/podsieciami.

    Linie puste oraz zaczynające się od '#' są pomijane.
    Pojedyncze IP są automatycznie traktowane jako /32.
    """
    if not path.exists():
        return []

    networks: list[ipaddress.IPv4Network] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            networks.append(ipaddress.ip_network(line, strict=False))
        except ValueError as err:
            print(f"[!] Pomijam błędny wpis w {path.name}: {line!r} ({err})")
    return networks


def ip_is_allowed(ip: str, networks: Iterable[ipaddress.IPv4Network]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


def parse_line(line: str) -> LogEvent | None:
    """Zwraca LogEvent, jeżeli linia zawiera interesujące nas zdarzenie."""
    ts_match = RE_TIMESTAMP.search(line)
    timestamp = ts_match.group("ts") if ts_match else ""

    if m := RE_LOGIN_FAILED.search(line):
        return LogEvent(
            kind="login_failed",
            timestamp=timestamp,
            ip=m.group("ip"),
            user=m.group("user").strip(),
            raw=line.rstrip(),
        )

    if m := RE_LOGIN_SUCCESS.search(line):
        return LogEvent(
            kind="login_success",
            timestamp=timestamp,
            ip=m.group("ip"),
            user=m.group("user").strip(),
            raw=line.rstrip(),
        )

    if m := RE_ACL_DENIED.search(line):
        return LogEvent(
            kind="acl_denied",
            timestamp=timestamp,
            ip=m.group("ip"),
            destination=m.group("dst"),
            dest_port=m.group("dport"),
            raw=line.rstrip(),
        )

    return None


def analyze(
    log_path: Path,
    allowed: list[ipaddress.IPv4Network],
    brute_force_threshold: int = 3,
) -> AnalysisResult:
    """Analizuje jeden plik logu i zwraca wynik."""
    result = AnalysisResult()

    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            result.total_lines += 1
            event = parse_line(line)
            if event is None:
                continue

            result.events.append(event)

            if event.kind == "login_failed":
                result.failed_by_ip[event.ip] += 1
            elif event.kind == "login_success":
                result.success_by_ip[event.ip] += 1
            elif event.kind == "acl_denied":
                result.acl_by_ip[event.ip] += 1

            if not ip_is_allowed(event.ip, allowed):
                result.unknown_ips.add(event.ip)

    # Podejrzenie brute-force: >= N nieudanych logowań z tego samego IP
    result.brute_force_suspects = [
        (ip, count)
        for ip, count in result.failed_by_ip.most_common()
        if count >= brute_force_threshold
    ]

    return result


# ---------------------------------------------------------------------------
# Raport
# ---------------------------------------------------------------------------


def print_report(log_path: Path, result: AnalysisResult) -> None:
    bar = "=" * 70
    print(bar)
    print(f" RAPORT: {log_path}")
    print(bar)
    print(f"Przeanalizowano linii:           {result.total_lines}")
    print(f"Wykryte zdarzenia (łącznie):     {len(result.events)}")
    print(f"  - nieudane logowania:          {sum(result.failed_by_ip.values())}")
    print(f"  - udane logowania:             {sum(result.success_by_ip.values())}")
    print(f"  - odrzucone przez ACL:         {sum(result.acl_by_ip.values())}")
    print()

    if result.unknown_ips:
        print("[!] Adresy IP SPOZA listy dozwolonych:")
        for ip in sorted(result.unknown_ips, key=lambda s: ipaddress.ip_address(s)):
            info = []
            if result.failed_by_ip[ip]:
                info.append(f"failed={result.failed_by_ip[ip]}")
            if result.success_by_ip[ip]:
                info.append(f"success={result.success_by_ip[ip]}")
            if result.acl_by_ip[ip]:
                info.append(f"acl_denied={result.acl_by_ip[ip]}")
            print(f"    - {ip:<16} {' '.join(info)}")
        print()
    else:
        print("[OK] Wszystkie wykryte IP mieszczą się na liście dozwolonych.\n")

    if result.brute_force_suspects:
        print("[!] Potencjalne ataki brute-force (wiele nieudanych logowań):")
        for ip, count in result.brute_force_suspects:
            print(f"    - {ip:<16} nieudane logowania: {count}")
        print()

    # TOP użytkownicy, na których celowano
    targeted_users = Counter(
        e.user for e in result.events if e.kind == "login_failed" and e.user
    )
    if targeted_users:
        print("Użytkownicy z największą liczbą nieudanych logowań:")
        for user, count in targeted_users.most_common(5):
            print(f"    - {user:<16} {count}")
        print()

    print(bar)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analizator logów Cisco IOS",
    )
    parser.add_argument(
        "logs",
        nargs="+",
        help="Ścieżka(i) do pliku(ów) z logami Cisco IOS",
    )
    parser.add_argument(
        "--allowed",
        default="allowed_ips.txt",
        help="Ścieżka do pliku z dozwolonymi IP/podsieciami (domyślnie: allowed_ips.txt)",
    )
    parser.add_argument(
        "--bf-threshold",
        type=int,
        default=3,
        help="Liczba nieudanych logowań z jednego IP, od której uznajemy brute-force (domyślnie: 3)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    allowed_path = Path(args.allowed)
    allowed = load_allowed_networks(allowed_path)
    if not allowed:
        print(
            f"[i] Brak wpisów w {allowed_path} – każde IP zostanie "
            "oznaczone jako spoza listy dozwolonych."
        )

    for log_file in args.logs:
        path = Path(log_file)
        if not path.exists():
            print(f"[!] Plik nie istnieje: {path}")
            continue
        result = analyze(path, allowed, brute_force_threshold=args.bf_threshold)
        print_report(path, result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
