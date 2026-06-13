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

# Wyłączenie lub awaria portu Cisco
RE_LINK_DOWN = re.compile(r"%LINK-3-UPDOWN:\s*Interface\s*(?P<port>\S+),\s*changed\s*state\s*to\s*down")
RE_LINEPROTO_DOWN = re.compile(r"%LINEPROTO-5-UPDOWN:\s*Line\s*protocol\s*on\s*Interface\s*(?P<port>\S+),\s*changed\s*state\s*to\s*down")
RE_PORT_SECURITY_VIOLATION = re.compile(r"%PM-4-ERR_DISABLE:\s*psecure-violation\s*error\s*detected\s*on\s*(?P<port>\S+)")

# Wykrywanie nazwy urządzenia w linii logu (np. "Cisc_R1: %SEC")
RE_DEVICE_IN_LINE = re.compile(r"\b(?P<device>[a-zA-Z][a-zA-Z0-9_\-]*)\s*:\s*%[A-Z]")

# ---------------------------------------------------------------------------
# Wyrażenia regularne dopasowujące typowe wpisy z systemowych syslogów (Linux)
# ---------------------------------------------------------------------------

# sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
RE_SYS_LOGIN_FAILED = re.compile(
    r"sshd\[\d+\]:\s*Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
)

# sshd[12345]: Accepted password for admin from 192.168.1.100 port 54321 ssh2
# sshd[12345]: Accepted publickey for admin from 192.168.1.100 port 54321 ssh2
RE_SYS_LOGIN_SUCCESS = re.compile(
    r"sshd\[\d+\]:\s*Accepted\s+(?:password|publickey)\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
)

# [UFW BLOCK] IN=eth0 OUT= MAC=... SRC=45.77.12.9 DST=10.0.0.1 ... PROTO=TCP SPT=51234 DPT=22
RE_SYS_UFW_BLOCK = re.compile(
    r"\[UFW BLOCK\].*?SRC=(?P<ip>\d+\.\d+\.\d+\.\d+).*?DST=(?P<dst>\d+\.\d+\.\d+\.\d+).*?PROTO=(?P<proto>\w+)(?:.*?SPT=(?P<sport>\d+))?.*?DPT=(?P<dport>\d+)"
)

# sudo: pam_unix(sudo:auth): authentication failure; logname= uid=1000 euid=0 ruser= rhost= user=admin
RE_SYS_SUDO_FAILURE = re.compile(
    r"sudo:\s+pam_unix\(sudo:auth\):\s+authentication failure;\s+.*?user=(?P<user>\S+)"
)

# Znacznik czasu typowy dla syslog (RFC 3164, np. Jun 13 12:34:56 lub ISO 8601, np. 2026-06-13T12:34:56.123+02:00)
RE_SYS_TIMESTAMP = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})"
)


# ---------------------------------------------------------------------------
# Struktury danych
# ---------------------------------------------------------------------------


@dataclass
class LogEvent:
    """Pojedyncze zdarzenie wyciągnięte z logu."""

    kind: str           # "login_failed" | "login_success" | "acl_denied" | "system_event" | "port_down"
    timestamp: str
    ip: str
    user: str | None = None
    destination: str | None = None
    dest_port: str | None = None
    raw: str = ""
    device_type: str = "cisco"  # "cisco" | "linux"
    device: str | None = None  # nazwa urządzenia (np. Cisc_R1)
    port: str | None = None    # nazwa portu (np. GigabitEthernet0/1)


@dataclass
class AnalysisResult:
    events: list[LogEvent] = field(default_factory=list)
    failed_by_ip: Counter = field(default_factory=Counter)
    success_by_ip: Counter = field(default_factory=Counter)
    acl_by_ip: Counter = field(default_factory=Counter)
    system_event_by_ip: Counter = field(default_factory=Counter)
    port_down_by_ip: Counter = field(default_factory=Counter)
    failed_by_device: Counter = field(default_factory=Counter)
    port_down_by_device: Counter = field(default_factory=Counter)
    port_down_by_port: Counter = field(default_factory=Counter)
    all_devices: set[str] = field(default_factory=set)
    unknown_ips: set[str] = field(default_factory=set)
    brute_force_suspects: list[tuple[str, int]] = field(default_factory=list)
    frequent_port_failures: list[tuple[str, int]] = field(default_factory=list)
    anomalous_devices: list[tuple[str, int, float]] = field(default_factory=list)
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


def parse_line(line: str, device: str | None = None) -> LogEvent | None:
    """Zwraca LogEvent, jeżeli linia zawiera interesujące nas zdarzenie."""
    # Wyciąganie timestampu
    ts_match = RE_TIMESTAMP.search(line)
    timestamp = ts_match.group("ts") if ts_match else ""
    device_type = "cisco"

    if not timestamp:
        sys_ts_match = RE_SYS_TIMESTAMP.search(line)
        if sys_ts_match:
            timestamp = sys_ts_match.group("ts")
            device_type = "linux"

    # Wykrywanie nazwy urządzenia w linii logu (jeśli nie przekazano w parametrze)
    if not device:
        dev_match = RE_DEVICE_IN_LINE.search(line)
        if dev_match:
            device = dev_match.group("device")

    # 1. Zdarzenia Cisco IOS (Awarie/Wyłączenia portów)
    port = None
    if m := RE_LINK_DOWN.search(line):
        port = m.group("port")
    elif m := RE_LINEPROTO_DOWN.search(line):
        port = m.group("port")
    elif m := RE_PORT_SECURITY_VIOLATION.search(line):
        port = m.group("port")

    if port:
        return LogEvent(
            kind="port_down",
            timestamp=timestamp,
            ip="127.0.0.1",
            raw=line.rstrip(),
            device_type="cisco",
            device=device,
            port=port,
        )

    # 2. Logowania i ACL Cisco IOS
    if m := RE_LOGIN_FAILED.search(line):
        return LogEvent(
            kind="login_failed",
            timestamp=timestamp,
            ip=m.group("ip"),
            user=m.group("user").strip(),
            raw=line.rstrip(),
            device_type="cisco",
            device=device,
        )

    if m := RE_LOGIN_SUCCESS.search(line):
        return LogEvent(
            kind="login_success",
            timestamp=timestamp,
            ip=m.group("ip"),
            user=m.group("user").strip(),
            raw=line.rstrip(),
            device_type="cisco",
            device=device,
        )

    if m := RE_ACL_DENIED.search(line):
        return LogEvent(
            kind="acl_denied",
            timestamp=timestamp,
            ip=m.group("ip"),
            destination=m.group("dst"),
            dest_port=m.group("dport"),
            raw=line.rstrip(),
            device_type="cisco",
            device=device,
        )

    # 3. Zdarzenia systemowe Linux (Syslog)
    if m := RE_SYS_LOGIN_FAILED.search(line):
        return LogEvent(
            kind="login_failed",
            timestamp=timestamp,
            ip=m.group("ip"),
            user=m.group("user").strip(),
            raw=line.rstrip(),
            device_type="linux",
            device=device,
        )

    if m := RE_SYS_LOGIN_SUCCESS.search(line):
        return LogEvent(
            kind="login_success",
            timestamp=timestamp,
            ip=m.group("ip"),
            user=m.group("user").strip(),
            raw=line.rstrip(),
            device_type="linux",
            device=device,
        )

    if m := RE_SYS_UFW_BLOCK.search(line):
        return LogEvent(
            kind="acl_denied",
            timestamp=timestamp,
            ip=m.group("ip"),
            destination=m.group("dst"),
            dest_port=m.group("dport"),
            raw=line.rstrip(),
            device_type="linux",
            device=device,
        )

    if m := RE_SYS_SUDO_FAILURE.search(line):
        rhost_match = re.search(r"rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)", line)
        ip = rhost_match.group("ip") if rhost_match else "127.0.0.1"
        return LogEvent(
            kind="login_failed",
            timestamp=timestamp,
            ip=ip,
            user=m.group("user").strip(),
            raw=line.rstrip(),
            device_type="linux",
            device=device,
        )

    # 4. Ogólne błędy i ostrzeżenia systemowe (Cisco i Linux)
    if any(kw in line.lower() for kw in ["error", "fail", "critical", "err_disable", "violation"]):
        # Spróbujmy wyciągnąć IP, jeśli istnieje w logu
        ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
        ip = ip_match.group(0) if ip_match else "127.0.0.1"
        return LogEvent(
            kind="system_event",
            timestamp=timestamp,
            ip=ip,
            raw=line.rstrip(),
            device_type=device_type,
        )

    return None


def detect_anomalies_kmeans(
    port_down_by_device: dict[str, int],
    all_devices: set[str]
) -> list[tuple[str, int, float]]:
    """Używa algorytmu K-Means dla 1D (K=2) w celu identyfikacji urządzeń
    o anomalnej, podwyższonej awaryjności portów w porównaniu z resztą floty.
    
    Zwraca listę krotek (nazwa_urządzenia, liczba_awarii, score_awaryjności).
    """
    full_profile = {}
    for dev in all_devices:
        full_profile[dev] = port_down_by_device.get(dev, 0)
        
    if not full_profile or max(full_profile.values()) == 0:
        return []

    devices = list(full_profile.keys())
    values = [float(full_profile[d]) for d in devices]

    c0 = min(values)
    c1 = max(values)
    
    if c0 == c1:
        return []

    for _ in range(15):
        g0 = []
        g1 = []
        for v in values:
            if abs(v - c0) < abs(v - c1):
                g0.append(v)
            else:
                g1.append(v)
        
        if not g0 or not g1:
            break
            
        new_c0 = sum(g0) / len(g0)
        new_c1 = sum(g1) / len(g1)
        
        if new_c0 == c0 and new_c1 == c1:
            break
            
        c0, c1 = new_c0, new_c1

    threshold = (c0 + c1) / 2
    
    anomalies = []
    for d in devices:
        val = full_profile[d]
        if val > threshold and val > 0:
            normal_avg = sum(g0) / len(g0) if c0 < c1 else sum(g1) / len(g1)
            score = float(val) / max(normal_avg, 1.0)
            anomalies.append((d, val, round(score, 2)))

    anomalies.sort(key=lambda x: x[1], reverse=True)
    return anomalies


def analyze_lines(
    lines: Iterable[str | tuple[str, str | None]],
    allowed: list[ipaddress.IPv4Network],
    brute_force_threshold: int = 3,
    port_failure_threshold: int = 3,
) -> AnalysisResult:
    """Analizuje listę linii logów i zwraca wynik.

    Może przyjąć linie z pliku, bazy danych lub dowolnego innego źródła.
    """
    result = AnalysisResult()

    for item in lines:
        if isinstance(item, tuple):
            line, device = item
        else:
            line, device = item, None

        result.total_lines += 1
        event = parse_line(line, device=device)
        if event is None:
            continue

        result.events.append(event)
        if event.device:
            result.all_devices.add(event.device)

        if event.kind == "login_failed":
            result.failed_by_ip[event.ip] += 1
            if event.device:
                result.failed_by_device[event.device] += 1
        elif event.kind == "login_success":
            result.success_by_ip[event.ip] += 1
        elif event.kind == "acl_denied":
            result.acl_by_ip[event.ip] += 1
        elif event.kind == "system_event":
            result.system_event_by_ip[event.ip] += 1
        elif event.kind == "port_down":
            result.port_down_by_ip[event.ip] += 1
            if event.device:
                result.port_down_by_device[event.device] += 1
            if event.port:
                result.port_down_by_port[event.port] += 1

        if event.ip != "127.0.0.1" and not ip_is_allowed(event.ip, allowed):
            result.unknown_ips.add(event.ip)

    # Podejrzenie brute-force
    result.brute_force_suspects = [
        (ip, count)
        for ip, count in result.failed_by_ip.most_common()
        if count >= brute_force_threshold
    ]

    # Zastępujemy stały próg detekcji dynamicznym ML za pomocą K-Means
    result.anomalous_devices = detect_anomalies_kmeans(
        result.port_down_by_device,
        result.all_devices
    )

    # Zachowujemy dla kompatybilności wstecznej frequent_port_failures
    result.frequent_port_failures = [
        (port, count)
        for port, count in result.port_down_by_port.most_common()
        if count >= port_failure_threshold
    ]

    return result


def analyze(
    log_path: Path,
    allowed: list[ipaddress.IPv4Network],
    brute_force_threshold: int = 3,
    port_failure_threshold: int = 3,
) -> AnalysisResult:
    """Analizuje jeden plik logu i zwraca wynik."""
    with log_path.open("r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    return analyze_lines(lines, allowed, brute_force_threshold, port_failure_threshold)


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
    print(
        f"  - nieudane logowania:          {sum(result.failed_by_ip.values())}")
    print(
        f"  - udane logowania:             {sum(result.success_by_ip.values())}")
    print(f"  - odrzucone przez ACL:         {sum(result.acl_by_ip.values())}")
    print(f"  - awarie/wyłączenia portów:    {sum(result.port_down_by_ip.values())}")
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
            if result.port_down_by_ip[ip]:
                info.append(f"port_down={result.port_down_by_ip[ip]}")
            print(f"    - {ip:<16} {' '.join(info)}")
        print()
    else:
        print("[OK] Wszystkie wykryte IP mieszczą się na liście dozwolonych.\n")

    if result.brute_force_suspects:
        print("[!] Potencjalne ataki brute-force (wiele nieudanych logowań):")
        for ip, count in result.brute_force_suspects:
            print(f"    - {ip:<16} nieudane logowania: {count}")
        print()

    # TOP urządzenia, na które celowano
    if result.failed_by_device:
        print("Urządzenia z największą liczbą nieudanych logowań:")
        for dev, count in result.failed_by_device.most_common(5):
            print(f"    - {dev:<16} {count}")
        print()

    # TOP urządzenia z awariami portów
    if result.port_down_by_device:
        print("Urządzenia z największą liczbą awarii portów:")
        for dev, count in result.port_down_by_device.most_common(5):
            print(f"    - {dev:<16} {count}")
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
        nargs="*",
        default=["Sample_Logs/Cisco_ios.log"],
        help="Ścieżka(i) do pliku(ów) z logami Cisco IOS (domyślnie: Sample_Logs/Cisco_ios.log)",
    )
    parser.add_argument(
        "--allowed",
        default="Allowed_IPS",
        help="Ścieżka do pliku z dozwolonymi IP/podsieciami (domyślnie: Allowed_IPS)",
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
        result = analyze(
            path, allowed, brute_force_threshold=args.bf_threshold)
        print_report(path, result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
