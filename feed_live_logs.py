"""
Feed Live Logs – dynamiczne dodawanie losowych wpisów do bazy PostgreSQL.
------------------------------------------------------------------------
Skrypt ciągle (lub jednorazowo) generuje realistyczne logi Cisco IOS
i Linux, wstawiając je do tabeli 'logs' w bazie 'cisco_logs'.

Przeznaczenie:
    - Testowanie dashboardu NMS w czasie rzeczywistym
    - Symulacja napływu zdarzeń sieciowych
    - Generowanie alertów (brute-force, nieznane IP, awarie portów)

Tryby pracy:
    1. Ciągły (domyślny): co N sekund wstawia porcję logów
    2. Jednorazowy (--once): wstawia jedną porcję i kończy
    3. Burst (--burst): symuluje atak brute-force (seria failów z jednego IP)

Wymagania:
    pip install psycopg2-binary

Użycie:
    python feed_live_logs.py                          # ciągły: 5 logów co 3s
    python feed_live_logs.py --batch 20 --interval 1  # 20 logów co 1s
    python feed_live_logs.py --once --batch 50         # jednorazowo 50 logów
    python feed_live_logs.py --burst                   # symulacja brute-force
    python feed_live_logs.py --burst --burst-count 30  # 30 prób brute-force
"""
from __future__ import annotations

import argparse
import random
import signal
import sys
import time
from datetime import datetime, timedelta

import psycopg2

# ---------------------------------------------------------------------------
# Importujemy generatory z init_db.py (reuse)
# ---------------------------------------------------------------------------
from init_db import (
    DEVICES,
    USERS,
    EXTERNAL_IPS,
    INTERFACES,
    build_weighted_generators,
    gen_login_failed,
    gen_login_success,
    gen_acl_denied,
    gen_link_updown,
    gen_config_change,
    gen_lineproto,
    gen_ospf_neighbor,
    gen_port_security,
    gen_ssh_failed,
    gen_dhcp_snooping,
    gen_stp_change,
    gen_hsrp_change,
    gen_duplex_mismatch,
    gen_sys_login_failed,
    gen_sys_login_success,
    gen_sys_ufw_block,
    gen_sys_sudo_failure,
    gen_sys_general_error,
    get_external_ip,
    get_internal_ip,
    generate_timestamp,
)

# ---------------------------------------------------------------------------
# Kolory w terminalu
# ---------------------------------------------------------------------------
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    DIM    = "\033[2m"

# ---------------------------------------------------------------------------
# Specjalne generatory do scenariuszy testowych
# ---------------------------------------------------------------------------

def gen_brute_force_burst(attacker_ip: str, target_user: str,
                          device: str, count: int) -> list[tuple[str, str, datetime]]:
    """Generuje serię szybkich prób logowania z jednego IP (brute-force)."""
    entries = []
    now = datetime.now()
    for i in range(count):
        dt = now - timedelta(seconds=random.randint(0, 60))
        ts = generate_timestamp(dt)
        port = random.choice(["22", "23"])
        log_line = (
            f"*{ts}: %SEC_LOGIN-4-LOGIN_FAILED: Login failed "
            f"[user: {target_user}] [Source: {attacker_ip}] [localport: {port}] "
            f"[Reason: Login Authentication Failed] at "
            f"{dt.strftime('%H:%M:%S UTC %a %b %d %Y')}"
        )
        entries.append((device, log_line, dt))
    return entries


def gen_port_flapping_burst(device: str, interface: str,
                            count: int) -> list[tuple[str, str, datetime]]:
    """Generuje serię szybkich zmian stanu portu (flapping)."""
    entries = []
    now = datetime.now()
    for i in range(count):
        dt = now - timedelta(seconds=i * 5)
        ts = generate_timestamp(dt)
        state = "down" if i % 2 == 0 else "up"
        log_line = (
            f"*{ts}: %LINK-3-UPDOWN: Interface {interface}, "
            f"changed state to {state}"
        )
        entries.append((device, log_line, dt))
    return entries


def gen_acl_scan_burst(attacker_ip: str, count: int) -> list[tuple[str, str, datetime]]:
    """Generuje serię prób skanowania portów (ACL denied z różnych portów)."""
    entries = []
    now = datetime.now()
    scan_ports = list(range(20, 1024))
    random.shuffle(scan_ports)
    for i in range(min(count, len(scan_ports))):
        dt = now - timedelta(seconds=random.randint(0, 120))
        ts = generate_timestamp(dt)
        dport = scan_ports[i]
        sport = random.randint(40000, 65535)
        dst = random.choice(["10.0.0.1", "192.168.1.1", "172.16.0.1"])
        device = random.choice(["Cisc_ER1", "Cisc_ER2", "Cisc_CORE1"])
        log_line = (
            f"*{ts}: %SEC-6-IPACCESSLOGP: list OUTSIDE_IN denied tcp "
            f"{attacker_ip}({sport}) -> {dst}({dport}), 1 packets"
        )
        entries.append((device, log_line, dt))
    return entries


# ---------------------------------------------------------------------------
# Funkcje pomocnicze
# ---------------------------------------------------------------------------

def connect_db(args) -> psycopg2.extensions.connection:
    """Łączy się z bazą danych cisco_logs."""
    dsn = (
        f"dbname=cisco_logs user={args.user} password={args.password} "
        f"host={args.host} port={args.port}"
    )
    return psycopg2.connect(dsn)


def insert_entries(conn, entries: list[tuple[str, str, datetime]]) -> int:
    """Wstawia wpisy do tabeli logs. Zwraca liczbę wstawionych."""
    cur = conn.cursor()
    for device, log_line, dt in entries:
        cur.execute(
            "INSERT INTO logs (device, log_line, created_at) "
            "VALUES (%s, %s, %s)",
            (device, log_line, dt),
        )
    conn.commit()
    cur.close()
    return len(entries)


def generate_random_batch(pool, batch_size: int) -> list[tuple[str, str, datetime]]:
    """Generuje losową porcję logów."""
    entries = []
    now = datetime.now()
    for _ in range(batch_size):
        # Losowy czas: ostatnie 5 minut (symulacja "na żywo")
        dt = now - timedelta(seconds=random.randint(0, 300))
        gen_fn = random.choice(pool)
        device = random.choice(DEVICES)
        log_line = gen_fn(dt)
        entries.append((device, log_line, dt))
    return entries


def print_entry_preview(device: str, log_line: str):
    """Wyświetla skrócony podgląd wpisu."""
    # Kolorowanie na podstawie typu
    if "LOGIN_FAILED" in log_line or "Failed password" in log_line:
        color = C.RED
        kind = "FAIL"
    elif "LOGIN_SUCCESS" in log_line or "Accepted" in log_line:
        color = C.GREEN
        kind = " OK "
    elif "IPACCESSLOGP" in log_line or "UFW BLOCK" in log_line:
        color = C.YELLOW
        kind = " ACL"
    elif "UPDOWN" in log_line:
        color = C.BLUE
        kind = "PORT"
    else:
        color = C.DIM
        kind = " SYS"

    # Skróć log do max 90 znaków
    short = log_line[:90] + ("…" if len(log_line) > 90 else "")
    print(f"  {color}[{kind}]{C.RESET} {C.CYAN}{device:<12}{C.RESET} {short}")


# ---------------------------------------------------------------------------
# Główne tryby pracy
# ---------------------------------------------------------------------------

def run_continuous(args):
    """Tryb ciągły – wstawia logi w pętli co N sekund."""
    pool = build_weighted_generators()
    conn = connect_db(args)
    total = 0

    print(f"{C.GREEN}{C.BOLD}[▶] Tryb ciągły uruchomiony{C.RESET}")
    print(f"    Porcja: {args.batch} logów co {args.interval}s")
    print(f"    Baza:   cisco_logs@{args.host}:{args.port}")
    print(f"    {C.DIM}Ctrl+C aby zatrzymać{C.RESET}\n")

    try:
        while True:
            entries = generate_random_batch(pool, args.batch)
            count = insert_entries(conn, entries)
            total += count
            now = datetime.now().strftime("%H:%M:%S")
            print(f"{C.BOLD}[{now}]{C.RESET} Wstawiono "
                  f"{C.GREEN}+{count}{C.RESET} logów "
                  f"(łącznie: {C.CYAN}{total}{C.RESET})")

            # Pokaż podgląd kilku wpisów
            preview_count = min(3, len(entries))
            for device, log_line, _ in entries[:preview_count]:
                print_entry_preview(device, log_line)

            if len(entries) > preview_count:
                print(f"  {C.DIM}... i {len(entries) - preview_count} więcej{C.RESET}")
            print()

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[■] Zatrzymano.{C.RESET} "
              f"Łącznie wstawiono: {C.CYAN}{total}{C.RESET} logów.")
    finally:
        conn.close()


def run_once(args):
    """Tryb jednorazowy – wstawia jedną porcję logów."""
    pool = build_weighted_generators()
    conn = connect_db(args)

    entries = generate_random_batch(pool, args.batch)
    count = insert_entries(conn, entries)
    conn.close()

    print(f"{C.GREEN}{C.BOLD}[✓] Wstawiono {count} losowych logów{C.RESET}")
    print(f"    Baza: cisco_logs@{args.host}:{args.port}\n")

    for device, log_line, _ in entries[:10]:
        print_entry_preview(device, log_line)

    if len(entries) > 10:
        print(f"  {C.DIM}... i {len(entries) - 10} więcej{C.RESET}")


def run_burst(args):
    """Tryb burst – symulacja ataku brute-force i/lub skanowania portów."""
    conn = connect_db(args)
    total = 0

    attacker_ip = args.burst_ip or get_external_ip()
    target_user = random.choice(USERS)
    device = random.choice(DEVICES[:5])

    print(f"{C.RED}{C.BOLD}[⚡] Tryb BURST – symulacja ataku{C.RESET}")
    print(f"    Atakujący IP: {C.RED}{attacker_ip}{C.RESET}")
    print(f"    Cel:          {C.YELLOW}{target_user}@{device}{C.RESET}")
    print()

    # --- Brute-force burst ---
    bf_count = args.burst_count
    print(f"  {C.RED}▸ Brute-force:{C.RESET} {bf_count} prób logowania...")
    entries = gen_brute_force_burst(attacker_ip, target_user, device, bf_count)
    count = insert_entries(conn, entries)
    total += count
    for d, ll, _ in entries[:5]:
        print_entry_preview(d, ll)
    if bf_count > 5:
        print(f"  {C.DIM}... i {bf_count - 5} więcej{C.RESET}")
    print()

    # --- Port scanning burst ---
    scan_count = args.burst_count // 2
    if scan_count > 0:
        print(f"  {C.YELLOW}▸ Skanowanie portów:{C.RESET} {scan_count} prób...")
        entries = gen_acl_scan_burst(attacker_ip, scan_count)
        count = insert_entries(conn, entries)
        total += count
        for d, ll, _ in entries[:5]:
            print_entry_preview(d, ll)
        if scan_count > 5:
            print(f"  {C.DIM}... i {scan_count - 5} więcej{C.RESET}")
        print()

    # --- Port flapping (opcjonalne) ---
    if random.random() < 0.5:
        iface = random.choice(INTERFACES[:6])
        flap_device = random.choice(DEVICES[:5])
        flap_count = random.randint(6, 12)
        print(f"  {C.BLUE}▸ Port flapping:{C.RESET} {iface} na {flap_device} "
              f"({flap_count}x)...")
        entries = gen_port_flapping_burst(flap_device, iface, flap_count)
        count = insert_entries(conn, entries)
        total += count
        for d, ll, _ in entries[:4]:
            print_entry_preview(d, ll)
        print()

    conn.close()
    print(f"{C.GREEN}{C.BOLD}[✓] Burst zakończony.{C.RESET} "
          f"Wstawiono łącznie: {C.CYAN}{total}{C.RESET} logów.")


def run_scenario(args):
    """Tryb scenariuszowy – symuluje pełny scenariusz ataku krok po kroku."""
    conn = connect_db(args)
    total = 0
    pool = build_weighted_generators()

    attacker_ip = get_external_ip()
    target_user = random.choice(["admin", "root", "cisco"])
    device = random.choice(DEVICES[:5])

    print(f"{C.RED}{C.BOLD}[🎬] Scenariusz: Symulacja ataku sieciowego{C.RESET}")
    print(f"    Atakujący: {C.RED}{attacker_ip}{C.RESET}")
    print(f"    Cel:       {C.YELLOW}{target_user}@{device}{C.RESET}")
    print(f"    {C.DIM}Każdy etap co 2 sekundy...{C.RESET}\n")

    stages = [
        ("🔍 Rekonesans – skanowanie portów",
         lambda: gen_acl_scan_burst(attacker_ip, 15)),
        ("🔑 Atak brute-force – próby logowania",
         lambda: gen_brute_force_burst(attacker_ip, target_user, device, 20)),
        ("🔓 Sukces logowania (atakujący)",
         lambda: [(device,
                   f"*{generate_timestamp(datetime.now())}: %SEC_LOGIN-5-LOGIN_SUCCESS: "
                   f"Login Success [user: {target_user}] [Source: {attacker_ip}] "
                   f"[localport: 22] at {datetime.now().strftime('%H:%M:%S UTC %a %b %d %Y')}",
                   datetime.now())]),
        ("⚙️ Zmiana konfiguracji",
         lambda: [(device,
                   f"*{generate_timestamp(datetime.now())}: %SYS-5-CONFIG_I: "
                   f"Configured from console by {target_user} on vty0 ({attacker_ip})",
                   datetime.now())]),
        ("🔌 Awaria interfejsów (sabotaż)",
         lambda: gen_port_flapping_burst(device, "GigabitEthernet0/0", 8)),
        ("📡 Szum tła – normalne logi",
         lambda: generate_random_batch(pool, 10)),
    ]

    try:
        for stage_name, gen_fn in stages:
            print(f"  {C.BOLD}{stage_name}{C.RESET}")
            entries = gen_fn()
            count = insert_entries(conn, entries)
            total += count
            for d, ll, _ in entries[:3]:
                print_entry_preview(d, ll)
            if len(entries) > 3:
                print(f"  {C.DIM}... +{len(entries) - 3} wpisów{C.RESET}")
            print()
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n{C.YELLOW}[■] Scenariusz przerwany.{C.RESET}")
    finally:
        conn.close()

    print(f"{C.GREEN}{C.BOLD}[✓] Scenariusz zakończony.{C.RESET} "
          f"Wstawiono łącznie: {C.CYAN}{total}{C.RESET} logów.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Feed Live Logs – dynamiczne testowanie bazy Cisco Log NMS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Przykłady:
  python feed_live_logs.py                          # ciągły: 5 logów co 3s
  python feed_live_logs.py --batch 20 --interval 1  # 20 logów co 1s
  python feed_live_logs.py --once --batch 50         # jednorazowo 50 logów
  python feed_live_logs.py --burst                   # symulacja brute-force
  python feed_live_logs.py --burst --burst-count 30  # 30 prób brute-force
  python feed_live_logs.py --scenario                # pełny scenariusz ataku
""",
    )

    # Połączenie z bazą
    db_group = parser.add_argument_group("Połączenie z bazą danych")
    db_group.add_argument("--host", default="127.0.0.1",
                          help="Host PostgreSQL (domyślnie: 127.0.0.1)")
    db_group.add_argument("--port", type=int, default=5432,
                          help="Port PostgreSQL (domyślnie: 5432)")
    db_group.add_argument("--user", default="postgres",
                          help="Użytkownik PostgreSQL (domyślnie: postgres)")
    db_group.add_argument("--password", default="ZAQ!2wsx",
                          help="Hasło PostgreSQL")

    # Tryby pracy
    mode_group = parser.add_argument_group("Tryb pracy")
    mode_exc = mode_group.add_mutually_exclusive_group()
    mode_exc.add_argument("--once", action="store_true",
                          help="Jednorazowe wstawienie porcji logów")
    mode_exc.add_argument("--burst", action="store_true",
                          help="Symulacja ataku brute-force + skanowania")
    mode_exc.add_argument("--scenario", action="store_true",
                          help="Pełny scenariusz ataku krok po kroku")

    # Parametry
    param_group = parser.add_argument_group("Parametry")
    param_group.add_argument("--batch", type=int, default=5,
                             help="Liczba logów w porcji (domyślnie: 5)")
    param_group.add_argument("--interval", type=float, default=3.0,
                             help="Interwał w sekundach (domyślnie: 3.0)")
    param_group.add_argument("--burst-count", type=int, default=15,
                             help="Liczba prób w trybie burst (domyślnie: 15)")
    param_group.add_argument("--burst-ip", type=str, default=None,
                             help="IP atakującego w trybie burst (losowy jeśli pominięty)")

    args = parser.parse_args()

    # Ładny banner
    print()
    print(f"  {C.BOLD}{C.CYAN}╔═══════════════════════════════════════════╗{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}║   Feed Live Logs – Cisco NMS Test Tool    ║{C.RESET}")
    print(f"  {C.BOLD}{C.CYAN}╚═══════════════════════════════════════════╝{C.RESET}")
    print()

    # Graceful shutdown
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))

    if args.burst:
        run_burst(args)
    elif args.scenario:
        run_scenario(args)
    elif args.once:
        run_once(args)
    else:
        run_continuous(args)


if __name__ == "__main__":
    main()
