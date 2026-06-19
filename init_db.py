"""
Inicjalizacja bazy danych PostgreSQL z przykładowymi logami Cisco IOS.
----------------------------------------------------------------------
Skrypt tworzy bazę 'cisco_logs' (jeśli nie istnieje), tabelę 'logs'
i wstawia 250 realistycznych wpisów z 5 urządzeń sieciowych.

Wymagania:
    pip install psycopg2-binary

Użycie:
    python init_db.py
    python init_db.py --host 127.0.0.1 --port 5432 --user postgres --password postgres
"""
from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta

import psycopg2

# ---------------------------------------------------------------------------
# Dane referencyjne
# ---------------------------------------------------------------------------

DEVICES = [
    "Cisc_R1", "Cisc_R2", "Cisc_R3", "Cisc_R4", "Cisc_R5",
    "Cisc_SW1", "Cisc_SW2", "Cisc_SW3", "Cisc_SW4", "Cisc_SW5",
    "Cisc_ER1", "Cisc_ER2", "Cisc_IR1", "Cisc_WLC1", "Cisc_CORE1",
]

USERS = [
    "admin", "root", "cisco", "guest", "netadmin",
    "operator", "monitor", "jkowalski", "backup_svc",
    "anowak", "piotr.zielinski", "svc_snmp", "readonly",
]

# IP wewnętrzne (dozwolone)
INTERNAL_IPS = [
    "192.168.1.10", "192.168.1.20", "192.168.1.55",
    "10.0.0.5", "10.10.10.5", "172.16.0.100",
    "10.1.1.1", "10.2.2.2", "172.16.10.50", "192.168.10.1",
]

# IP zewnętrzne (potencjalnie złośliwe)
EXTERNAL_IPS = [
    "203.0.113.45", "198.51.100.23", "185.220.101.42",
    "45.77.12.9", "91.234.55.17", "77.83.12.200",
    "104.248.33.91", "23.129.64.15", "62.210.105.44",
    "159.89.174.22", "5.188.210.101", "141.98.10.30",
    "31.184.198.71", "89.248.172.16", "112.85.42.187",
]

DST_IPS = [
    "10.0.0.1", "10.0.0.2", "192.168.1.1", "172.16.0.1",
    "10.1.1.254", "192.168.100.1", "10.255.255.1",
]
DST_PORTS = ["22", "23", "80", "443", "8080",
             "3389", "8443", "53", "161", "25"]
ACL_NAMES = ["101", "102", "103", "OUTSIDE_IN",
             "MGMT_ACL", "DMZ_ACL", "BLOCK_LIST"]
PROTOCOLS = ["tcp", "udp", "icmp"]
INTERFACES = [
    "GigabitEthernet0/0", "GigabitEthernet0/1", "GigabitEthernet0/2",
    "GigabitEthernet0/3", "GigabitEthernet1/0", "GigabitEthernet1/1",
    "FastEthernet0/0", "FastEthernet0/1", "FastEthernet0/24",
    "Serial0/0/0", "Serial0/0/1", "Loopback0",
    "Vlan10", "Vlan20", "Vlan100", "Tunnel0", "Port-channel1",
]
MAC_PREFIXES = ["aa:bb:cc", "00:1a:2b", "de:ad:be", "ca:fe:00", "f0:0d:ba"]


def get_internal_ip() -> str:
    # 70% szans na stałe IP z listy, 30% szans na w pełni losowe IP wewnętrzne
    if random.random() < 0.7:
        return random.choice(INTERNAL_IPS)
    choice = random.choice(["192", "10", "172"])
    if choice == "192":
        return f"192.168.1.{random.randint(2, 254)}"
    elif choice == "172":
        return f"172.16.{random.randint(0, 31)}.{random.randint(2, 254)}"
    else:
        return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(2, 254)}"


def get_external_ip() -> str:
    # 70% szans na stałe IP z listy, 30% szans na w pełni losowe IP zewnętrzne
    if random.random() < 0.7:
        return random.choice(EXTERNAL_IPS)
    while True:
        o1 = random.randint(1, 223)
        if o1 in (10, 127):
            continue
        o2 = random.randint(0, 255)
        if o1 == 172 and (16 <= o2 <= 31):
            continue
        if o1 == 192 and o2 == 168:
            continue
        return f"{o1}.{o2}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def get_dst_ip() -> str:
    if random.random() < 0.7:
        return random.choice(DST_IPS)
    return get_internal_ip()


def generate_timestamp(dt: datetime) -> str:
    """Generuje timestamp w formacie Cisco IOS."""
    return dt.strftime("%b %d %H:%M:%S") + f".{random.randint(0, 999):03d}"


def gen_login_failed(dt: datetime) -> str:
    user = random.choice(USERS)
    ip = get_external_ip() if random.random() < 0.8 else get_internal_ip()
    ts = generate_timestamp(dt)
    port = random.choice(["22", "23"])
    return (
        f"*{ts}: %SEC_LOGIN-4-LOGIN_FAILED: Login failed "
        f"[user: {user}] [Source: {ip}] [localport: {port}] "
        f"[Reason: Login Authentication Failed] at "
        f"{dt.strftime('%H:%M:%S UTC %a %b %d %Y')}"
    )


def gen_login_success(dt: datetime) -> str:
    user = random.choice(USERS[:5])  # głównie znani admini
    ip = get_internal_ip()
    ts = generate_timestamp(dt)
    return (
        f"*{ts}: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success "
        f"[user: {user}] [Source: {ip}] [localport: 22] at "
        f"{dt.strftime('%H:%M:%S UTC %a %b %d %Y')}"
    )


def gen_acl_denied(dt: datetime) -> str:
    ip = get_external_ip()
    dst = get_dst_ip()
    dport = random.choice(DST_PORTS)
    proto = random.choice(PROTOCOLS)
    acl = random.choice(ACL_NAMES)
    sport = random.randint(1024, 65535)
    pkts = random.randint(1, 20)
    ts = generate_timestamp(dt)
    return (
        f"*{ts}: %SEC-6-IPACCESSLOGP: list {acl} denied {proto} "
        f"{ip}({sport}) -> {dst}({dport}), {pkts} packets"
    )


def gen_link_updown(dt: datetime) -> str:
    iface = random.choice(INTERFACES)
    state = random.choice(["up", "down"])
    ts = generate_timestamp(dt)
    return (
        f"*{ts}: %LINK-3-UPDOWN: Interface {iface}, "
        f"changed state to {state}"
    )


def gen_config_change(dt: datetime) -> str:
    user = random.choice(["admin", "netadmin", "operator"])
    ip = get_internal_ip()
    vty = random.randint(0, 4)
    ts = generate_timestamp(dt)
    return (
        f"*{ts}: %SYS-5-CONFIG_I: Configured from console "
        f"by {user} on vty{vty} ({ip})"
    )


def gen_lineproto(dt: datetime) -> str:
    iface = random.choice(INTERFACES)
    state = random.choice(["up", "down"])
    ts = generate_timestamp(dt)
    return (
        f"*{ts}: %LINEPROTO-5-UPDOWN: Line protocol on Interface "
        f"{iface}, changed state to {state}"
    )


def gen_ospf_neighbor(dt: datetime) -> str:
    neighbor = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    iface = random.choice(INTERFACES[:6])
    state = random.choice(["FULL", "DOWN", "INIT", "2WAY"])
    ts = generate_timestamp(dt)
    return (
        f"*{ts}: %OSPF-5-ADJCHG: Process 1, Nbr {neighbor} "
        f"on {iface} from LOADING to {state}, Loading Done"
    )


def gen_port_security(dt: datetime) -> str:
    iface = random.choice(INTERFACES[:8])
    mac = f"{random.choice(MAC_PREFIXES)}:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}"
    ts = generate_timestamp(dt)
    return (
        f"*{ts}: %PM-4-ERR_DISABLE: psecure-violation error detected "
        f"on {iface} - MAC {mac}"
    )


def gen_ssh_failed(dt: datetime) -> str:
    ip = get_external_ip()
    ts = generate_timestamp(dt)
    ver = random.choice(["1.99", "2.0"])
    return (
        f"*{ts}: %SSH-4-SSH2_UNEXPECTED_MSG: Unexpected message type has arrived "
        f"from {ip}, SSH version {ver} - connection CLOSED"
    )


def gen_dhcp_snooping(dt: datetime) -> str:
    mac = f"{random.choice(MAC_PREFIXES)}:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}:{random.randint(10, 99):02x}"
    iface = random.choice(INTERFACES[:8])
    vlan = random.choice([10, 20, 30, 100, 200])
    ts = generate_timestamp(dt)
    return (
        f"*{ts}: %DHCP_SNOOPING-5-DHCP_SNOOPING_UNTRUSTED_PORT: "
        f"DHCP drop on untrusted port {iface}, VLAN {vlan}, MAC {mac}"
    )


def gen_stp_change(dt: datetime) -> str:
    iface = random.choice(INTERFACES[:8])
    vlan = random.choice([1, 10, 20, 30, 100])
    state = random.choice(["forwarding", "blocking", "listening", "learning"])
    ts = generate_timestamp(dt)
    return (
        f"*{ts}: %SPANTREE-5-TOPOTCHANGE: Topology change on VLAN {vlan}, "
        f"interface {iface} changed to {state}"
    )


def gen_hsrp_change(dt: datetime) -> str:
    group = random.randint(0, 10)
    iface = random.choice(INTERFACES[:6])
    state_from = random.choice(["Init", "Standby", "Listen"])
    state_to = random.choice(["Active", "Standby", "Speak"])
    ts = generate_timestamp(dt)
    return (
        f"*{ts}: %HSRP-5-STATECHANGE: {iface} Grp {group} "
        f"state {state_from} -> {state_to}"
    )


def gen_duplex_mismatch(dt: datetime) -> str:
    iface = random.choice(INTERFACES[:8])
    ts = generate_timestamp(dt)
    return (
        f"*{ts}: %CDP-4-DUPLEX_MISMATCH: duplex mismatch discovered "
        f"on {iface} (not half duplex), with neighbor switch port"
    )


def gen_sys_login_failed(dt: datetime) -> str:
    user = random.choice(USERS)
    ip = get_external_ip() if random.random() < 0.8 else get_internal_ip()
    pid = random.randint(1000, 30000)
    port = random.randint(32768, 61000)
    is_invalid = random.choice(["", "invalid user "])
    ts = dt.strftime("%b %e %H:%M:%S")
    return f"{ts} localhost sshd[{pid}]: Failed password for {is_invalid}{user} from {ip} port {port} ssh2"


def gen_sys_login_success(dt: datetime) -> str:
    user = random.choice(USERS[:5])
    ip = get_internal_ip()
    pid = random.randint(1000, 30000)
    port = random.randint(32768, 61000)
    method = random.choice(["password", "publickey"])
    ts = dt.strftime("%b %e %H:%M:%S")
    return f"{ts} localhost sshd[{pid}]: Accepted {method} for {user} from {ip} port {port} ssh2"


def gen_sys_ufw_block(dt: datetime) -> str:
    ip = get_external_ip()
    dst = get_dst_ip()
    dport = random.choice(DST_PORTS)
    proto = random.choice(PROTOCOLS).upper()
    sport = random.randint(1024, 65535)
    ts = dt.strftime("%b %e %H:%M:%S")
    mac = "00:11:22:33:44:55:66:77:88:99:aa:bb:08:00"
    return f"{ts} localhost kernel: [12345.678901] [UFW BLOCK] IN=eth0 OUT= MAC={mac} SRC={ip} DST={dst} LEN=40 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO={proto} SPT={sport} DPT={dport} WINDOW=5840 RES=0x00 SYN URGP=0"


def gen_sys_sudo_failure(dt: datetime) -> str:
    user = random.choice(USERS)
    ts = dt.strftime("%b %e %H:%M:%S")
    ip = get_internal_ip() if random.random() < 0.8 else ""
    rhost = f" rhost={ip}" if ip else ""
    return f"{ts} localhost sudo: pam_unix(sudo:auth): authentication failure; logname=uid=1000 euid=0 ruser=root{rhost} user={user}"


def gen_sys_general_error(dt: datetime) -> str:
    ts = dt.strftime("%b %e %H:%M:%S")
    services = ["systemd", "cron", "nginx",
                "postgresql", "dockerd", "fail2ban"]
    service = random.choice(services)
    pid = random.randint(100, 5000)
    errors = [
        "Failed to start Service.",
        "Error parsing configuration file, syntax error at line 42.",
        "Critical error: connection timed out while reading request.",
        "FATAL: database system is shutting down.",
        "Warning: disk usage exceeds 90% on /dev/sda1.",
    ]
    err = random.choice(errors)
    return f"{ts} localhost {service}[{pid}]: {err}"


# Proporcje typów logów (realistyczne – więcej failów i ACL)
LOG_GENERATORS = [
    (gen_login_failed,     25),
    (gen_login_success,     8),
    (gen_acl_denied,       10),
    (gen_link_updown,       10),
    (gen_config_change,     3),
    (gen_lineproto,         2),
    (gen_ospf_neighbor,     2),
    (gen_port_security,     2),
    (gen_ssh_failed,        12),
    (gen_dhcp_snooping,     2),
    (gen_stp_change,        2),
    (gen_hsrp_change,       1),
    (gen_duplex_mismatch,   1),
    # Linux system logs
    (gen_sys_login_failed, 15),
    (gen_sys_login_success, 8),
    (gen_sys_ufw_block,    10),
    (gen_sys_sudo_failure,  3),
    (gen_sys_general_error, 4),
]


def build_weighted_generators():
    pool = []
    for fn, weight in LOG_GENERATORS:
        pool.extend([fn] * weight)
    return pool


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inicjalizacja bazy PostgreSQL z logami Cisco IOS"
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="postgres")
    parser.add_argument("--password", default="ZAQ!2wsx")
    parser.add_argument("--count", type=int, default=800,
                        help="Liczba logów do wygenerowania (domyślnie: 400)")
    args = parser.parse_args()

    dsn_master = (
        f"dbname=postgres user={args.user} password={args.password} "
        f"host={args.host} port={args.port}"
    )

    # ---- Tworzenie bazy cisco_logs ----
    print("[i] Łączenie z PostgreSQL...")
    conn = psycopg2.connect(dsn_master)
    conn.autocommit = True
    cur = conn.cursor()

    cur.execute(
        "SELECT 1 FROM pg_database WHERE datname = 'cisco_logs'"
    )
    if cur.fetchone():
        print("[i] Baza 'cisco_logs' już istnieje – usuwam i tworzę od nowa.")
        # Zamknij inne połączenia
        cur.execute("""
            SELECT pg_terminate_backend(pid)
            FROM pg_stat_activity
            WHERE datname = 'cisco_logs' AND pid <> pg_backend_pid()
        """)
        cur.execute("DROP DATABASE cisco_logs")

    cur.execute("CREATE DATABASE cisco_logs")
    print("[+] Baza 'cisco_logs' utworzona.")
    cur.close()
    conn.close()

    # ---- Tworzenie tabeli i wstawianie logów ----
    dsn_logs = (
        f"dbname=cisco_logs user={args.user} password={args.password} "
        f"host={args.host} port={args.port}"
    )
    conn = psycopg2.connect(dsn_logs)
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id          SERIAL PRIMARY KEY,
            device      VARCHAR(50)  NOT NULL,
            log_line    TEXT         NOT NULL,
            created_at  TIMESTAMP    DEFAULT NOW()
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_logs_device ON logs(device)")
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS allowed_ips (
            id          SERIAL PRIMARY KEY,
            ip_or_net   VARCHAR(100) NOT NULL UNIQUE,
            description VARCHAR(255),
            created_at  TIMESTAMP    DEFAULT NOW()
        )
    """)
    conn.commit()
    print("[+] Tabele 'logs' oraz 'allowed_ips' zostały utworzone.")

    # Seeding allowed_ips z pliku lub wartości domyślnych
    from pathlib import Path
    allowed_ips_to_seed = []
    allowed_file = Path("Allowed_IPS")
    if allowed_file.exists():
        try:
            for line in allowed_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                allowed_ips_to_seed.append((line, "Zaimportowane z pliku Allowed_IPS"))
        except Exception as e:
            print(f"[!] Błąd odczytu pliku Allowed_IPS podczas seedowania: {e}")
            
    if not allowed_ips_to_seed:
        allowed_ips_to_seed = [
            ("192.168.1.0/24", "Sieć wewnętrzna biura"),
            ("10.0.0.0/8", "Infrastruktura główna"),
            ("172.16.0.0/12", "Sieć VPN dla administratorów"),
            ("10.228.1.15", "Serwer monitoringu NMS (Host)"),
        ]

    for ip_or_net, desc in allowed_ips_to_seed:
        try:
            cur.execute(
                "INSERT INTO allowed_ips (ip_or_net, description) VALUES (%s, %s) "
                "ON CONFLICT (ip_or_net) DO NOTHING",
                (ip_or_net, desc)
            )
        except Exception as e:
            print(f"[!] Błąd wstawiania do allowed_ips: {e}")
    conn.commit()
    print(f"[+] Whitelista zainicjowana w bazie ({len(allowed_ips_to_seed)} wpisów).")


    # ---- Generowanie logów ----
    pool = build_weighted_generators()
    now = datetime.now()
    count = args.count
    inserted = 0

    for i in range(count):
        dt = now - timedelta(
            minutes=random.randint(1, 10080)  # ostatnie 7 dni
        )
        gen_fn = random.choice(pool)
        device = random.choice(DEVICES)
        log_line = gen_fn(dt)

        cur.execute(
            "INSERT INTO logs (device, log_line, created_at) "
            "VALUES (%s, %s, %s)",
            (device, log_line, dt),
        )
        inserted += 1

    conn.commit()
    cur.close()
    conn.close()

    print(f"[+] Wstawiono {inserted} logów z {len(DEVICES)} urządzeń.")
    print("[i] Gotowe. Uruchom web_app.py --db aby użyć bazy danych.")


if __name__ == "__main__":
    main()
