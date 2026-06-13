-- ============================================================
-- Cisco Log Analyzer – Setup bazy danych PostgreSQL
-- ============================================================
-- Użycie:
--   1. psql -U postgres -f setup_database.sql
--   2. Lub: uruchom python init_db.py (wygeneruje dane automatycznie)
-- ============================================================

-- Tworzenie bazy (uruchom jako superuser/postgres)
-- DROP DATABASE IF EXISTS cisco_logs;
-- CREATE DATABASE cisco_logs;

-- Po utworzeniu bazy, połącz się z nią:
-- \c cisco_logs

CREATE TABLE IF NOT EXISTS logs (
    id          SERIAL PRIMARY KEY,
    device      VARCHAR(50)  NOT NULL,
    log_line    TEXT         NOT NULL,
    created_at  TIMESTAMP    DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_logs_device ON logs(device);

-- Przykładowe dane (podzbiór – pełne 250 logów generuje init_db.py)
INSERT INTO logs (device, log_line) VALUES
('Cisc_R1', '*Jun 10 08:14:45.128: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 203.0.113.45] [localport: 22] [Reason: Login Authentication Failed] at 08:14:45 UTC Tue Jun 10 2026'),
('Cisc_R1', '*Jun 10 08:15:12.877: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: root] [Source: 203.0.113.45] [localport: 22] [Reason: Login Authentication Failed] at 08:15:12 UTC Tue Jun 10 2026'),
('Cisc_R2', '*Jun 10 08:12:03.412: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: admin] [Source: 192.168.1.10] [localport: 22] at 08:12:03 UTC Tue Jun 10 2026'),
('Cisc_ER1', '*Jun 10 08:16:03.201: %SEC-6-IPACCESSLOGP: list 101 denied tcp 45.77.12.9(51234) -> 10.0.0.1(22), 3 packets'),
('Cisc_ER2', '*Jun 10 08:25:33.100: %SEC-6-IPACCESSLOGP: list 102 denied tcp 91.234.55.17(44321) -> 10.0.0.1(23), 5 packets'),
('Cisc_IR1', '*Jun 10 08:40:55.678: %SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: guest] [Source: 185.220.101.42] [localport: 22] [Reason: Login Authentication Failed] at 08:40:55 UTC Tue Jun 10 2026'),
('Cisc_R1', '*Jun 10 08:45:22.450: %LINK-3-UPDOWN: Interface GigabitEthernet0/1, changed state to down'),
('Cisc_R2', '*Jun 10 08:50:10.774: %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: netadmin] [Source: 192.168.1.20] [localport: 22] at 08:50:10 UTC Tue Jun 10 2026'),
('Cisc_ER1', '*Jun 10 09:01:15.332: %SYS-5-CONFIG_I: Configured from console by admin on vty0 (192.168.1.10)'),
('Cisc_IR1', '*Jun 10 09:10:44.201: %LINEPROTO-5-UPDOWN: Line protocol on Interface GigabitEthernet0/0, changed state to up');
