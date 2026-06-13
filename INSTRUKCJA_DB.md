# Instrukcja konfiguracji bazy danych PostgreSQL

## 1. Instalacja PostgreSQL

### Ubuntu / Debian
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### Fedora / RHEL
```bash
sudo dnf install postgresql-server postgresql-contrib
sudo postgresql-setup --initdb
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

### Arch Linux
```bash
sudo pacman -S postgresql
sudo -u postgres initdb -D /var/lib/postgres/data
sudo systemctl start postgresql
sudo systemctl enable postgresql
```

## 2. Konfiguracja użytkownika

```bash
# Ustawienie hasła dla użytkownika postgres
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'ZAQ!2wsx';"
```

> Jeśli chcesz użyć innego hasła, zmień je również w `init_db.py` i w web_app.py (flaga `--db-password`).

## 3. Upewnij się, że pg_hba.conf pozwala na logowanie hasłem

Edytuj plik `pg_hba.conf` (lokalizacja: `/etc/postgresql/*/main/pg_hba.conf` na Ubuntu):

```
# Zmień "peer" na "md5" dla połączeń lokalnych:
local   all   all   md5
host    all   all   127.0.0.1/32   md5
```

Następnie zrestartuj PostgreSQL:
```bash
sudo systemctl restart postgresql
```

## 4. Tworzenie bazy danych

### Opcja A: Automatycznie (zalecane)

```bash
pip install psycopg2-binary
python init_db.py
```

Skrypt automatycznie:
- Utworzy bazę `cisco_logs`
- Utworzy tabelę `logs`
- Wstawi 250 przykładowych logów z 5 urządzeń

Opcjonalne parametry:
```bash
python init_db.py --host 127.0.0.1 --port 5432 --user postgres --password postgres --count 500
```

### Opcja B: Ręcznie przez SQL

```bash
sudo -u postgres psql -c "CREATE DATABASE cisco_logs;"
sudo -u postgres psql -d cisco_logs -f setup_database.sql
```

## 5. Uruchomienie web_app.py z bazą danych

```bash
python web_app.py --db
```

Lub z pełną konfiguracją:
```bash
python web_app.py --db --db-host 127.0.0.1 --db-port 5432 --db-name cisco_logs --db-user postgres --db-password postgres
```

## 6. Schemat tabeli

| Kolumna    | Typ           | Opis                        |
|------------|---------------|-----------------------------|
| id         | SERIAL (PK)   | Auto-increment              |
| device     | VARCHAR(50)   | Nazwa urządzenia Cisco      |
| log_line   | TEXT          | Surowa linia logu           |
| created_at | TIMESTAMP     | Data wstawienia rekordu     |

## 7. Sprawdzenie danych

```bash
psql -U postgres -d cisco_logs -c "SELECT COUNT(*) FROM logs;"
psql -U postgres -d cisco_logs -c "SELECT device, COUNT(*) FROM logs GROUP BY device;"
psql -U postgres -d cisco_logs -c "SELECT * FROM logs LIMIT 5;"
```
