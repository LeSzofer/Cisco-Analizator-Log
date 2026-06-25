# Niezwykle Szczegółowa Analiza Kodu: `Cisco_Log_Analyzer.py`

Niniejszy dokument przedstawia wnikliwe, niemalże linia-po-linii, objaśnienie skryptu `Cisco_Log_Analyzer.py`. Każda sekcja, funkcja oraz kluczowy element języka Python zostały tutaj szczegółowo opisane i przeanalizowane.

---

## Spis Treści
1. [Metadane i Nagłówek (Linie 1–20)](#1-metadane-i-nagłówek-linie-120)
2. [Importy i Konfiguracja Środowiska (Linie 22–30)](#2-importy-i-konfiguracja-środowiska-linie-2230)
3. [Wyrażenia Regularne (Regex) (Linie 34–96)](#3-wyrażenia-regularne-regex-linie-3496)
4. [Klasy Danych (Dataclasses) (Linie 98–136)](#4-klasy-danych-dataclasses-linie-98136)
5. [Wczytywanie i Walidacja Adresów IP (Linie 143–170)](#5-wczytywanie-i-walidacja-adresów-ip-linie-143170)
6. [Parsowanie Pojedynczych Linii Logu (Linie 172–308)](#6-parsowanie-pojedynczych-linii-logu-linie-172308)
7. [Detekcja Anomalii Algorytmem K-Means (Linie 310–367)](#7-detekcja-anomalii-algorytmem-k-means-linie-310367)
8. [Analiza Zbiorcza i Procesowanie Strumieniowe (Linie 369–449)](#8-analiza-zbiorcza-i-procesowanie-strumieniowe-linie-369449)
9. [Prezentacja Wyników i Raportowanie (Linie 456–519)](#9-prezentacja-wyników-i-raportowanie-linie-456519)
10. [Interfejs CLI i Pętla Główna (Linie 526–574)](#10-interfejs-cli-i-pętla-główna-linie-526574)

---

## 1. Metadane i Nagłówek (Linie 1–20)

```python
"""
Cisco IOS Log Analyzer
----------------------
...
"""
```
* **Co to jest**: Jest to tzw. *docstring* modułu (wielolinijkowy komentarz dokumentacyjny ujęty w potrójne cudzysłowy `"""`).
* **Zastosowanie**: Python traktuje pierwszy wielolinijkowy tekst na początku pliku jako dokumentację modułu. Jest on przypisywany do specjalnego atrybutu `__doc__` i wyświetlany m.in. przy wywołaniu wbudowanej funkcji `help(Cisco_Log_Analyzer)`.
* **Zawartość**: Opisuje główne przeznaczenie skryptu (analizator logów sieciowych i systemowych) oraz definiuje podstawowe przełączniki CLI (CommandLine Interface) dla użytkownika.

---

## 2. Importy i Konfiguracja Środowiska (Linie 22–30)

### Linia 22: `from __future__ import annotations`
* **Mechanizm**: Jest to dyrektywa kompilatora. Wprowadza ona tzw. *postponed evaluation of annotations* (odłożone w czasie wartościowanie adnotacji typów).
* **Dlaczego jej używamy**: 
  1. Zapobiega błędom wykonania (RuntimeError), gdy deklarujemy typ klasy, która nie została jeszcze w pełni zdefiniowana w kodzie (tzw. referencje w przód).
  2. Zmniejsza narzut pamięciowy przy imporcie modułu, ponieważ adnotacje typów są przechowywane jako ciągi znaków (stringi), a nie analizowane jako obiekty w trakcie ładowania pliku.

### Linie 24–30: Szczegóły importowanych modułów
* **`import argparse`**: Standardowa biblioteka Pythona do budowania parserów wiersza poleceń. Automatycznie generuje komunikaty pomocy (`--help`), obsługuje parametry pozycyjne oraz flagi.
* **`import ipaddress`**: Moduł do niskopoziomowej analizy adresów sieciowych. Udostępnia klasy do reprezentacji pojedynczych hostów (`IPv4Address`) oraz całych podsieci CIDR (`IPv4Network`). Chroni przed ręcznym, podatnym na błędy pisaniem parserów maski sieciowej.
* **`import re`**: Moduł wyrażeń regularnych (ang. *regular expressions*). Oferuje silnik dopasowywania wzorców tekstowych oparty na maszynie stanów.
* **`from collections import Counter, defaultdict`**:
  * `Counter`: Podklasa słownika (`dict`), wyspecjalizowana do zliczania elementów. Zamiast zgłaszać błąd `KeyError` przy braku klucza, zwraca `0` i umożliwia łatwe pobieranie najczęstszych elementów metodą `most_common()`.
  * `defaultdict`: Podklasa słownika, która przyjmuje w konstruktorze fabrykę typów (np. `list` lub `int`). W przypadku odwołania do nieistniejącego klucza, automatycznie tworzy i przypisuje do niego nową instancję typu bazowego.
* **`from dataclasses import dataclass, field`**:
  * `@dataclass`: Dekorator klas, wprowadzony w Pythonie 3.7. Automatycznie generuje metody specjalne, takie jak `__init__()`, `__repr__()` (czytelna reprezentacja tekstowa) oraz `__eq__()` (porównywanie obiektów).
  * `field`: Funkcja pozwalająca na szczegółowe definiowanie parametrów pól w klasie danych (np. ustawienie domyślnych wartości za pomocą tzw. fabryk dla obiektów mutowalnych).
* **`from pathlib import Path`**: Nowoczesna, obiektowa alternatywa dla modułu `os.path`. Reprezentuje ścieżkę w systemie operacyjnym jako obiekt z bogatym zestawem metod (np. `.exists()`, `.open()`, czy `.splitlines()`).
* **`from typing import Iterable`**: Adnotacja typu reprezentująca dowolny obiekt, po którym można iterować pętlą `for` (np. lista, krotka, generator, plik tekstowy czytany linia po linii).

---

## 3. Wyrażenia Regularne (Regex) (Linie 34–96)

Każde wyrażenie jest prekompilowane za pomocą `re.compile(pattern)`. Zwiększa to wydajność, ponieważ Python kompiluje wzorzec do wewnętrznego kodu bajtowego tylko raz na początku uruchomienia programu, a nie przy każdej analizowanej linii logu.

### A. Wzorce dla Cisco IOS
1. **`RE_LOGIN_FAILED`** *(Linie 38-41)*:
   ```python
   r"%SEC_LOGIN-4-LOGIN_FAILED:.*?\[user:\s*(?P<user>[^\]]+)\].*?\[Source:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)\]"
   ```
   * `r"..."`: Przedrostek `r` oznacza surowy ciąg znaków (*raw string*). Dzięki temu ukośnik wsteczny `\` jest traktowany jako znak ucieczki dla regexa, a nie dla samego Pythona.
   * `.*?`: Leniwe (non-greedy) dopasowanie dowolnych znaków. Zatrzymuje się na pierwszym napotkanym nawiasie kwadratowym.
   * `\[user:\s*`: Dopasowuje dosłowny ciąg `[user:` oraz ewentualne białe znaki po nim.
   * `(?P<user>[^\]]+)`: Nazwana grupa przechwytująca o nazwie `user`. Wyrażenie `[^\]]+` dopasowuje jeden lub więcej znaków, które **nie są** nawiasem kwadratowym zamykającym `]`.
   * `(?P<ip>\d+\.\d+\.\d+\.\d+)`: Nazwana grupa `ip`. Wzorzec dopasowuje cztery grupy cyfr (`\d+`) rozdzielone kropkami (dosłowne kropki wymagają ukośnika ucieczki: `\.`).

2. **`RE_LOGIN_SUCCESS`** *(Linie 44-47)*:
   Działa identycznie jak powyżej, ale dopasowuje komunikat o powodzeniu logowania `%SEC_LOGIN-5-LOGIN_SUCCESS`.

3. **`RE_ACL_DENIED`** *(Linie 50-54)*:
   ```python
   r"%SEC-6-IPACCESSLOGP:.*?denied\s+\w+\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\(\d+\)\s*->\s*(?P<dst>\d+\.\d+\.\d+\.\d+)\((?P<dport>\d+)\)"
   ```
   * `%SEC-6-IPACCESSLOGP:`: Nagłówek blokady pakietu ACL w Cisco.
   * `denied\s+\w+\s+`: Dopasowuje słowo "denied", po którym następuje jeden lub więcej białych znaków, a następnie słowo opisujące protokół (np. `tcp`, `udp`) i kolejne spacje.
   * `(?P<ip>...)\(\d+\)`: Przechwytuje IP źródłowe. Nawiasy `\(\d+\)` dopasowują numer portu źródłowego w nawiasach okrągłych (np. `(51234)`).
   * `\s*->\s*`: Dopasowuje strzałkę określającą kierunek pakietu z opcjonalnymi spacjami.
   * `(?P<dst>...)\((?P<dport>\d+)\)`: Przechwytuje IP docelowe oraz port docelowy (`dport`).

4. **`RE_TIMESTAMP`** *(Linia 57)*:
   ```python
   r"^\*?(?P<ts>\w+\s+\d+\s+\d+:\d+:\d+(?:\.\d+)?)"
   ```
   * `^\*?`: Znak `^` oznacza początek linii. Znak `*` w Cisco czasami oznacza brak synchronizacji czasu z NTP. Ponieważ `*` jest znakiem specjalnym w regex, jest poprzedzony ukośnikiem `\*`. Znak zapytania `?` oznacza, że może on wystąpić 0 lub 1 raz.
   * `(?P<ts>...)`: Przechwytuje timestamp.
   * `\w+\s+\d+\s+`: Trzyliterowy skrót miesiąca (np. `Apr`), spacja, oraz dzień miesiąca (np. `1`).
   * `\d+:\d+:\d+`: Godzina, minuta, sekunda rozdzielone dwukropkami.
   * `(?:\.\d+)?`: Opcjonalna grupa nieprzechwytująca `(?:...)` dla milisekund (kropka i cyfry).

5. **`RE_LINK_DOWN` & `RE_LINEPROTO_DOWN`** *(Linie 60-61)*:
   Wykrywają awarie interfejsów fizycznych oraz logicznych. Przechwytują nazwę portu w grupie `(?P<port>\S+)`, gdzie `\S+` oznacza ciąg znaków niebędących białymi znakami (np. `GigabitEthernet0/1`).

6. **`RE_PORT_SECURITY_VIOLATION`** *(Linie 62)*:
   Wychwytuje mechanizm Port Security, blokujący port w przypadku podłączenia nieautoryzowanego adresu MAC.

7. **`RE_DEVICE_IN_LINE`** *(Linie 65)*:
   ```python
   r"\b(?P<device>[a-zA-Z][a-zA-Z0-9_\-]*)\s*:\s*%[A-Z]"
   ```
   * `\b`: Granica słowa (zapobiega dopasowaniu w środku dłuższego ciągu).
   * `[a-zA-Z][a-zA-Z0-9_\-]*`: Nazwa urządzenia musi zaczynać się od litery, a dalej może zawierać litery, cyfry, podkreślniki lub myślniki.
   * `\s*:\s*%[A-Z]`: Dwukropek otoczony opcjonalnymi spacjami, a po nim znak `%` i wielka litera (początek identyfikatora Cisco, np. `%SEC` lub `%SYS`).

### B. Wzorce dla Linux Syslog
1. **`RE_SYS_LOGIN_FAILED`** *(Linie 72-74)*:
   Dopasowuje błędy SSH: `sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 54321`. Wyciąga użytkownika, IP i port.
2. **`RE_SYS_LOGIN_SUCCESS`** *(Linie 78-80)*:
   Dopasowuje udane logowania przez hasło lub klucz publiczny.
3. **`RE_SYS_UFW_BLOCK`** *(Linie 83-85)*:
   Parsuje logi firewalla UFW, wyszukując pola `SRC=`, `DST=`, `PROTO=` oraz `DPT=`.
4. **`RE_SYS_SUDO_FAILURE`** *(Linie 88-90)*:
   Dopasowuje nieudane wywołania sudo na poziomie systemu.
5. **`RE_SYS_TIMESTAMP`** *(Linie 93-95)*:
   Dopasowuje timestamp w formacie RFC 3164 (np. `Jun 13 12:34:56`) lub nowszym ISO 8601 zawierającym strefę czasową (np. `2026-06-13T12:34:56.123+02:00`).

---

## 4. Klasy Danych (Dataclasses) (Linie 98–136)

### `LogEvent`
Klasa ta reprezentuje znormalizowany model pojedynczego zdarzenia. Bez względu na to, czy log pochodził z serwera Linux czy przełącznika Cisco, informacje są mapowane do tego samego formatu.

* `@dataclass`: Python automatycznie generuje dla tej klasy konstruktor `__init__`. Dzięki temu możemy tworzyć obiekty pisząc: `LogEvent(kind="login_failed", timestamp="...", ip="...")`.
* **Typowanie**: Pola takie jak `user: str | None = None` oznaczają, że wartość może być ciągiem znaków lub wartością `None`. Domyślnie pole przyjmuje wartość `None`.

### `AnalysisResult`
Klasa przechowująca kompletny stan analizy. Ze względu na to, że pola tej klasy przechowują obiekty mutowalne (takie jak listy, zbiory czy liczniki), nie można przypisać im domyślnych wartości wprost (np. `events: list = []` jest w Pythonie błędem, ponieważ wszystkie instancje współdzieliłyby tę samą listę).

Rozwiązaniem jest użycie funkcji `field(default_factory=...)`:
```python
events: list[LogEvent] = field(default_factory=list)
failed_by_ip: Counter = field(default_factory=Counter)
```
* **`default_factory=list`**: Przy tworzeniu nowego obiektu `AnalysisResult`, Python wywoła funkcję `list()` (konstruktor listy), gwarantując, że każdy obiekt otrzyma swoją własną, niezależną i pustą listę.
* **`default_factory=Counter`**: Automatycznie inicjalizuje licznik do zliczania statystyk.

---

## 5. Wczytywanie i Walidacja Adresów IP (Linie 143–170)

### Funkcja `load_allowed_networks`
Wczytuje zaufane adresy z pliku.

```python
143: def load_allowed_networks(path: Path) -> list[ipaddress.IPv4Network]:
```
* Parametr `path` przyjmuje obiekt `Path`. Funkcja zwraca listę obiektów `IPv4Network`.

```python
149:     if not path.exists():
150:         return []
```
* Instrukcja warunkowa sprawdza, czy plik istnieje na dysku za pomocą metody `.exists()`. Jeśli nie, funkcja bezpiecznie kończy działanie i zwraca pustą listę, zamiast rzucać wyjątkiem braku pliku.

```python
152:     networks: list[ipaddress.IPv4Network] = []
153:     for line in path.read_text(encoding="utf-8").splitlines():
```
* `path.read_text(encoding="utf-8")`: Wczytuje całą zawartość pliku do pamięci jako jeden długi ciąg znaków, dbając o kodowanie UTF-8.
* `.splitlines()`: Dzieli ten ciąg znaków na listę linii, automatycznie usuwając znaki końca linii (`\n` oraz `\r`).
* `for line in ...`: Pętla przetwarza każdą linię z osobna.

```python
154:         line = line.strip()
155:         if not line or line.startswith("#"):
156:             continue
```
* `line.strip()`: Usuwa białe znaki (spacje, tabulatory) z początku i końca linii.
* `if not line`: Jeśli po usunięciu spacji linia jest pusta, warunek jest spełniony.
* `line.startswith("#")`: Sprawdza, czy linia jest komentarzem.
* `continue`: Pomija dalszą część pętli i przechodzi do kolejnej linii pliku.

```python
157:         try:
158:             networks.append(ipaddress.ip_network(line, strict=False))
159:         except ValueError as err:
160:             print(f"[!] Pomijam błędny wpis w {path.name}: {line!r} ({err})")
```
* `try...except ValueError`: Blok obsługi wyjątków. Konwersja tekstu na obiekt sieci może się nie udać (np. gdy ktoś wpisze bzdury typu "192.168.1.300").
* `ipaddress.ip_network(line, strict=False)`: Główny konstruktor sieci.
  * Ustawienie `strict=False` powoduje, że jeśli podamy adres hosta zamiast adresu sieci (np. `192.168.1.55/24`), system automatycznie zamaskuje bity hosta i utworzy poprawny obiekt sieci `192.168.1.0/24`. Gdyby `strict` było ustawione na `True`, funkcja rzuciłaby wyjątek `ValueError`.
* `line!r`: Specjalny format zapisu (reprezentacja `repr()`), który otacza wypisywany ciąg apostrofami. Ułatwia to debugowanie, pokazując ewentualne niewidoczne znaki w błędnej linii.

---

### Funkcja `ip_is_allowed`
Sprawdza przynależność IP do zaufanych podsieci.

```python
164: def ip_is_allowed(ip: str, networks: Iterable[ipaddress.IPv4Network]) -> bool:
165:     try:
166:         addr = ipaddress.ip_address(ip)
167:     except ValueError:
168:         return False
169:     return any(addr in net for net in networks)
```
* `ipaddress.ip_address(ip)`: Konwertuje ciąg znaków na obiekt reprezentujący pojedynczy adres IP. W przypadku niepowodzenia (błędny format IP), zgłaszany jest wyjątek `ValueError` i funkcja zwraca `False`.
* `any(addr in net for net in networks)`: 
  * Wyrażenie generatorowe `addr in net for net in networks` sprawdza kolejno, czy adres `addr` należy do podsieci `net`.
  * Operator `in` dla obiektów klasy `IPv4Network` i `IPv4Address` jest silnie zoptymalizowany pod kątem operacji bitowych.
  * Funkcja `any()` zwraca `True` w momencie znalezienia pierwszego dopasowania (nie sprawdza reszty sieci w liście). Jeśli lista sieci jest pusta, `any()` zwraca `False`.

---

## 6. Parsowanie Pojedynczych Linii Logu (Linie 172–308)

Funkcja `parse_line` przyjmuje surowy tekst linii z logu i opcjonalnie nazwę urządzenia. Zwraca obiekt `LogEvent` lub `None`.

```python
175:     ts_match = RE_TIMESTAMP.search(line)
176:     timestamp = ts_match.group("ts") if ts_match else ""
```
* `RE_TIMESTAMP.search(line)`: Przeszukuje linię w poszukiwaniu dopasowania do wzorca czasu Cisco.
* `ts_match.group("ts")`: Wyciąga dopasowaną wartość z nazwanej grupy `ts`. Jeśli dopasowania nie było, zmienna `timestamp` staje się pustym ciągiem znaków.

```python
179:     if not timestamp:
180:         sys_ts_match = RE_SYS_TIMESTAMP.search(line)
181:         if sys_ts_match:
182:             timestamp = sys_ts_match.group("ts")
183:             device_type = "linux"
```
* Jeśli nie znaleziono czasu Cisco, sprawdzany jest czas typu Linux Syslog. Jeśli zostanie dopasowany, typ urządzenia (`device_type`) jest przełączany z domyślnego `"cisco"` na `"linux"`.

```python
186:     if not device:
187:         dev_match = RE_DEVICE_IN_LINE.search(line)
188:         if dev_match:
189:             device = dev_match.group("device")
```
* Jeśli nazwa urządzenia nie została podana przy wywołaniu funkcji, skrypt próbuje ją wyodrębnić bezpośrednio z logu.

```python
193:     if m := RE_LINK_DOWN.search(line):
194:         port = m.group("port")
```
* **Operator Walrus (`:=`)**: Wprowadzony w Pythonie 3.8 operator przypisania wewnątrz wyrażeń. Pozwala na jednoczesne wykonanie dopasowania regexa, przypisanie wyniku do zmiennej `m` oraz sprawdzenie w warunku `if`, czy wynik nie jest wartością `None`. Zapobiega to dwukrotnemu pisaniu tej samej instrukcji.
* Kod sprawdza kolejne typy awarii interfejsów (link down, lineprotocol down, psecure-violation). W przypadku wykrycia, zwracany jest obiekt `LogEvent` o typie `"port_down"`.

Następnie funkcja po kolei dopasowuje inne wzorce:
* Cisco logowania: `%SEC_LOGIN-4-LOGIN_FAILED` i `%SEC_LOGIN-5-LOGIN_SUCCESS`.
* Cisco ACL: `%SEC-6-IPACCESSLOGP`.
* Linux logowania: błędy i sukcesy SSH, blokady zapory UFW, błędy sudo.

#### Obsługa błędów SUDO:
```python
281:     if m := RE_SYS_SUDO_FAILURE.search(line):
282:         rhost_match = re.search(r"rhost=(?P<ip>\d+\.\d+\.\d+\.\d+)", line)
283:         ip = rhost_match.group("ip") if rhost_match else "127.0.0.1"
```
* Podczas błędów autoryzacji sudo, adres IP hosta, który wywołał zdarzenie, bywa logowany w polu `rhost=`. Skrypt próbuje go dynamicznie wyciągnąć. Jeśli wywołanie było lokalne (brak pola `rhost`), przypisywany jest adres lokalny `127.0.0.1`.

#### Wykrywanie ogólnych błędów:
```python
295:     if any(kw in line.lower() for kw in ["error", "fail", "critical", "err_disable", "violation"]):
296:         # Spróbujmy wyciągnąć IP, jeśli istnieje w logu
297:         ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
...
```
* `line.lower()`: Konwertuje całą linię na małe litery, dzięki czemu wyszukiwanie słów kluczowych jest niewrażliwe na wielkość znaków (np. dopasuje "Error", "ERROR" i "critical").
* `any(...)`: Jeśli chociaż jedno słowo kluczowe z listy znajduje się w linii logu, linia jest klasyfikowana jako zdarzenie systemowe.
* `(?:\d{1,3}\.){3}\d{1,3}`: Regex dopasowujący dowolny adres IP w tekście (grupa nieprzechwytująca `(?:...)` dopasowuje trzy powtórzenia cyfr z kropką, a na końcu czwartą grupę cyfr).

---

## 7. Detekcja Anomalii Algorytmem K-Means (Linie 310–367)

Ta funkcja służy do identyfikacji urządzeń, które wykazują nietypowo dużą liczbę awarii portów w stosunku do pozostałych urządzeń w sieci.

```python
310: def detect_anomalies_kmeans(
311:     port_down_by_device: dict[str, int],
312:     all_devices: set[str]
313: ) -> list[tuple[str, int, float]]:
```
* Przyjmuje słownik mapujący urządzenia na ilość awarii oraz zbiór wszystkich urządzeń. Zwraca listę krotek zawierających nazwę urządzenia, liczbę awarii oraz wskaźnik anomalii.

```python
319:     full_profile = {}
320:     for dev in all_devices:
321:         full_profile[dev] = port_down_by_device.get(dev, 0)
```
* Buduje kompletny profil sieci. Jeśli jakieś urządzenie nie miało żadnych awarii (nie występuje w słowniku `port_down_by_device`), metoda `.get(dev, 0)` przypisuje mu domyślnie `0`.

```python
323:     if not full_profile or max(full_profile.values()) == 0:
324:         return []
```
* Zabezpieczenie przed dzieleniem przez zero. Jeśli żadne urządzenie nie uległo awarii, algorytm natychmiast kończy działanie.

```python
329:     c0 = min(values)
330:     c1 = max(values)
```
* **Inicjalizacja**: Ustala początkowe położenie dwóch klastrów (centroidów). `c0` zaczyna od wartości minimalnej (zazwyczaj 0), a `c1` od wartości maksymalnej (urządzenie o największej liczbie awarii).

```python
335:     for _ in range(15):
336:         g0 = []
337:         g1 = []
```
* Główna pętla wykonuje maksymalnie 15 iteracji (co w przypadku jednowymiarowego zbioru danych jest wartością w zupełności wystarczającą do osiągnięcia zbieżności). W każdej iteracji przygotowywane są nowe puste listy dla grup `g0` i `g1`.

```python
338:         for v in values:
339:             if abs(v - c0) < abs(v - c1):
340:                 g0.append(v)
341:             else:
342:                 g1.append(v)
```
* Klasyfikacja: Dla każdej wartości awarii `v` obliczana jest odległość bezwzględna `abs(v - c)` do obu centroidów. Wartość trafia do grupy tego centroidu, do którego ma bliżej.

```python
347:         new_c0 = sum(g0) / len(g0)
348:         new_c1 = sum(g1) / len(g1)
```
* Aktualizacja: Środki klastrów są przesuwane w miejsce nowo obliczonych średnich arytmetycznych z przypisanych do nich wartości.

```python
350:         if new_c0 == c0 and new_c1 == c1:
351:             break
```
* Warunek stopu: Jeśli w danej iteracji centroidy nie zmieniły swojej pozycji ani o ułamek, oznacza to, że algorytm osiągnął optymalny podział i dalsze iteracje są zbędne.

```python
355:     threshold = (c0 + c1) / 2
```
* Próg podziału (`threshold`) jest wyznaczany jako dokładny środek geometryczny pomiędzy dwoma ostatecznymi centroidami grup.

```python
357:     anomalies = []
358:     for d in devices:
359:         val = full_profile[d]
360:         if val > threshold and val > 0:
361:             normal_avg = sum(g0) / len(g0) if c0 < c1 else sum(g1) / len(g1)
362:             score = float(val) / max(normal_avg, 1.0)
363:             anomalies.append((d, val, round(score, 2)))
```
* Wyłonienie anomalii: Każde urządzenie, które ma więcej awarii niż wyliczony `threshold`, trafia na listę anomalii.
* `score`: Wylicza współczynnik anomalii. Jest to stosunek awarii danego urządzenia do średniej liczby awarii w grupie urządzeń "zdrowych" (czyli tej grupy, która ma mniejszy centroid).
* `round(score, 2)`: Zaokrągla wskaźnik do dwóch miejsc po przecinku w celu zachowania czytelności raportu.

---

## 8. Główna Logika Analizująca (Linie 369–449)

### Funkcja `analyze_lines`
Przetwarza linie logów i agreguje statystyki.

```python
381:     for item in lines:
382:         if isinstance(item, tuple):
383:             line, device = item
384:         else:
385:             line, device = item, None
```
* Funkcja jest elastyczna. Obsługuje wejście w postaci samej linii tekstowej (`str`) lub krotki `(line, device)`. Funkcja `isinstance(item, tuple)` sprawdza typ elementu w locie w celu poprawnego rozpakowania zmiennych.

```python
388:         event = parse_line(line, device=device)
389:         if event is None:
390:             continue
```
* Pobiera znormalizowany obiekt zdarzenia. Jeśli linia nie zawierała żadnego z poszukiwanych wzorców (funkcja `parse_line` zwróciła `None`), pętla przechodzi do następnej linii.

```python
396:         if event.kind == "login_failed":
397:             result.failed_by_ip[event.ip] += 1
...
```
* Blok instrukcji warunkowych `if/elif` sprawdza typ zdarzenia i inkrementuje odpowiednie liczniki w obiekcie `AnalysisResult`. Zastosowanie obiektów `Counter` sprawia, że nie musimy najpierw sprawdzać, czy dane IP istnieje w słowniku – operacja `+= 1` tworzy klucz automatycznie w razie potrzeby.

```python
413:         if event.ip != "127.0.0.1" and not ip_is_allowed(event.ip, allowed):
414:             result.unknown_ips.add(event.ip)
```
* Zabezpieczenie przed fałszywymi alarmami: Adresy lokalne `127.0.0.1` są ignorowane. Inne adresy IP są sprawdzane funkcją `ip_is_allowed`. Jeśli nie należą do zaufanych podsieci, ich adresy są dodawane do zbioru `unknown_ips`.

```python
416:     # Podejrzenie brute-force
417:     result.brute_force_suspects = [
418:         (ip, count)
419:         for ip, count in result.failed_by_ip.most_common()
420:         if count >= brute_force_threshold
421:     ]
```
* **List Comprehension** (wyrażenie listowe): Zwięzły sposób na budowanie nowej listy na podstawie istniejącej kolekcji.
* `result.failed_by_ip.most_common()`: Metoda ta zwraca listę krotek `(element, licznik)` posortowaną malejąco według liczby wystąpień.
* Skrypt odfiltrowuje tylko te IP, dla których licznik błędnych logowań przekroczył zadany próg (`brute_force_threshold`).

---

### Funkcja `analyze`
```python
439: def analyze(
...
446:     with log_path.open("r", encoding="utf-8", errors="replace") as fh:
447:         lines = fh.readlines()
448:     return analyze_lines(lines, allowed, brute_force_threshold, port_failure_threshold)
```
* `with log_path.open(...) as fh`: Użycie tzw. menedżera kontekstu (instrukcja `with`). Gwarantuje ona, że plik zostanie poprawnie zamknięty w systemie operacyjnym po wyjściu z bloku kodu, nawet jeśli w trakcie czytania pliku wystąpi nieoczekiwany błąd.
* `errors="replace"`: Parametr ten zapobiega przerwaniu programu w przypadku napotkania w pliku logu znaków o nieprawidłowym kodowaniu binarnym. Takie znaki zostaną automatycznie zastąpione oficjalnym znakiem zastępczym Unicode (U+FFFD, czyli ``).
* `fh.readlines()`: Wczytuje cały plik jako listę osobnych linii tekstu.

---

## 9. Prezentacja Wyników i Raportowanie (Linie 456–519)

### Funkcja `print_report`
Generuje podsumowanie i wypisuje je na ekran.

```python
457:     bar = "=" * 70
```
* Przeciążenie operatora mnożenia dla obiektów tekstowych. Instrukcja ta tworzy ciąg składający się z dokładnie 70 znaków równości (`=`).

```python
483:             print(f"    - {ip:<16} {' '.join(info)}")
```
* `{ip:<16}`: Formatowanie wyrównujące tekst do lewej strony na stałej szerokości 16 znaków. Gwarantuje to, że kolumny z adresami IP będą idealnie wyrównane w pionie, niezależnie od długości adresu IP (np. `10.0.0.1` vs `203.0.113.155`).
* `' '.join(info)`: Łączy elementy listy `info` (która przechowuje statystyki zdarzeń dla tego IP) w jeden ciąg znaków rozdzielony spacjami.

```python
509:     targeted_users = Counter(
510:         e.user for e in result.events if e.kind == "login_failed" and e.user
511:     )
```
* dynamicznie tworzy nowy obiekt `Counter` na podstawie wyrażenia generatorowego, filtrującego wszystkie zdarzenia o typie `"login_failed"` i zliczającego nazwy użytkowników, na których próbowano się zalogować.

---

## 10. Interfejs CLI i Pętla Główna (Linie 526–574)

### Funkcja `build_parser`
Definiuje strukturę argumentów wiersza poleceń.

```python
526: def build_parser() -> argparse.ArgumentParser:
527:     parser = argparse.ArgumentParser(
528:         description="Analizator logów Cisco IOS",
529:     )
```
* Inicjalizuje obiekt parsera z opisem aplikacji, który pojawi się w konsoli po dodaniu flagi `-h` lub `--help`.

```python
530:     parser.add_argument(
531:         "logs",
532:         nargs="*",
533:         default=["Sample_Logs/Cisco_ios.log"],
...
537:     parser.add_argument(
538:         "--allowed",
539:         default="Allowed_IPS",
...
```
* `"logs"`: Parametr pozycyjny (nie wymaga kresek).
  * `nargs="*"`: Oznacza, że użytkownik może podać zero, jeden lub wiele plików logów na raz.
  * `default=[...]`: Jeśli użytkownik nie poda żadnego pliku, skrypt automatycznie użyje domyślnego pliku z katalogu `Sample_Logs`.
* `"--allowed"`: Parametr opcjonalny (wymaga flagi `--allowed ścieżka`).

---

### Funkcja `main` i Blok Startowy
```python
550: def main(argv: list[str] | None = None) -> int:
551:     args = build_parser().parse_args(argv)
```
* `parse_args(argv)`: Analizuje argumenty przekazane do skryptu. Jeśli funkcja zostanie wywołana bez parametrów (domyślnie `argv=None`), biblioteka `argparse` odczyta je bezpośrednio z systemowej tablicy `sys.argv`.

```python
561:     for log_file in args.logs:
562:         path = Path(log_file)
563:         if not path.exists():
564:             print(f"[!] Plik nie istnieje: {path}")
565:             continue
```
* Pętla przechodzi po wszystkich plikach przekazanych przez użytkownika. Obiekt `Path` weryfikuje istnienie każdego z plików na dysku. W przypadku braku pliku wypisywane jest ostrzeżenie, a skrypt przechodzi do następnego elementu listy.

```python
573: if __name__ == "__main__":
574:     raise SystemExit(main())
```
* `if __name__ == "__main__"`: Konstrukcja warunkowa sprawdzająca kontekst uruchomienia. Zmienna `__name__` przyjmuje wartość `"__main__"` tylko wtedy, gdy plik został bezpośrednio uruchomiony (np. poprzez `python Cisco_Log_Analyzer.py`). Jeśli plik został zaimportowany w innym skrypcie jako biblioteka, ten warunek nie zostanie spełniony, co zapobiega automatycznemu uruchomieniu funkcji `main()`.
* `raise SystemExit(main())`: Uruchamia funkcję `main()`, pobiera od niej kod wyjścia (`0` oznacza sukces) i zamyka interpreter Pythona z tym właśnie kodem systemowym.
