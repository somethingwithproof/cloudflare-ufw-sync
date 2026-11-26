# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](./pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · **Polski** · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Synchronizacja adresów IP Cloudflare dla UFW.

## Przegląd

`cloudflare-ufw-sync` synchronizuje zakresy adresów IP Cloudflare z regułami zapory UFW (Uncomplicated Firewall). Synchronizator zarządza skonfigurowanymi przez siebie regułami UFW; ograniczenie dostępu do serwera źródłowego (origin) zależy również od domyślnej polityki oraz innych reguł zezwalających. Sama synchronizacja nie gwarantuje, że bezpośredni dostęp do serwera źródłowego jest zablokowany.

## Architektura

![Diagram architektury](../../../architecture.png)

## Funkcje

- 🔄 Automatyczna synchronizacja zakresów adresów IP Cloudflare z regułami UFW
- 🔒 Bezpieczne zarządzanie regułami UFW z odpowiednią obsługą uprawnień
- 🛠️ Obsługa zakresów adresów IPv4 oraz IPv6
- 🔍 Szczegółowe logowanie na potrzeby audytu i rozwiązywania problemów
- 🔧 Konfigurowalne ustawienia
- 🧪 Zestaw testów

## Instalacja

### Ze źródeł

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Konfiguracja

Utwórz plik konfiguracyjny w `/etc/cloudflare-ufw-sync/config.yml` lub `~/.config/cloudflare-ufw-sync/config.yml`:

```yaml
cloudflare:
  api_key: your-api-key  # Optional: Only needed if using authenticated endpoints
  ip_types:
    - v4  # IPv4 addresses
    - v6  # IPv6 addresses

ufw:
  default_policy: deny
  port: 443  # The port to allow access to
  proto: tcp  # Protocol passed to ufw (for example tcp or udp)
  comment: "Cloudflare IP"  # Comment for UFW rules

sync:
  interval: 86400  # Sync interval in seconds (default: 1 day)
```

## Użycie

### Wiersz poleceń

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### Jako usługa

Dostarczono plik usługi systemd umożliwiający uruchamianie synchronizacji jako usługi:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Lokalizacja

Pomoc CLI, podsumowania statusu oraz komunikaty operacyjne obsługują 45 języków (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) bez dodatkowych zależności. Rozpoznawanie języka sprawdza `--lang`, następnie `LC_ALL`, `LC_MESSAGES` i `LANG`, z powrotem do `en`.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Rozwój

### Testowanie w Docker

Jeśli wolisz odizolowane środowisko, możesz zbudować i uruchomić zestaw testów w całości w Docker.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Jest to dokładnie ta sama konfiguracja, której używa się w CI oraz przez opiekunów projektu podczas lokalnej weryfikacji zmian.

### Cele Make

Dla wygody kilka celów make odzwierciedla przepływ pracy w Docker:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Przygotowanie środowiska

```bash
# Clone the repository
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync

# Set up a virtual environment
python -m venv venv
source venv/bin/activate

# Install dev dependencies
pip install -e ".[dev]"
```

### Testowanie i lintowanie za pomocą Tox

Projekt zawiera plik `tox.ini`, który konfiguruje środowiska do testowania, lintowania i sprawdzania typów. Pozwala to uruchamiać lokalnie przed zatwierdzeniem zmian te same sprawdzenia, które wykonywane są w potoku CI.

```bash
# Install tox
pip install tox

# Run tests, lint and type checks on supported Python
tox -e py312,lint,mypy

# Run tests on Python 3.12, the minimum supported version
tox -e py312

# Run only linting checks
tox -e lint

# Run only type checking
tox -e mypy

# Format code
tox -e format
```

### Testowanie ręczne

Jeśli wolisz uruchamiać testy i lintowanie ręcznie:

```bash
# Run tests
pytest

# Run linting
black .
isort .
flake8

# Run type checking
mypy src
```

## Licencja

Ten projekt jest objęty licencją MIT - szczegóły znajdują się w pliku [LICENSE](../../../LICENSE).

## Bezpieczeństwo

Zobacz [SECURITY.md](../../../SECURITY.md), aby zapoznać się z polityką bezpieczeństwa i sposobem zgłaszania podatności.

## Współpraca

Wkład w projekt jest mile widziany! Zachęcamy do przesyłania Pull Requestów.
