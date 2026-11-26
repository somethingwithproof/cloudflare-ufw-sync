# Cloudflare UFW-sinkronisering

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](./pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

**Afrikaans** · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Cloudflare IP-sinkronisering vir UFW.

## Oorsig

`cloudflare-ufw-sync` sinkroniseer Cloudflare se IP-reekse met jou UFW-reëls (Uncomplicated Firewall). Die sinkroniseerder bestuur sy gekonfigureerde UFW-reëls; die beperking van oorsprongtoegang hang ook af van die verstekbeleid en enige ander toelatingsreëls. Sinkronisering alleen bewys nie dat direkte oorsprongtoegang geblokkeer is nie.

## Argitektuur

![Argitektuurdiagram](../../../architecture.png)

## Kenmerke

- 🔄 Outomatiese sinkronisering van Cloudflare IP-reekse met UFW-reëls
- 🔒 Bestuur UFW-reëls veilig met behoorlike toestemmingshantering
- 🛠️ Ondersteun beide IPv4- en IPv6-adresreekse
- 🔍 Gedetailleerde logboeke vir oudit en foutsporing
- 🔧 Aanpasbare konfigurasie
- 🧪 Toetsstel

## Installasie

### Vanuit bronkode

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Konfigurasie

Skep 'n konfigurasielêer by `/etc/cloudflare-ufw-sync/config.yml` of `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Gebruik

### Opdragreël

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### As 'n diens

'n systemd-dienslêer word verskaf om die sinkronisering as 'n diens te laat loop:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Lokalisering

CLI-hulp, statusopsommings en bedryfsboodskappe ondersteun 45 lokale (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) sonder ekstra afhanklikhede. Oplossing kontroleer `--lang`, dan `LC_ALL`, `LC_MESSAGES`, en `LANG`, en val terug na `en`.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Ontwikkeling

### Toetsing met Docker

As jy 'n geïsoleerde omgewing verkies, kan jy die toetsstel geheel en al in Docker bou en laat loop.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Dit is presies die opstelling wat in CI en deur onderhouers gebruik word wanneer veranderings plaaslik nagegaan word.

### Make-teikens

Geriefshalwe weerspieël 'n paar make-teikens die Docker-werkvloei:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Opstelling

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

### Toetsing en linting met Tox

Die projek sluit 'n `tox.ini`-lêer in wat omgewings vir toetsing, linting en tipekontrole opstel. Dit stel jou in staat om dieselfde kontroles plaaslik uit te voer wat in die CI-pyplyn uitgevoer word voordat jy jou veranderings commit.

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

### Handmatige toetsing

As jy verkies om toetse en linting handmatig uit te voer:

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

## Lisensie

Hierdie projek is gelisensieer onder die MIT-lisensie - sien die [LICENSE](../../../LICENSE)-lêer vir besonderhede.

## Sekuriteit

Sien [SECURITY.md](../../../SECURITY.md) vir sekuriteitsbeleid en die aanmelding van kwesbaarhede.

## Bydraes

Bydraes is welkom! Dien gerus 'n trekversoek in.
