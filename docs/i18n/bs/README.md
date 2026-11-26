# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (28 locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · **Bosanski** · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Hrvatski](../hr/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Српски](../sr/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Sinhronizacija Cloudflare IP adresa za UFW.

## Pregled

`cloudflare-ufw-sync` sinhronizira opsege Cloudflare IP adresa sa vašim UFW (Uncomplicated Firewall) pravilima. Alat upravlja isključivo svojim podešenim UFW pravilima; ograničavanje direktnog pristupa izvornom serveru zavisi i od zadane politike vatrozida te svih ostalih pravila koja dozvoljavaju pristup. Sama sinhronizacija ne garantuje da je direktan pristup izvornom serveru blokiran.

## Arhitektura

![Dijagram arhitekture](../../../architecture.png)

## Mogućnosti

- 🔄 Automatska sinhronizacija Cloudflare IP opsega sa UFW pravilima
- 🔒 Sigurno upravljanje UFW pravilima uz ispravnu obradu dozvola
- 🛠️ Podrška za IPv4 i IPv6 opsege adresa
- 🔍 Detaljno vođenje dnevnika za reviziju, izvještaje i otklanjanje grešaka
- 🔧 Prilagodljive postavke konfiguracije
- 🧪 Skup automatizovanih testova

## Instalacija

### Iz izvornog koda

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Konfiguracija

Kreirajte konfiguracijsku datoteku na putanji `/etc/cloudflare-ufw-sync/config.yml` ili `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Korištenje

### Komandna linija

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### Kao servis

Datoteka systemd servisa omogućava pokretanje sinhronizacije kao sistemskog servisa:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Lokalizacija

Pomoć komandne linije, sažeci statusa i operativne poruke podržavaju 48 lokaliteta (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`, `bs`, `hr`, `sr`) bez ikakvih dodatnih ovisnosti. Određivanje jezika redom provjerava `--lang`, zatim `LC_ALL`, `LC_MESSAGES` i `LANG`, te se u suprotnom vraća na `en`.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Razvoj

### Testiranje pomoću Dockera

Ako želite izolovano okruženje, možete napraviti sliku i pokrenuti cijeli skup testova unutar Dockera.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Ovo je ista postavka koja se koristi u CI sistemu i koju održavaoci koriste za lokalnu provjeru izmjena.

### Make ciljevi

Radi jednostavnijeg rada, nekoliko Make ciljeva prati Docker tok rada:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Podešavanje okruženja

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

### Testiranje i statička provjera pomoću Toxa

Projekat sadrži datoteku `tox.ini` koja priprema okruženja za testiranje, provjeru stila koda i provjeru tipova. To vam omogućava da na svom računaru pokrenete iste provjere koje se izvršavaju u CI procesu prije slanja izmjena.

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

### Ručno testiranje

Ako preferirate ručno pokretanje testova i provjera stila koda:

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

## Licenca

Ovaj projekat je objavljen pod MIT licencom - za detalje pogledajte datoteku [LICENSE](../../../LICENSE).

## Sigurnost

Pogledajte [SECURITY.md](../../../SECURITY.md) za sigurnosnu politiku i upute za prijavu ranjivosti.

## Doprinos

Doprinosi su dobrodošli! Slobodno pošaljite Pull Request.
