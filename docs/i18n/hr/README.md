# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (28 locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [Bosanski](../bs/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · **Hrvatski** · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Српски](../sr/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Sinkronizacija Cloudflare IP adresa za UFW.

## Pregled

`cloudflare-ufw-sync` sinkronizira raspone Cloudflare IP adresa s vašim pravilima vatrozida UFW (Uncomplicated Firewall). Sinkronizator upravlja isključivo vlastitim podešenim UFW pravilima; ograničavanje izravnog pristupa izvornom poslužitelju ovisi i o zadanim pravilima te svim drugim pravilima dopuštanja. Sama sinkronizacija ne dokazuje da je izravan pristup izvornom poslužitelju blokiran.

## Arhitektura

![Dijagram arhitekture](../../../architecture.png)

## Značajke

- 🔄 Automatska sinkronizacija raspona Cloudflare IP adresa s UFW pravilima
- 🔒 Sigurno upravljanje UFW pravilima uz ispravno rukovanje ovlastima
- 🛠️ Podrška za raspone IPv4 i IPv6 adresa
- 🔍 Opsežno zapisivanje za reviziju, izvješća i otklanjanje pogrešaka
- 🔧 Prilagodljive postavke u datoteci konfiguracije
- 🧪 Sveobuhvatan skup testova

## Instalacija

### Iz izvornog koda

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Postavke

Izradite datoteku postavki na putanji `/etc/cloudflare-ufw-sync/config.yml` ili `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Upotreba

### Naredbeni redak

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### Kao usluga

Priložena je datoteka usluge systemd za izvođenje sinkronizacije kao pozadinske usluge:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Lokalizacija

Pomoć naredbenog retka, sažeci stanja i radne poruke podržavaju 48 lokaliteta (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`, `bs`, `hr`, `sr`) bez ikakvih dodatnih ovisnosti. Razrješavanje jezika najprije provjerava `--lang`, zatim `LC_ALL`, `LC_MESSAGES` i `LANG`, uz povratak na `en`.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Razvoj

### Testiranje pomoću Dockera

Ako preferirate izolirano okruženje, možete izgraditi sliku i pokrenuti skup testova u cijelosti unutar Dockera.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Ovo je identično okruženje koje se upotrebljava u CI sustavu i koje održavatelji koriste za lokalnu provjeru promjena.

### Ciljevi alata Make

Radi lakšeg rada, nekoliko ciljeva alata Make preslikava tijek rada u Dockeru:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Postavljanje okruženja

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

### Testiranje i provjera stila pomoću alata Tox

Projekt uključuje datoteku `tox.ini` koja postavlja okruženja za testiranje, statičku analizu i provjeru tipova. To vam omogućuje da na vlastitom računalu pokrenete iste provjere koje se izvršavaju u CI cjevovodu prije pohrane izmjena.

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

Ako radije pokrećete testove i statičku analizu ručno:

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

## Licencija

Ovaj projekt objavljen je pod MIT licencijom - pojedinosti potražite u datoteci [LICENSE](../../../LICENSE).

## Sigurnost

Pogledajte [SECURITY.md](../../../SECURITY.md) za sigurnosna pravila i postupak prijave ranjivosti.

## Doprinosi

Doprinosi su dobrodošli! Slobodno pošaljite zahtjev za spajanje (Pull Request).
