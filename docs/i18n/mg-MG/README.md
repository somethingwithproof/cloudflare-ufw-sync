# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · **Malagasy** · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Fampifanarahana ny adiresy IP Cloudflare ho an'ny UFW.

## Fijerena ankapobeny

Ny `cloudflare-ufw-sync` dia mampifanaraka ny faritra adiresy IP an'ny Cloudflare amin'ny fitsipiky ny UFW (Uncomplicated Firewall) anao. Ny mpampifanaraka no mitantana ireo fitsipika UFW voarindra ao aminy; ny famerana ny fidirana mivantana amin'ny loharano (origin) dia miankina ihany koa amin'ny politika fototra sy izay fitsipika fanekena hafa. Ny fampifanarahana irery dia tsy manaporofo fa voasakana ny fidirana mivantana amin'ny loharano.

## Maritrano

![Sarin'ny maritrano](../../../architecture.png)

## Endri-javatra

- 🔄 Fampifanarahana mandeha ho azy ny faritra adiresy IP Cloudflare amin'ny fitsipika UFW
- 🔒 Fitantanana azo antoka ny fitsipika UFW miaraka amin'ny fikarakarana alalana sahaza
- 🛠️ Manohana na ny faritra adiresy IPv4 na IPv6
- 🔍 Firaketana an-tsoratra amin'ny antsipiriany ho an'ny fanaraha-maso sy ny famahana olana
- 🔧 Fanefena azo amboarina araka izay tiana
- 🧪 Andiana fitsapana

## Fametrahana

### Avy amin'ny kaody loharano

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Fanefena

Mamorona rakitra fanefena ao amin'ny `/etc/cloudflare-ufw-sync/config.yml` na `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Fampiasana

### Andalan-kibaiko

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### Amin'ny maha-tolotra (service) azy

Misy rakitra tolotra systemd omena mba hampandehanana ny fampifanarahana ho tolotra:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Fiteny sy faritra

Ny fanampiana CLI, ny famintinana sata, ary ny hafatra fampandehanana dia manohana fiteny sy faritra 45 (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) tsy misy fiankinan-doha fanampiny. Ny famaritana ny fiteny dia manamarina ny `--lang`, avy eo `LC_ALL`, `LC_MESSAGES`, ary `LANG`, ary miverina amin'ny `en`.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Fampandrosoana

### Fitsapana amin'ny Docker

Raha tianao ny tontolo mitokana, dia azonao atao ny manangana sy mampandeha ny andiana fitsapana manontolo ao anatin'ny Docker.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Io indrindra no fanamboarana ampiasaina ao amin'ny CI sy ampiasain'ny mpikojakoja rehefa manamarina ny fanovana eo an-toerana.

### Tanjona Make

Ho fanamorana, misy tanjona make vitsivitsy manaraka ny fizotran'ny Docker:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Fanomanana

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

### Fitsapana sy fanamarinana kaody amin'ny Tox

Ahitana rakitra `tox.ini` ity tetikasa ity izay manomana tontolo ho an'ny fitsapana, fanamarinana kaody (linting), ary fanamarinana karazana (type checking). Izany dia ahafahanao manao eo an-toerana ireo fanamarinana mitovy amin'izay atao ao amin'ny CI alohan'ny handefasana ny fanovanao.

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

### Fitsapana atao tanana

Raha tianao ny manao ny fitsapana sy ny fanamarinana kaody tanana:

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

## Lisansa

Ity tetikasa ity dia omena lisansa eo ambanin'ny MIT License - jereo ny rakitra [LICENSE](../../../LICENSE) raha mila antsipiriany.

## Fiarovana

Jereo ny [SECURITY.md](../../../SECURITY.md) raha mila ny politikan'ny fiarovana sy ny fomba fanaovana tatitra momba ny lesoka fiarovana.

## Fandraisana anjara

Ankasitrahana ny fandraisana anjara! Aza misalasala mandefa Pull Request.
