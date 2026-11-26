# Usawazishaji wa Cloudflare UFW

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · **Kiswahili** · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Usawazishaji wa IP za Cloudflare kwa ajili ya UFW.

## Muhtasari

`cloudflare-ufw-sync` husawazisha masafa ya IP ya Cloudflare na sheria zako za UFW (Uncomplicated Firewall). Kisawazishaji husimamia sheria zake za UFW zilizosanidiwa; kuzuia ufikiaji wa seva asili pia kunategemea sera chaguo-msingi na sheria nyingine zozote za kuruhusu. Usawazishaji pekee hauthibitishi kuwa ufikiaji wa moja kwa moja kwa seva asili umezuiwa.

## Muundo wa mfumo

![Mchoro wa Muundo wa Mfumo](../../../architecture.png)

## Vipengele

- 🔄 Usawazishaji otomatiki wa masafa ya IP ya Cloudflare na sheria za UFW
- 🔒 Husimamia sheria za UFW kwa usalama na ushughulikiaji sahihi wa ruhusa
- 🛠️ Inasaidia masafa ya anwani za IPv4 na IPv6
- 🔍 Uwekaji kumbukumbu wa kina kwa ukaguzi na utatuzi wa matatizo
- 🔧 Usanidi unaoweza kubinafsishwa
- 🧪 Msururu wa majaribio

## Usakinishaji

### Kutoka kwa msimbo chanzo

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Usanidi

Tengeneza faili ya usanidi katika `/etc/cloudflare-ufw-sync/config.yml` au `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Matumizi

### Mstari wa amri

```bash
# Run a sync operation
sudo cloudflare-ufw-sync sync

# Run in daemon mode
sudo cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### Kama huduma

Faili ya huduma ya systemd imetolewa ili kuendesha usawazishaji kama huduma:

```bash
sudo install -d -m 0755 /var/log/cloudflare-ufw-sync
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Ujanibishaji

Usaidizi wa CLI, muhtasari wa hali, na ujumbe wa uendeshaji husaidia lugha 45 (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) bila vitegemezi vya ziada. Utatuzi hukagua `--lang`, kisha `LC_ALL`, `LC_MESSAGES`, na `LANG`, na kurudi kwenye `en`.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Uendelezaji

### Majaribio kwa kutumia Docker

Ukipenda mazingira yaliyotengwa, unaweza kujenga na kuendesha msururu wa majaribio yote ndani ya Docker.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Huu ndio usanidi kamili unaotumiwa katika CI na wasimamizi wanapokagua mabadiliko katika mazingira ya ndani.

### Malengo ya Make

Kwa urahisi, malengo machache ya make huakisi mtiririko wa kazi wa Docker:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Maandalizi

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

### Majaribio na ukaguzi wa msimbo kwa kutumia Tox

Mradi unajumuisha faili ya `tox.ini` inayoweka mazingira ya majaribio, ukaguzi wa mtindo wa msimbo, na ukaguzi wa aina. Hii hukuruhusu kuendesha ukaguzi uleule katika mazingira ya ndani unaofanywa katika bomba la CI kabla ya kuwasilisha mabadiliko yako.

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

### Majaribio ya mkono

Ukipenda kuendesha majaribio na ukaguzi wa msimbo wewe mwenyewe:

```bash
# Run tests
pytest

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src
```

## Leseni

Mradi huu umeidhinishwa chini ya Leseni ya MIT - tazama faili ya [LICENSE](../../../LICENSE) kwa maelezo.

## Usalama

Tazama [SECURITY.md](../../../SECURITY.md) kwa sera ya usalama na kuripoti udhaifu.

## Kuchangia

Michango inakaribishwa! Tafadhali jisikie huru kuwasilisha Pull Request.
