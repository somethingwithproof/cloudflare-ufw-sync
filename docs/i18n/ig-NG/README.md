# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · **Igbo** · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Mmekọrịta adreesị IP Cloudflare maka UFW.

## Nchịkọta

`cloudflare-ufw-sync` na-eme ka usoro adreesị IP nke Cloudflare na iwu UFW (Uncomplicated Firewall) gị kwekọọ. Ngwa mmekọrịta a na-ejikwa iwu UFW ya a haziri; igbochi nnweta ozugbo na seva mbụ daberekwa na iwu ndabara na iwu nkwado ọ bụla ọzọ. Mmekọrịta naanị ya anaghị egosi na e gbochiri nnweta ozugbo na seva mbụ.

## Nhazi usoro

![Eserese Nhazi Usoro](../../../architecture.png)

## Njirimara

- 🔄 Mmekọrịta na-akpaghị aka nke usoro adreesị IP Cloudflare na iwu UFW
- 🔒 Na-ejikwa iwu UFW n'ụzọ dị nchebe site na njikwa ikike kwesịrị ekwesị
- 🛠️ Na-akwado ma usoro adreesị IPv4 ma IPv6
- 🔍 Ndekọ ozi zuru ezu maka nnyocha na idozi nsogbu
- 🔧 Nhazi a pụrụ ịhazi dị ka e si chọọ
- 🧪 Otu nnwale

## Nwụnye

### Site na koodu isi

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Nhazi

Mepụta faịlụ nhazi na `/etc/cloudflare-ufw-sync/config.yml` ma ọ bụ `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Ojiji

### Ahịrị iwu

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### Dị ka ọrụ sistemụ

E nyere faịlụ ọrụ systemd iji gbaa mmekọrịta ahụ dị ka ọrụ sistemụ:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Nhazi asụsụ mpaghara

Enyemaka CLI, nchịkọta ọkwa, na ozi ọrụ na-akwado asụsụ mpaghara 45 (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) na-enweghị ihe ndabere ọzọ ọ bụla. Mkpebi asụsụ na-enyocha `--lang`, wee `LC_ALL`, `LC_MESSAGES`, na `LANG`, wee laghachi na `en`.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Mmepe

### Nnwale site na Docker

Ọ bụrụ na ị họrọ gburugburu dịpụrụ iche, i nwere ike iwulite ma gbaa otu nnwale ahụ kpamkpam na Docker.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Nke a bụ kpọmkwem nhazi a na-eji na CI na nke ndị nlekọta na-eji mgbe ha na-enyocha mgbanwe n'igwe ha.

### Ebumnuche Make

Maka mfe, ụfọdụ ebumnuche make na-egosipụta usoro ọrụ Docker:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Ntọlite

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

### Nnwale na Linting site na Tox

Ọrụ a gụnyere faịlụ `tox.ini` nke na-atọlite gburugburu maka nnwale, linting, na nnyocha ụdị data. Nke a na-enye gị ohere ịgba otu nnyocha ndị a na-eme na usoro CI n'igwe gị tupu i dee kọmit maka mgbanwe gị.

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

### Nnwale aka

Ọ bụrụ na ị họrọ ịgba nnwale na linting n'onwe gị:

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

## Ikikere

E nyere ọrụ a ikikere n'okpuru MIT License - lee faịlụ [LICENSE](../../../LICENSE) maka nkọwa zuru ezu.

## Nchekwa

Lee [SECURITY.md](../../../SECURITY.md) maka ụkpụrụ nchekwa na ịkọ akụkọ adịghị ike nchekwa.

## Inye aka

A na-anabata ntinye aka! Biko nweere onwe gị iziga Pull Request.
