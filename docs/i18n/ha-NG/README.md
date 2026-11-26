# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](./pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · **Hausa** · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Daidaita adiresoshin IP na Cloudflare don UFW.

## Taƙaitaccen bayani

`cloudflare-ufw-sync` yana daidaita kewayon adiresoshin IP na Cloudflare tare da ƙa'idojin UFW (Uncomplicated Firewall) naka. Mai daidaitawar yana sarrafa ƙa'idojin UFW da aka saita masa; hana shiga sabar asali kai tsaye ya dogara ne kuma da ainihin manufar tsoho da duk wasu ƙa'idojin izini. Daidaitawa kaɗai ba ta tabbatar da cewa an toshe shiga sabar asali kai tsaye ba.

## Tsarin gini

![Zanen tsarin gini](../../../architecture.png)

## Fasaloli

- 🔄 Daidaitawa ta atomatik na kewayon adiresoshin IP na Cloudflare tare da ƙa'idojin UFW
- 🔒 Yana sarrafa ƙa'idojin UFW cikin tsaro tare da ingantaccen kulawa da izini
- 🛠️ Yana goyan bayan kewayon adiresoshin IPv4 da IPv6 duka
- 🔍 Cikakken rajistan bayanai don bincike da magance matsaloli
- 🔧 Saiti mai sauƙin keɓancewa
- 🧪 Tarin gwaje-gwaje

## Shigarwa

### Daga lambar asali

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Saiti

Ƙirƙiri fayil ɗin saiti a `/etc/cloudflare-ufw-sync/config.yml` ko `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Amfani

### Layin umarni

```bash
# Run a sync operation
sudo cloudflare-ufw-sync sync

# Run in daemon mode
sudo cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### A matsayin sabis

An samar da fayil ɗin sabis na systemd don gudanar da daidaitawar a matsayin sabis:

```bash
sudo install -d -m 0755 /var/log/cloudflare-ufw-sync
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Daidaita harshe

Taimakon CLI, taƙaitaccen matsayi, da saƙonnin aiki suna goyan bayan harsuna 45 (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) ba tare da ƙarin wani abin dogaro ba. Zaɓin harshe yana duba `--lang`, sannan `LC_ALL`, `LC_MESSAGES`, da `LANG`, yana komawa zuwa `en` a ƙarshe.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Haɓakawa

### Gwajin aiki tare da Docker

Idan ka fi son keɓaɓɓen muhalli, za ka iya ginawa da gudanar da tarin gwaje-gwajen gaba ɗaya a cikin Docker.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Wannan shi ne ainihin tsarin da ake amfani da shi a CI da kuma masu kulawa yayin tabbatar da sauye-sauye a na'urar gida.

### Umarnin Make

Don sauƙin aiki, wasu umarnin make suna kwaikwayon tsarin aikin Docker:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Shirin farawa

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

### Gwaji da binciken lamba tare da Tox

Aikin ya ƙunshi fayil ɗin `tox.ini` wanda ke saita muhallai don gwaji, binciken tsarin lamba (linting), da duba nau'ikan bayanai. Wannan yana ba ka damar gudanar da irin binciken da ake yi a tsarin CI a na'urarka kafin ka adana sauye-sauyenka.

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

### Gwaji da hannu

Idan ka fi son gudanar da gwaje-gwaje da binciken lamba da hannu:

```bash
# Run tests
pytest

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src
```

## Lasisi

An ba da lasisin wannan aikin a ƙarƙashin MIT License - duba fayil ɗin [LICENSE](../../../LICENSE) don cikakken bayani.

## Tsaro

Duba [SECURITY.md](../../../SECURITY.md) don manufar tsaro da bayar da rahoton matsalolin tsaro.

## Ba da gudummawa

Ana maraba da gudummawa! Jin daɗi ka tura Pull Request.
