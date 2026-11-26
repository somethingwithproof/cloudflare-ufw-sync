# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · **Yorùbá** · [isiZulu](../zu-ZA/README.md)

</details>

Ìṣọ̀kan IP Cloudflare fún UFW.

## Àkópọ̀

`cloudflare-ufw-sync` ń ṣọ̀kan àwọn ààlà IP ti Cloudflare pẹ̀lú àwọn òfin UFW (Uncomplicated Firewall) rẹ. Olùṣọ̀kan náà ń ṣàkóso àwọn òfin UFW tí a ṣètò fún un; dídín ààyè ìwọlé orísun kù tún sinmi lórí ìlànà àìyípadà àti àwọn òfin ìgbàláyè mìíràn. Ìṣọ̀kan nìkan kò fìdí rẹ̀ múlẹ̀ pé a ti dí ìwọlé tààrà sí orísun.

## Àwòrán ìṣètò

![Àwòrán Ìṣètò](../../../architecture.png)

## Àwọn ẹ̀yà ara

- 🔄 Ìṣọ̀kan aládàáṣe ti àwọn ààlà IP Cloudflare pẹ̀lú àwọn òfin UFW
- 🔒 Ṣíṣàkóso àwọn òfin UFW ní ààbò pẹ̀lú ìtọ́jú ìyọ̀ǹda tó yẹ
- 🛠️ Ṣe àtìlẹ́yìn fún àwọn ààlà àdírẹ́sì IPv4 àti IPv6 méjèèjì
- 🔍 Àkọsílẹ̀ kíkún fún àyẹ̀wò àti yíyanjú ìṣòro
- 🔧 Ìṣètò tí a lè ṣàtúnṣe
- 🧪 Àkójọ àyẹ̀wò

## Ìfisórí

### Láti Orísun

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Ìṣètò

Ṣẹ̀dá fáìlì ìṣètò kan ní `/etc/cloudflare-ufw-sync/config.yml` tàbí `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Ìlò

### Ìlà-àṣẹ

```bash
# Run a sync operation
sudo cloudflare-ufw-sync sync

# Run in daemon mode
sudo cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### Gẹ́gẹ́ bí Iṣẹ́-ìsìn

A pèsè fáìlì iṣẹ́-ìsìn systemd kan láti ṣiṣẹ́ ìṣọ̀kan náà gẹ́gẹ́ bí iṣẹ́-ìsìn:

```bash
sudo install -d -m 0755 /var/log/cloudflare-ufw-sync
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Ìsọdèdè

Ìrànlọ́wọ́ ìlà-àṣẹ, àwọn àkópọ̀ ipò, àti àwọn ìfiránṣẹ́ ìṣiṣẹ́ ṣe àtìlẹ́yìn fún èdè agbègbè 45 (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) láìsí àfikún ìgbẹ́kẹ̀lé kankan. Ìyànjú ń ṣàyẹ̀wò `--lang`, lẹ́yìn náà `LC_ALL`, `LC_MESSAGES`, àti `LANG`, ó sì ń padà sí `en`.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Ìdàgbàsókè

### Ṣíṣe àyẹ̀wò pẹ̀lú Docker

Tí o bá fẹ́ àyíká tí a yà sọ́tọ̀, o lè kọ kí o sì ṣiṣẹ́ àkójọ àyẹ̀wò náà pátápátá nínú Docker.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Èyí ni ìṣètò pàtó tí a ń lò nínú CI àti láti ọwọ́ àwọn olùtọ́jú nígbà tí wọ́n bá ń ṣàyẹ̀wò àwọn àyípadà lórí ẹ̀rọ wọn.

### Àwọn àfojúsùn Make

Fún ìrọ̀rùn, àwọn àfojúsùn make díẹ̀ ṣe àfarawé ìṣàn-iṣẹ́ Docker náà:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Ìṣètò ìbẹ̀rẹ̀

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

### Àyẹ̀wò àti Linting pẹ̀lú Tox

Iṣẹ́-àkànṣe yìí ní fáìlì `tox.ini` kan tí ó ń ṣètò àwọn àyíká fún àyẹ̀wò, linting, àti àyẹ̀wò irú dátà. Èyí fún ọ láàyè láti ṣe àwọn àyẹ̀wò kan náà lórí ẹ̀rọ rẹ tí a ń ṣe nínú ìlà-iṣẹ́ CI ṣáájú kí o tó fi àwọn àyípadà rẹ sílẹ̀.

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

### Àyẹ̀wò Ọwọ́

Tí o bá fẹ́ láti ṣe àwọn àyẹ̀wò àti linting pẹ̀lú ọwọ́:

```bash
# Run tests
pytest

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src
```

## Ìwé-àṣẹ

Iṣẹ́-àkànṣe yìí wà lábẹ́ Ìwé-àṣẹ MIT; wo fáìlì [LICENSE](../../../LICENSE) fún àlàyé kíkún.

## Ààbò

Wo [SECURITY.md](../../../SECURITY.md) fún ìlànà ààbò àti fífi ìròyìn àwọn àléébù ààbò ránṣẹ́.

## Ìfikún

A gbà àwọn ìfikún tọwọ́tẹsẹ̀! Jọ̀wọ́ má ṣe lọ́ tìkọ̀ láti fi Pull Request ránṣẹ́.
