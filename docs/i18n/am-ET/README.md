# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · **አማርኛ** · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

ለUFW የCloudflare IP ማመሳሰያ።

## አጠቃላይ እይታ

`cloudflare-ufw-sync` የCloudflareን የIP ክልሎች ከUFW (Uncomplicated Firewall) ደንቦችዎ ጋር ያመሳስላል። አመሳሳዩ የተዋቀሩትን የUFW ደንቦቹን ያስተዳድራል፤ የመነሻ አገልጋይ መዳረሻን መገደብ በነባሪው ፖሊሲ እና በሌሎች የፍቃድ ደንቦች ላይም ይወሰናል። ማመሳሰል ብቻውን ቀጥተኛ የመነሻ አገልጋይ መዳረሻ መታገዱን አያረጋግጥም።

## አርክቴክቸር

![የአርክቴክቸር ንድፍ](../../../architecture.png)

## ባህሪያት

- 🔄 የCloudflare IP ክልሎችን ከUFW ደንቦች ጋር በራስ ሰር ማመሳሰል
- 🔒 በተገቢው የፈቃድ አያያዝ የUFW ደንቦችን በደህንነት ያስተዳድራል
- 🛠️ ሁለቱንም IPv4 እና IPv6 አድራሻ ክልሎች ይደግፋል
- 🔍 ለኦዲት እና ለችግር መፍቻ ዝርዝር መዝገቦች
- 🔧 ሊበጅ የሚችል ውቅር
- 🧪 የሙከራ ስብስብ

## መጫን

### ከምንጭ ኮድ

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## ውቅር

በ`/etc/cloudflare-ufw-sync/config.yml` ወይም በ`~/.config/cloudflare-ufw-sync/config.yml` ላይ የውቅር ፋይል ይፍጠሩ:

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

## አጠቃቀም

### የትእዛዝ መስመር

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### እንደ አገልግሎት

ማመሳሰሉን እንደ አገልግሎት ለማስኬድ የsystemd አገልግሎት ፋይል ቀርቧል:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## የቋንቋ አካባቢያዊነት

የCLI እገዛ፣ የሁኔታ ማጠቃለያዎች እና የአሠራር መልእክቶች ምንም ተጨማሪ ጥገኝነቶች ሳይኖራቸው 45 ቋንቋዎችን (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) ይደግፋሉ። የቋንቋ አመራረጥ መጀመሪያ `--lang`ን፣ ከዚያ `LC_ALL`፣ `LC_MESSAGES` እና `LANG`ን ይፈትሻል፣ ወደ `en` በመመለስ።

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## ልማት

### በDocker መሞከር

የተነጠለ አካባቢን የሚመርጡ ከሆነ፣ የሙከራ ስብስቡን ሙሉ በሙሉ በDocker ውስጥ መገንባት እና ማስኬድ ይችላሉ።

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

ይህ በCI ውስጥ እና ጠባቂዎች ለውጦችን በአካባቢያቸው ሲፈትሹ የሚጠቀሙበት ትክክለኛው አወቃቀር ነው።

### የMake ዒላማዎች

ለምቾት ሲባል ጥቂት የmake ዒላማዎች የDocker የሥራ ፍሰትን ያንጸባርቃሉ:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### ዝግጅት

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

### በTox መሞከር እና ኮድ መፈተሽ

ፕሮጀክቱ ለሙከራ፣ ለኮድ ፍተሻ እና ለዓይነት ፍተሻ አካባቢዎችን የሚያዘጋጅ `tox.ini` ፋይል ያካትታል። ይህ ለውጦችዎን ከማስገባትዎ በፊት በCI ሂደት ውስጥ የሚከናወኑትን ተመሳሳይ ፍተሻዎች በአካባቢዎ እንዲያስኪዱ ያስችልዎታል።

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

### በእጅ የሚደረግ ሙከራ

ሙከራዎችን እና የኮድ ፍተሻዎችን በእጅ ማስኬድ የሚመርጡ ከሆነ:

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

## ፈቃድ

ይህ ፕሮጀክት በMIT ፈቃድ ሥር የተፈቀደ ነው፤ ለዝርዝሮች የ[LICENSE](../../../LICENSE) ፋይልን ይመልከቱ።

## ደህንነት

ለደህንነት ፖሊሲ እና ተጋላጭነቶችን ለማሳወቅ [SECURITY.md](../../../SECURITY.md)ን ይመልከቱ።

## አስተዋጽዖ ማበርከት

አስተዋጽዖዎች በደስታ ይቀበላሉ! እባክዎ Pull Request ለማስገባት አያመንቱ።
