# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](./pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · **తెలుగు** · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

UFW కోసం Cloudflare IP సమకాలీకరణ.

## అవలోకనం

`cloudflare-ufw-sync` మీ UFW (Uncomplicated Firewall) నియమాలతో Cloudflare యొక్క IP శ్రేణులను సమకాలీకరిస్తుంది. ఈ సమకాలీకరణ సాధనం కాన్ఫిగర్ చేసిన తన UFW నియమాలను నిర్వహిస్తుంది; ఆరిజిన్ యాక్సెస్‌ను నియంత్రించడం అనేది డిఫాల్ట్ విధానం మరియు ఇతర అనుమతి నియమాలపై కూడా ఆధారపడి ఉంటుంది. కేవలం సమకాలీకరణ మాత్రమే డైరెక్ట్-ఆరిజిన్ యాక్సెస్ బ్లాక్ చేయబడిందని నిరూపించదు.

## ఆర్కిటెక్చర్

![ఆర్కిటెక్చర్ రేఖాచిత్రం](../../../architecture.png)

## ఫీచర్లు

- 🔄 UFW నియమాలతో Cloudflare IP శ్రేణుల స్వయంచాలక సమకాలీకరణ
- 🔒 సరైన అనుమతుల నిర్వహణతో UFW నియమాలను సురక్షితంగా నిర్వహిస్తుంది
- 🛠️ IPv4 మరియు IPv6 చిరునామా శ్రేణులు రెండింటికీ మద్దతు ఇస్తుంది
- 🔍 ఆడిట్ మరియు సమస్యల పరిష్కారం కోసం సవివరమైన లాగింగ్
- 🔧 అనుకూలీకరించదగిన కాన్ఫిగరేషన్
- 🧪 పరీక్షా సూట్

## ఇన్‌స్టాలేషన్

### సోర్స్ నుండి

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## కాన్ఫిగరేషన్

`/etc/cloudflare-ufw-sync/config.yml` లేదా `~/.config/cloudflare-ufw-sync/config.yml` వద్ద ఒక కాన్ఫిగరేషన్ ఫైల్‌ను సృష్టించండి:

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

## వినియోగం

### కమాండ్ లైన్

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### సర్వీస్‌గా

సమకాలీకరణను ఒక సర్వీస్‌గా అమలు చేయడానికి systemd సర్వీస్ ఫైల్ అందించబడింది:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## స్థానికీకరణ

CLI సహాయం, స్థితి సారాంశాలు మరియు కార్యాచరణ సందేశాలు ఎటువంటి అదనపు డిపెండెన్సీలు లేకుండా 45 లోకేల్స్‌కు (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) మద్దతు ఇస్తాయి. నిర్ధారణ `--lang`, ఆపై `LC_ALL`, `LC_MESSAGES`, మరియు `LANG`లను తనిఖీ చేసి, చివరకు `en`కు తిరిగి వస్తుంది.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## అభివృద్ధి

### Dockerతో పరీక్షించడం

మీరు వివిక్త వాతావరణాన్ని కోరుకుంటే, పరీక్షా సూట్‌ను పూర్తిగా Dockerలో నిర్మించి అమలు చేయవచ్చు.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

మార్పులను స్థానికంగా తనిఖీ చేసేటప్పుడు CIలో మరియు మెయింటెయినర్లు ఉపయోగించే ఖచ్చితమైన సెటప్ ఇదే.

### Make టార్గెట్‌లు

సౌలభ్యం కోసం, కొన్ని make టార్గెట్‌లు Docker వర్క్‌ఫ్లోను ప్రతిబింబిస్తాయి:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### సెటప్

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

### Toxతో పరీక్షించడం మరియు లింటింగ్

ఈ ప్రాజెక్ట్‌లో పరీక్షలు, లింటింగ్ మరియు టైప్ చెకింగ్ కోసం వాతావరణాలను సెటప్ చేసే `tox.ini` ఫైల్ ఉంది. మీ మార్పులను కమిట్ చేయడానికి ముందు CI పైప్‌లైన్‌లో నిర్వహించే తనిఖీలను స్థానికంగా అమలు చేయడానికి ఇది మిమ్మల్ని అనుమతిస్తుంది.

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

### మాన్యువల్ పరీక్ష

మీరు పరీక్షలు మరియు లింటింగ్‌ను మాన్యువల్‌గా అమలు చేయాలనుకుంటే:

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

## లైసెన్స్

ఈ ప్రాజెక్ట్ MIT లైసెన్స్ కింద లైసెన్స్ పొందింది, వివరాల కోసం [LICENSE](../../../LICENSE) ఫైల్‌ను చూడండి.

## భద్రత

భద్రతా విధానం మరియు లోపాలను నివేదించడం కోసం [SECURITY.md](../../../SECURITY.md) చూడండి.

## సహకారం

సహకారాలకు స్వాగతం! దయచేసి నిరభ్యంతరంగా పుల్ రిక్వెస్ట్‌ను సమర్పించండి.
