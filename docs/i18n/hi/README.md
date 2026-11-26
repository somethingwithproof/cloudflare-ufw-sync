# Cloudflare UFW सिंक

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](./pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · **हिन्दी** · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

UFW के लिए Cloudflare IP सिंक्रनाइज़ेशन।

## अवलोकन

`cloudflare-ufw-sync` Cloudflare की IP श्रेणियों को आपके UFW (Uncomplicated Firewall) नियमों के साथ सिंक्रनाइज़ करता है। सिंक्रनाइज़र अपने कॉन्फ़िगर किए गए UFW नियमों का प्रबंधन करता है; ओरिजिन एक्सेस को प्रतिबंधित करना डिफ़ॉल्ट नीति और किसी भी अन्य अनुमति नियमों पर भी निर्भर करता है। केवल सिंक्रनाइज़ेशन से यह साबित नहीं होता कि डायरेक्ट-ओरिजिन एक्सेस अवरुद्ध है।

## आर्किटेक्चर

![आर्किटेक्चर आरेख](../../../architecture.png)

## विशेषताएं

- 🔄 UFW नियमों के साथ Cloudflare IP श्रेणियों का स्वचालित सिंक्रनाइज़ेशन
- 🔒 उचित अनुमति प्रबंधन के साथ UFW नियमों का सुरक्षित संचालन
- 🛠️ IPv4 और IPv6 दोनों पता श्रेणियों का समर्थन
- 🔍 ऑडिट और समस्या निवारण के लिए विस्तृत लॉगिंग
- 🔧 अनुकूलन योग्य कॉन्फ़िगरेशन
- 🧪 परीक्षण सुइट

## स्थापना

### सोर्स से

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## कॉन्फ़िगरेशन

`/etc/cloudflare-ufw-sync/config.yml` या `~/.config/cloudflare-ufw-sync/config.yml` पर एक कॉन्फ़िगरेशन फ़ाइल बनाएं:

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

## उपयोग

### कमांड लाइन

```bash
# Run a sync operation
sudo cloudflare-ufw-sync sync

# Run in daemon mode
sudo cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### सेवा के रूप में

सिंक्रनाइज़ेशन को एक सेवा के रूप में चलाने के लिए एक systemd सेवा फ़ाइल प्रदान की गई है:

```bash
sudo install -d -m 0755 /var/log/cloudflare-ufw-sync
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## स्थानीयकरण

CLI सहायता, स्थिति सारांश और परिचालन संदेश बिना किसी अतिरिक्त निर्भरता के 45 लोकेल (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) का समर्थन करते हैं। रिज़ॉल्यूशन `--lang`, फिर `LC_ALL`, `LC_MESSAGES`, और `LANG` की जांच करता है, और कुछ न मिलने पर `en` पर वापस आ जाता है।

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## विकास

### Docker के साथ परीक्षण

यदि आप एक अलग-थलग वातावरण पसंद करते हैं, तो आप पूरी तरह से Docker में परीक्षण सुइट बना और चला सकते हैं।

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

यह वही सेटअप है जिसका उपयोग CI में और स्थानीय स्तर पर परिवर्तनों की जांच करते समय रखरखावकर्ताओं द्वारा किया जाता है।

### Make लक्ष्य

सुविधा के लिए, कुछ make लक्ष्य Docker वर्कफ़्लो को दर्शाते हैं:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### सेटअप

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

### Tox के साथ परीक्षण और लिंटिंग

परियोजना में एक `tox.ini` फ़ाइल शामिल है जो परीक्षण, लिंटिंग और टाइप जांच के लिए वातावरण सेट करती है। यह आपको अपने परिवर्तनों को कमिट करने से पहले स्थानीय स्तर पर वही जांच चलाने की अनुमति देता है जो CI पाइपलाइन में किए जाते हैं।

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

### मैनुअल परीक्षण

यदि आप परीक्षण और लिंटिंग मैनुअल रूप से चलाना पसंद करते हैं:

```bash
# Run tests
pytest

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src
```

## लाइसेंस

यह परियोजना MIT लाइसेंस के तहत लाइसेंसीकृत है, विवरण के लिए [LICENSE](../../../LICENSE) फ़ाइल देखें।

## सुरक्षा

सुरक्षा नीति और कमजोरियों की रिपोर्ट करने के लिए [SECURITY.md](../../../SECURITY.md) देखें।

## योगदान

योगदान का स्वागत है! कृपया बेझिझक एक पुल अनुरोध सबमिट करें।
