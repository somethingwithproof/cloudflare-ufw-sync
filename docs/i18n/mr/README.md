# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · **मराठी** · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

UFW साठी Cloudflare IP सिंक्रोनायझेशन.

## आढावा

`cloudflare-ufw-sync` तुमच्या UFW (Uncomplicated Firewall) नियमांसह Cloudflare च्या IP रेंजेस सिंक्रोनाइझ करते. सिंक्रोनायझर त्याचे कॉन्फिगर केलेले UFW नियम व्यवस्थापित करतो; मूळ (origin) प्रवेश प्रतिबंधित करणे हे डीफॉल्ट धोरण आणि इतर कोणत्याही allow नियमांवर देखील अवलंबून असते. एकट्या सिंक्रोनायझेशनवरून थेट-मूळ (direct-origin) प्रवेश अवरोधित केला गेला आहे हे सिद्ध होत नाही.

## आर्किटेक्चर

![आर्किटेक्चर आकृती](../../../architecture.png)

## वैशिष्ट्ये

- 🔄 UFW नियमांसह Cloudflare IP रेंजेसचे स्वयंचलित सिंक्रोनायझेशन
- 🔒 योग्य परवानगी हाताळणीसह UFW नियम सुरक्षितपणे व्यवस्थापित करते
- 🛠️ IPv4 आणि IPv6 दोन्ही पत्ता रेंजेसना समर्थन देते
- 🔍 ऑडिट आणि समस्यानिवारणासाठी तपशीलवार लॉगिंग
- 🔧 सानुकूलित करण्यायोग्य कॉन्फिगरेशन
- 🧪 चाचणी संच

## इंस्टॉलेशन

### सोर्समधून

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## कॉन्फिगरेशन

`/etc/cloudflare-ufw-sync/config.yml` किंवा `~/.config/cloudflare-ufw-sync/config.yml` येथे कॉन्फिगरेशन फाइल तयार करा:

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

## वापर

### कमांड लाइन

```bash
# Run a sync operation
sudo cloudflare-ufw-sync sync

# Run in daemon mode
sudo cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### सेवा म्हणून

सिंक्रोनायझेशन सेवा म्हणून चालवण्यासाठी systemd सर्व्हिस फाइल प्रदान केली आहे:

```bash
sudo install -d -m 0755 /var/log/cloudflare-ufw-sync
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## स्थानिकीकरण

CLI मदत, स्थिती सारांश आणि ऑपरेशनल संदेश कोणत्याही अतिरिक्त अवलंबित्वाशिवाय 45 लोकेल्स (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) ला समर्थन देतात. रिझोल्यूशन `--lang`, नंतर `LC_ALL`, `LC_MESSAGES`, आणि `LANG` तपासते आणि शेवटी `en` वर परत येते.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## विकास

### Docker सह चाचणी

तुम्हाला वेगळे वातावरण हवे असल्यास, तुम्ही संपूर्ण चाचणी संच Docker मध्ये तयार करून चालवू शकता.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

स्थानिक पातळीवर बदल तपासताना CI मध्ये आणि मेंटेनर्सद्वारे वापरला जाणारा हाच अचूक सेटअप आहे.

### Make लक्ष्ये

सोयीसाठी, काही make लक्ष्ये Docker वर्कफ्लोची प्रतिकृती तयार करतात:

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

### Tox सह चाचणी आणि लिंटिंग

प्रकल्पामध्ये `tox.ini` फाइल समाविष्ट आहे जी चाचणी, लिंटिंग आणि टाइप चेकिंगसाठी वातावरण सेट करते. हे तुम्हाला तुमचे बदल कमिट करण्यापूर्वी CI पाइपलाइनमध्ये केल्या जाणाऱ्या त्याच तपासण्या स्थानिक पातळीवर चालवण्याची परवानगी देते.

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

### मॅन्युअल चाचणी

तुम्ही चाचण्या आणि लिंटिंग मॅन्युअली चालवू इच्छित असल्यास:

```bash
# Run tests
pytest

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src
```

## परवाना

हा प्रकल्प MIT परवान्याअंतर्गत परवानाकृत आहे - तपशीलांसाठी [LICENSE](../../../LICENSE) फाइल पहा.

## सुरक्षा

सुरक्षा धोरण आणि भेद्यता कळवण्यासाठी [SECURITY.md](../../../SECURITY.md) पहा.

## योगदान

योगदानांचे स्वागत आहे! कृपया मोकळ्या मनाने Pull Request सबमिट करा.
