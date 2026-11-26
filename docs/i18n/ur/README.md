# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · **اردو** · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

UFW کے لیے Cloudflare IP ہم آہنگی۔

## جائزہ

`cloudflare-ufw-sync` Cloudflare کی IP رینجز کو آپ کے UFW (Uncomplicated Firewall) قواعد کے ساتھ ہم آہنگ (synchronize) کرتا ہے۔ سنکرونائزر اپنے کنفیگر کردہ UFW قواعد کا انتظام کرتا ہے؛ اصل سرور (origin) تک رسائی کو محدود کرنا ڈیفالٹ پالیسی اور کسی بھی دوسرے allow قواعد پر بھی منحصر ہوتا ہے۔ محض ہم آہنگی سے یہ ثابت نہیں ہوتا کہ اصل سرور تک براہِ راست رسائی مسدود ہے۔

## فنِ تعمیر

![فنِ تعمیر کا خاکہ](../../../architecture.png)

## خصوصیات

- 🔄 Cloudflare IP رینجز کی UFW قواعد کے ساتھ خودکار ہم آہنگی
- 🔒 مناسب اجازتوں (permission handling) کے ساتھ UFW قواعد کا محفوظ انتظام
- 🛠️ IPv4 اور IPv6 دونوں ایڈریس رینجز کی معاونت
- 🔍 آڈٹ اور خرابیوں کے ازالے کے لیے تفصیلی لاگنگ
- 🔧 قابلِ تخصیص کنفیگریشن
- 🧪 ٹیسٹ سویٹ

## تنصیب

### سورس کوڈ سے

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## کنفیگریشن

`/etc/cloudflare-ufw-sync/config.yml` یا `~/.config/cloudflare-ufw-sync/config.yml` پر ایک کنفیگریشن فائل بنائیں:

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

## استعمال

### کمانڈ لائن

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### بطور سروس

ہم آہنگی کو سروس کے طور پر چلانے کے لیے ایک systemd سروس فائل فراہم کی گئی ہے:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## لوکلائزیشن

CLI مدد، اسٹیٹس کے خلاصے، اور آپریشنل پیغامات بغیر کسی اضافی انحصار کے 45 لوکیلز (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) کی معاونت کرتے ہیں۔ لوکیل کی شناخت پہلے `--lang`، پھر `LC_ALL`، `LC_MESSAGES`، اور `LANG` کو چیک کرتی ہے، اور آخر میں `en` پر واپس آتی ہے۔

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## ترقی

### Docker کے ساتھ ٹیسٹنگ

اگر آپ ایک الگ تھلگ ماحول پسند کرتے ہیں، تو آپ ٹیسٹ سویٹ کو مکمل طور پر Docker میں بنا اور چلا سکتے ہیں۔

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

یہ بالکل وہی سیٹ اپ ہے جو CI میں اور مینٹینرز کی طرف سے مقامی طور پر تبدیلیوں کی بنیادی جانچ کرتے وقت استعمال ہوتا ہے۔

### Make اہداف

سہولت کے لیے، چند make اہداف Docker ورک فلو کی عکاسی کرتے ہیں:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### سیٹ اپ

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

### Tox کے ساتھ ٹیسٹنگ اور لنٹنگ

اس پروجیکٹ میں ایک `tox.ini` فائل شامل ہے جو ٹیسٹنگ، لنٹنگ، اور ٹائپ چیکنگ کے لیے ماحول ترتیب دیتی ہے۔ اس سے آپ اپنی تبدیلیاں کمٹ کرنے سے پہلے مقامی طور پر وہی جانچیں چلا سکتے ہیں جو CI پائپ لائن میں انجام دی جاتی ہیں۔

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

### دستی ٹیسٹنگ

اگر آپ ٹیسٹس اور لنٹنگ دستی طور پر چلانا پسند کرتے ہیں:

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

## لائسنس

یہ پروجیکٹ MIT لائسنس کے تحت لائسنس یافتہ ہے، تفصیلات کے لیے [LICENSE](../../../LICENSE) فائل دیکھیں۔

## سیکیورٹی

سیکیورٹی پالیسی اور کمزوریوں کی اطلاع دینے کے لیے [SECURITY.md](../../../SECURITY.md) دیکھیں۔

## تعاون

تعاون کا خیرمقدم ہے! براہِ کرم بلا جھجک Pull Request جمع کروائیں۔
