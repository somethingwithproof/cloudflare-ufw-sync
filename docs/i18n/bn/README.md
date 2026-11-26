# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · **বাংলা** · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

UFW-এর জন্য Cloudflare IP সিঙ্ক্রোনাইজেশন।

## সংক্ষিপ্ত বিবরণ

`cloudflare-ufw-sync` আপনার UFW (Uncomplicated Firewall) নিয়মগুলোর সাথে Cloudflare-এর IP রেঞ্জগুলো সিঙ্ক্রোনাইজ করে। সিঙ্ক্রোনাইজারটি তার কনফিগার করা UFW নিয়মগুলো পরিচালনা করে; অরিজিন অ্যাক্সেস সীমাবদ্ধ করা ডিফল্ট নীতি এবং অন্যান্য অনুমতির নিয়মগুলোর ওপরও নির্ভর করে। কেবল সিঙ্ক্রোনাইজেশন প্রমাণ করে না যে সরাসরি-অরিজিন অ্যাক্সেস ব্লক করা হয়েছে।

## আর্কিটেকচার

![আর্কিটেকচার ডায়াগ্রাম](../../../architecture.png)

## বৈশিষ্ট্যসমূহ

- 🔄 UFW নিয়মের সাথে Cloudflare IP রেঞ্জের স্বয়ংক্রিয় সিঙ্ক্রোনাইজেশন
- 🔒 সঠিক অনুমতি ব্যবস্থাপনার সাথে নিরাপদে UFW নিয়ম পরিচালনা করে
- 🛠️ IPv4 এবং IPv6 উভয় ঠিকানা রেঞ্জ সমর্থন করে
- 🔍 অডিট এবং সমস্যা সমাধানের জন্য বিস্তারিত লগিং
- 🔧 কাস্টমাইজযোগ্য কনফিগারেশন
- 🧪 টেস্ট স্যুট

## ইনস্টলেশন

### সোর্স থেকে

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## কনফিগারেশন

`/etc/cloudflare-ufw-sync/config.yml` অথবা `~/.config/cloudflare-ufw-sync/config.yml`-এ একটি কনফিগারেশন ফাইল তৈরি করুন:

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

## ব্যবহার

### কমান্ড লাইন

```bash
# Run a sync operation
sudo cloudflare-ufw-sync sync

# Run in daemon mode
sudo cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### সার্ভিস হিসেবে

সার্ভিস হিসেবে সিঙ্ক্রোনাইজেশন চালানোর জন্য একটি systemd সার্ভিস ফাইল সরবরাহ করা হয়েছে:

```bash
sudo install -d -m 0755 /var/log/cloudflare-ufw-sync
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## লোকালাইজেশন

CLI সাহায্য, স্ট্যাটাস সারাংশ এবং অপারেশনাল বার্তাগুলো কোনো অতিরিক্ত ডিপেন্ডেন্সি ছাড়াই ৪৫টি লোকেল (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) সমর্থন করে। লোকেল নির্ধারণে প্রথমে `--lang`, তারপর `LC_ALL`, `LC_MESSAGES` এবং `LANG` পরীক্ষা করা হয়, এবং না পাওয়া গেলে `en`-এ ফিরে যায়।

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## উন্নয়ন

### Docker দিয়ে টেস্ট করা

আপনি যদি একটি বিচ্ছিন্ন পরিবেশ পছন্দ করেন, তবে পুরো টেস্ট স্যুটটি Docker-এ তৈরি ও চালাতে পারেন।

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

স্থানীয়ভাবে পরিবর্তনগুলো যাচাই করার সময় CI এবং রক্ষণাবেক্ষণকারীরা ঠিক এই সেটআপটিই ব্যবহার করেন।

### Make টার্গেটসমূহ

সুবিধার জন্য, কয়েকটি make টার্গেট Docker ওয়ার্কফ্লোকে অনুসরণ করে:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### সেটআপ

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

### Tox দিয়ে টেস্টিং এবং লিন্টিং

প্রকল্পটিতে একটি `tox.ini` ফাইল রয়েছে যা টেস্টিং, লিন্টিং এবং টাইপ চেকিংয়ের জন্য পরিবেশ প্রস্তুত করে। এটি আপনাকে আপনার পরিবর্তনগুলো কমিট করার আগে CI পাইপলাইনে চালানো একই পরীক্ষাগুলো স্থানীয়ভাবে চালানোর সুযোগ দেয়।

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

### ম্যানুয়াল টেস্টিং

আপনি যদি ম্যানুয়ালি টেস্ট এবং লিন্টিং চালাতে পছন্দ করেন:

```bash
# Run tests
pytest

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src
```

## লাইসেন্স

এই প্রকল্পটি MIT লাইসেন্সের অধীনে লাইসেন্সপ্রাপ্ত - বিস্তারিত জানার জন্য [LICENSE](../../../LICENSE) ফাইলটি দেখুন।

## নিরাপত্তা

নিরাপত্তা নীতি এবং দুর্বলতা রিপোর্ট করার জন্য [SECURITY.md](../../../SECURITY.md) দেখুন।

## অবদান রাখা

অবদান স্বাগত! অনুগ্রহ করে নিঃসংকোচে একটি Pull Request জমা দিন।
