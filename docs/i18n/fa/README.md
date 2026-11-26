# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · **فارسی** · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

همگام‌سازی IPهای Cloudflare برای UFW.

## نمای کلی

`cloudflare-ufw-sync` بازه‌های IP مربوط به Cloudflare را با قوانین UFW (Uncomplicated Firewall) شما همگام‌سازی می‌کند. همگام‌ساز قوانین پیکربندی‌شده UFW خود را مدیریت می‌کند؛ محدود کردن دسترسی به مبدا (origin) به سیاست پیش‌فرض و سایر قوانین مجاز (allow) نیز بستگی دارد. همگام‌سازی به‌تنهایی مسدود بودن دسترسی مستقیم به مبدا را تضمین نمی‌کند.

## معماری

![نمودار معماری](../../../architecture.png)

## ویژگی‌ها

- 🔄 همگام‌سازی خودکار بازه‌های IP کلودفلر با قوانین UFW
- 🔒 مدیریت امن قوانین UFW با رسیدگی صحیح به مجوزها
- 🛠️ پشتیبانی از هر دو بازه نشانی IPv4 و IPv6
- 🔍 ثبت گزارش (لاگ) دقیق برای ممیزی و عیب‌یابی
- 🔧 پیکربندی قابل سفارشی‌سازی
- 🧪 مجموعه آزمون

## نصب

### از سورس

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## پیکربندی

یک فایل پیکربندی در مسیر `/etc/cloudflare-ufw-sync/config.yml` یا `~/.config/cloudflare-ufw-sync/config.yml` بسازید:

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

## نحوه استفاده

### خط فرمان

```bash
# Run a sync operation
sudo cloudflare-ufw-sync sync

# Run in daemon mode
sudo cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### به‌عنوان سرویس

یک فایل سرویس systemd برای اجرای همگام‌سازی به‌صورت سرویس ارائه شده است:

```bash
sudo install -d -m 0755 /var/log/cloudflare-ufw-sync
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## بومی‌سازی

راهنمای خط فرمان، خلاصه وضعیت‌ها و پیام‌های عملیاتی از ۴۵ زبان و منطقه (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) بدون نیاز به وابستگی اضافه پشتیبانی می‌کنند. تشخیص زبان ابتدا `--lang` و سپس `LC_ALL`، `LC_MESSAGES` و `LANG` را بررسی می‌کند و در نهایت به `en` بازمی‌گردد.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## توسعه

### آزمون با Docker

اگر محیط ایزوله را ترجیح می‌دهید، می‌توانید مجموعه آزمون را به‌طور کامل درون Docker بسازید و اجرا کنید.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

این دقیقاً همان چیدمانی است که در CI و توسط نگه‌دارندگان پروژه برای بررسی سریع تغییرات به‌صورت محلی استفاده می‌شود.

### هدف‌های Make

برای راحتی بیشتر، چند هدف make وجود دارد که گردش کار Docker را بازتاب می‌دهند:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### راه‌اندازی

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

### آزمون و لینت با Tox

این پروژه شامل یک فایل `tox.ini` است که محیط‌هایی را برای آزمون، لینت کردن و بررسی نوع‌ها (type checking) تنظیم می‌کند. این کار به شما امکان می‌دهد پیش از کامیت کردن تغییرات، همان بررسی‌هایی را که در پایپ‌لاین CI انجام می‌شود به‌صورت محلی اجرا کنید.

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

### آزمون دستی

اگر ترجیح می‌دهید آزمون‌ها و لینت را به‌صورت دستی اجرا کنید:

```bash
# Run tests
pytest

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src
```

## مجوز

این پروژه تحت مجوز MIT منتشر شده است؛ برای جزئیات بیشتر فایل [LICENSE](../../../LICENSE) را ببینید.

## امنیت

برای سیاست امنیتی و گزارش آسیب‌پذیری‌ها، [SECURITY.md](../../../SECURITY.md) را ببینید.

## مشارکت

از مشارکت‌های شما استقبال می‌شود! لطفاً با خیال راحت یک Pull Request ارسال کنید.
