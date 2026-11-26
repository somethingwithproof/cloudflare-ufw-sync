# مزامنة Cloudflare مع UFW

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · **العربية (المغرب)** · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

مزامنة عناوين IP ديال Cloudflare مع UFW.

## نظرة عامة

`cloudflare-ufw-sync` كيدير مزامنة لنطاقات IP ديال Cloudflare مع قواعد UFW (Uncomplicated Firewall) ديالك. المزامن كيتحكم فقواعد UFW اللي مريكلين فيه؛ تقييد الوصول المباشر للسيرفر الأصلي (origin) كيعتمد حتى هو على السياسة الافتراضية وأي قواعد سماح أخرى. المزامنة بوحدها ما كتبتش باللي الوصول المباشر للأصل مسدود.

## البنية الهندسية

![مخطط البنية الهندسية](../../../architecture.png)

## المميزات

- 🔄 مزامنة أوتوماتيكية لنطاقات IP ديال Cloudflare مع قواعد UFW
- 🔒 تدبير آمن لقواعد UFW مع التعامل الصحيح مع الصلاحيات
- 🛠️ كيدعم نطاقات العناوين IPv4 وIPv6 بجوج
- 🔍 تسجيل مفصل للتدقيق وحل المشاكل
- 🔧 إعدادات قابلة للتخصيص
- 🧪 مجموعة اختبارات

## التثبيت

### من الكود المصدري

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## الإعدادات

صاوب ملف إعدادات فـ `/etc/cloudflare-ufw-sync/config.yml` ولا `~/.config/cloudflare-ufw-sync/config.yml`:

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

## الاستعمال

### سطر الأوامر

```bash
# Run a sync operation
sudo cloudflare-ufw-sync sync

# Run in daemon mode
sudo cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### كخدمة فالنظام

كاين ملف خدمة systemd واجد باش تشغل المزامنة كخدمة:

```bash
sudo install -d -m 0755 /var/log/cloudflare-ufw-sync
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## التوطين واللغات

مساعدة سطر الأوامر، ملخصات الحالة، والرسائل التشغيلية كيدعمو 45 لغة محلية (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) بلا حتى شي اعتماديات زائدة. اختيار اللغة كيقلب فـ `--lang`، من بعد فـ `LC_ALL`، و`LC_MESSAGES`، و`LANG`، وكيرجع لـ `en` إلا ما لقاش.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## التطوير

### الاختبار بـ Docker

إلا كنتي كتفضل بيئة معزولة، تقدر تبني وتشغل مجموعة الاختبارات كاملة داخل Docker.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

هادي هي بالضبط نفس التهيئة اللي كتستعمل فـ CI وعند المشرفين فاش كيتأكدو من التغييرات محليا.

### أهداف Make

باش نسهلو الخدمة، كاينين شي أهداف make كيعكسو نفس الـ workflow ديال Docker:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### الإعداد

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

### الاختبار والتدقيق بـ Tox

المشروع فيه ملف `tox.ini` اللي كيوجد بيئات للاختبار، تدقيق الكود (linting)، وفحص الأنواع (type checking). هاد الشي كيخليك تدوز نفس الفحوصات محليا اللي كيدوزو فـ CI pipeline قبل ما دير commit للتغييرات ديالك.

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

### الاختبار اليدوي

إلا كنتي كتفضل تشغل الاختبارات وتدقيق الكود بيديك:

```bash
# Run tests
pytest

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src
```

## الرخصة

هاد المشروع مرخص تحت رخصة MIT. شوف ملف [LICENSE](../../../LICENSE) للتفاصيل.

## الأمان

شوف [SECURITY.md](../../../SECURITY.md) لسياسة الأمان وكيفاش تبلغ على الثغرات.

## المساهمة

المساهمات مرحب بيها! ما تترددش تصيفط Pull Request.
