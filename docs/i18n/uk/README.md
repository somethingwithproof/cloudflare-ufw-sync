# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · **Українська** · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Синхронізація IP-адрес Cloudflare для UFW.

## Огляд

`cloudflare-ufw-sync` синхронізує діапазони IP-адрес Cloudflare із правилами UFW (Uncomplicated Firewall). Синхронізатор керує лише налаштованими правилами UFW; обмеження доступу до оригінального сервера також залежить від політики за замовчуванням та будь-яких інших правил дозволу. Сама лише синхронізація не гарантує, що прямий доступ до оригінального сервера заблоковано.

## Архітектура

![Діаграма архітектури](../../../architecture.png)

## Можливості

- 🔄 Автоматична синхронізація діапазонів IP-адрес Cloudflare із правилами UFW
- 🔒 Безпечне керування правилами UFW із належною обробкою прав доступу
- 🛠️ Підтримка діапазонів адрес як IPv4, так і IPv6
- 🔍 Детальне журналювання для аудиту та усунення несправностей
- 🔧 Гнучка конфігурація
- 🧪 Набір тестів

## Встановлення

### Із вихідного коду

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Конфігурація

Створіть файл конфігурації за шляхом `/etc/cloudflare-ufw-sync/config.yml` або `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Використання

### Командний рядок

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### Як сервіс

Для запуску синхронізації у вигляді служби надається файл сервісу systemd:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Локалізація

Довідка CLI, зведення статусу та операційні повідомлення підтримують 45 мов (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) без жодних додаткових залежностей. Визначення локалі перевіряє `--lang`, далі `LC_ALL`, `LC_MESSAGES` і `LANG`, із переходом до `en` за замовчуванням.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Розробка

### Тестування за допомогою Docker

Якщо ви віддаєте перевагу ізольованому середовищу, ви можете зібрати та запустити набір тестів повністю в Docker.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Саме таке налаштування використовується в CI та мейнтейнерами для локальної перевірки працездатності змін.

### Цілі Make

Для зручності кілька цілей make дублюють робочий процес Docker:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Налаштування середовища

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

### Тестування та лінтинг за допомогою Tox

Проєкт містить файл `tox.ini`, який налаштовує середовища для тестування, лінтингу та перевірки типів. Це дає змогу локально запускати перед комітом ті самі перевірки, що виконуються в конвеєрі CI.

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

### Ручне тестування

Якщо ви віддаєте перевагу ручному запуску тестів і лінтингу:

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

## Ліцензія

Цей проєкт розповсюджується за ліцензією MIT - докладніше дивіться у файлі [LICENSE](../../../LICENSE).

## Безпека

Дивіться [SECURITY.md](../../../SECURITY.md), щоб ознайомитися з політикою безпеки та порядком повідомлення про вразливості.

## Участь у розробці

Внесок у розвиток проєкту вітається! Будь ласка, надсилайте Pull Request.
