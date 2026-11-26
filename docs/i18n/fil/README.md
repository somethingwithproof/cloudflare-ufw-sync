# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](./pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · **Filipino** · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Pag-sync ng IP ng Cloudflare para sa UFW.

## Pangkalahatang-ideya

Sini-sync ng `cloudflare-ufw-sync` ang mga IP range ng Cloudflare sa iyong mga panuntunan sa UFW (Uncomplicated Firewall). Pinamamahalaan ng synchronizer ang mga naka-configure na panuntunan nito sa UFW; nakadepende rin ang paghigpit sa origin access sa default policy at sa anumang iba pang mga panuntunan sa pagpapahintulot. Ang pag-sync lamang ay hindi nagpapatunay na naka-block ang direktang access sa origin.

## Arkitektura

![Diagram ng Arkitektura](../../../architecture.png)

## Mga Tampok

- 🔄 Awtomatikong pag-sync ng mga IP range ng Cloudflare sa mga panuntunan sa UFW
- 🔒 Ligtas na pinamamahalaan ang mga panuntunan sa UFW na may wastong pangangasiwa ng pahintulot
- 🛠️ Sinusuportahan ang parehong mga IPv4 at IPv6 address range
- 🔍 Detalyadong pag-log para sa audit at pag-troubleshoot
- 🔧 Nako-customize na configuration
- 🧪 Test suite

## Pag-install

### Mula sa Source

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Configuration

Gumawa ng configuration file sa `/etc/cloudflare-ufw-sync/config.yml` o `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Paggamit

### Command Line

```bash
# Run a sync operation
sudo cloudflare-ufw-sync sync

# Run in daemon mode
sudo cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### Bilang isang Serbisyo

May ibinibigay na systemd service file upang patakbuhin ang pag-sync bilang isang serbisyo:

```bash
sudo install -d -m 0755 /var/log/cloudflare-ufw-sync
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Localization

Sinusuportahan ng tulong sa CLI, mga buod ng status, at mga mensahe sa operasyon ang 45 locale (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) nang walang dagdag na dependency. Sinusuri ng pagresolba ang `--lang`, pagkatapos ay `LC_ALL`, `LC_MESSAGES`, at `LANG`, at bumabalik sa `en`.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Pag-develop

### Pag-test gamit ang Docker

Kung mas gusto mo ang isang nakahiwalay na environment, maaari mong i-build at patakbuhin ang buong test suite sa Docker.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Ito mismo ang setup na ginagamit sa CI at ng mga maintainer kapag nagsasagawa ng lokal na sanity-check sa mga pagbabago.

### Mga Make target

Para sa kaginhawahan, may ilang make target na sumasalamin sa Docker workflow:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Pag-setup

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

### Pag-test at Pag-lint gamit ang Tox

May kasamang `tox.ini` file ang proyekto na nagse-setup ng mga environment para sa pag-test, pag-lint, at type checking. Pinapayagan ka nitong patakbuhin sa lokal ang parehong mga pagsusuri na isinasagawa sa CI pipeline bago i-commit ang iyong mga pagbabago.

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

### Manu-manong Pag-test

Kung mas gusto mong patakbuhin nang manu-mano ang mga test at pag-lint:

```bash
# Run tests
pytest

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src
```

## Lisensya

Ang proyektong ito ay lisensyado sa ilalim ng MIT License - tingnan ang [LICENSE](../../../LICENSE) file para sa mga detalye.

## Seguridad

Tingnan ang [SECURITY.md](../../../SECURITY.md) para sa patakaran sa seguridad at pag-uulat ng mga kahinaan.

## Pag-ambag

Malugod na tinatanggap ang mga kontribusyon! Huwag mag-atubiling magsumite ng Pull Request.
