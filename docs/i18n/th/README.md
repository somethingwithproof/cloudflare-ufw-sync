# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · **ไทย** · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

เครื่องมือซิงโครไนซ์ IP ของ Cloudflare สำหรับ UFW

## ภาพรวม

`cloudflare-ufw-sync` ทำหน้าที่ซิงโครไนซ์ช่วง IP ของ Cloudflare เข้ากับกฎของ UFW (Uncomplicated Firewall) ตัวซิงโครไนเซอร์จะจัดการเฉพาะกฎ UFW ที่กำหนดค่าไว้เท่านั้น ส่วนการจำกัดการเข้าถึงเซิร์ฟเวอร์ต้นทางยังขึ้นอยู่กับนโยบายเริ่มต้นและกฎการอนุญาตอื่นๆ ด้วย การซิงโครไนซ์เพียงอย่างเดียวไม่ได้รับประกันว่าการเข้าถึงต้นทางโดยตรงจะถูกบล็อกทั้งหมด

## สถาปัตยกรรม

![แผนภาพสถาปัตยกรรม](../../../architecture.png)

## คุณสมบัติ

- 🔄 ซิงโครไนซ์ช่วง IP ของ Cloudflare กับกฎ UFW โดยอัตโนมัติ
- 🔒 จัดการกฎ UFW อย่างปลอดภัยพร้อมการตรวจสอบสิทธิ์ที่เหมาะสม
- 🛠️ รองรับช่วงแอดเดรสทั้ง IPv4 และ IPv6
- 🔍 บันทึก log อย่างละเอียดเพื่อการตรวจสอบและแก้ไขปัญหา
- 🔧 ปรับแต่งการตั้งค่าได้ตามต้องการ
- 🧪 มีชุดการทดสอบครบถ้วน

## การติดตั้ง

### จากซอร์สโค้ด

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## การตั้งค่า

สร้างไฟล์การตั้งค่าที่ `/etc/cloudflare-ufw-sync/config.yml` หรือ `~/.config/cloudflare-ufw-sync/config.yml`:

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

## การใช้งาน

### บรรทัดคำสั่ง

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### การรันเป็น Service

มีไฟล์ systemd service เตรียมไว้ให้เพื่อรันการซิงโครไนซ์เป็นเซอร์วิสเบื้องหลัง:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## การรองรับหลายภาษา (Localization)

ข้อความช่วยเหลือของ CLI, สรุปสถานะ และข้อความการทำงานรองรับ 45 ภาษา (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) โดยไม่ต้องติดตั้งแพ็กเกจเพิ่มเติม การตรวจสอบภาษาจะเช็ก `--lang` ตามด้วย `LC_ALL`, `LC_MESSAGES` และ `LANG` และใช้ `en` เป็นค่าเริ่มต้น

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## การพัฒนา

### การทดสอบด้วย Docker

หากต้องการสภาพแวดล้อมที่แยกอิสระ คุณสามารถบิลด์และรันชุดการทดสอบทั้งหมดภายใน Docker ได้

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

นี่คือสภาพแวดล้อมเดียวกับที่ใช้ใน CI และที่ผู้ดูแลโปรเจกต์ใช้ตรวจสอบความเรียบร้อยของการเปลี่ยนแปลงในเครื่อง

### คำสั่ง Make

เพื่อความสะดวก มีคำสั่ง make จำนวนหนึ่งที่จำลองเวิร์กโฟลว์ของ Docker ไว้ให้:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### การตั้งค่าสภาพแวดล้อม

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

### การทดสอบและการตรวจโค้ดด้วย Tox

โปรเจกต์มีไฟล์ `tox.ini` ที่ตั้งค่าสภาพแวดล้อมสำหรับการทดสอบ การตรวจรูปแบบโค้ด (linting) และการตรวจสอบชนิดข้อมูล (type checking) ช่วยให้คุณรันการตรวจสอบแบบเดียวกับในไปป์ไลน์ CI บนเครื่องก่อนคอมมิตได้

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

### การทดสอบด้วยตนเอง

หากต้องการรันการทดสอบและการตรวจโค้ดด้วยตนเอง:

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

## สัญญาอนุญาต

โปรเจกต์นี้ใช้สัญญาอนุญาต MIT License ดูรายละเอียดได้ในไฟล์ [LICENSE](../../../LICENSE)

## ความปลอดภัย

ดูนโยบายความปลอดภัยและวิธีการรายงานช่องโหว่ได้ที่ [SECURITY.md](../../../SECURITY.md)

## การมีส่วนร่วม

ยินดีรับการมีส่วนร่วมทุกด้าน สามารถส่ง Pull Request เข้ามาได้เลย
