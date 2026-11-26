# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](./pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · **Tiếng Việt** · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Đồng bộ hóa dải IP Cloudflare cho UFW.

## Tổng quan

`cloudflare-ufw-sync` đồng bộ hóa các dải IP của Cloudflare với quy tắc UFW (Uncomplicated Firewall) của bạn. Công cụ đồng bộ quản lý các quy tắc UFW đã được cấu hình; việc hạn chế truy cập trực tiếp vào máy chủ gốc (origin) còn phụ thuộc vào chính sách mặc định và mọi quy tắc cho phép (allow) khác. Chỉ riêng việc đồng bộ hóa không chứng minh được rằng mọi truy cập trực tiếp vào máy chủ gốc đã bị chặn.

## Kiến trúc

![Sơ đồ kiến trúc](../../../architecture.png)

## Tính năng

- 🔄 Tự động đồng bộ hóa các dải IP của Cloudflare với quy tắc UFW
- 🔒 Quản lý an toàn các quy tắc UFW với cơ chế xử lý quyền phù hợp
- 🛠️ Hỗ trợ cả dải địa chỉ IPv4 và IPv6
- 🔍 Ghi nhật ký chi tiết phục vụ kiểm tra và khắc phục sự cố
- 🔧 Cấu hình có thể tùy chỉnh
- 🧪 Bộ kiểm thử đầy đủ

## Cài đặt

### Từ mã nguồn

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Cấu hình

Tạo tệp cấu hình tại `/etc/cloudflare-ufw-sync/config.yml` hoặc `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Cách sử dụng

### Dòng lệnh

```bash
# Run a sync operation
sudo cloudflare-ufw-sync sync

# Run in daemon mode
sudo cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### Chạy dưới dạng dịch vụ

Tệp dịch vụ systemd được cung cấp sẵn để chạy việc đồng bộ hóa dưới dạng dịch vụ nền:

```bash
sudo install -d -m 0755 /var/log/cloudflare-ufw-sync
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Bản địa hóa

Trợ giúp CLI, tóm tắt trạng thái và các thông báo vận hành hỗ trợ 45 ngôn ngữ/vùng (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) mà không cần thêm phụ thuộc. Thứ tự phân giải kiểm tra `--lang`, sau đó đến `LC_ALL`, `LC_MESSAGES` và `LANG`, rồi dự phòng về `en`.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Phát triển

### Kiểm thử với Docker

Nếu muốn một môi trường cô lập, bạn có thể dựng và chạy toàn bộ bộ kiểm thử trong Docker.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Đây chính là thiết lập được sử dụng trong CI và bởi các nhà phát triển duy trì dự án khi kiểm tra nhanh các thay đổi tại máy cục bộ.

### Các mục tiêu Make

Để thuận tiện, một vài mục tiêu make được cung cấp tương ứng với quy trình Docker:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Thiết lập

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

### Kiểm thử và kiểm tra mã nguồn (Lint) với Tox

Dự án bao gồm tệp `tox.ini` để thiết lập các môi trường cho kiểm thử, lint và kiểm tra kiểu dữ liệu. Điều này cho phép bạn chạy cục bộ các bước kiểm tra tương tự như trong pipeline CI trước khi commit thay đổi.

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

### Kiểm thử thủ công

Nếu bạn muốn chạy kiểm thử và lint theo cách thủ công:

```bash
# Run tests
pytest

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src
```

## Giấy phép

Dự án này được cấp phép theo Giấy phép MIT - xem tệp [LICENSE](../../../LICENSE) để biết thêm chi tiết.

## Bảo mật

Xem [SECURITY.md](../../../SECURITY.md) để biết chính sách bảo mật và cách báo cáo lỗ hổng.

## Đóng góp

Mọi đóng góp đều được hoan nghênh! Đừng ngần ngại gửi Pull Request.
