# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](./pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](./LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · [Português (BR)](../pt-BR/README.md) · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · **简体中文** · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

用于 UFW 的 Cloudflare IP 同步工具。

## 概述

`cloudflare-ufw-sync` 将 Cloudflare 的 IP 地址段同步到你的 UFW（Uncomplicated Firewall）规则中。该同步器仅管理其配置范围内的 UFW 规则；限制源站访问还取决于默认策略以及其他放行规则。仅靠同步本身并不能证明对源站的直接访问已被阻断。

## 架构

![架构图](../../../architecture.png)

## 功能特性

- 🔄 自动将 Cloudflare IP 地址段同步至 UFW 规则
- 🔒 通过规范的权限控制安全管理 UFW 规则
- 🛠️ 同时支持 IPv4 和 IPv6 地址段
- 🔍 详尽的日志记录，便于审计和故障排查
- 🔧 支持自定义配置
- 🧪 完整的测试套件

## 安装

### 从源码安装

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## 配置

在 `/etc/cloudflare-ufw-sync/config.yml` 或 `~/.config/cloudflare-ufw-sync/config.yml` 创建配置文件：

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

## 用法

### 命令行

```bash
# Run a sync operation
sudo cloudflare-ufw-sync sync

# Run in daemon mode
sudo cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### 作为系统服务运行

项目提供了 systemd 服务文件，可将同步任务作为后台服务运行：

```bash
sudo install -d -m 0755 /var/log/cloudflare-ufw-sync
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## 本地化

CLI 帮助、状态摘要和操作消息支持 45 种语言区域（`en`、`de`、`es`、`fr`、`it`、`pt-BR`、`nl`、`ru`、`uk`、`ja`、`ko`、`zh-CN`、`zh-TW`、`ar`、`hi`、`pl`、`tr`、`sv`、`vi`、`id`、`af-ZA`、`am-ET`、`ar-EG`、`ar-MA`、`fr-MA`、`fr-SN`、`ha-NG`、`ig-NG`、`mg-MG`、`rw-RW`、`so-SO`、`sw-KE`、`xh-ZA`、`yo-NG`、`zu-ZA`、`bn`、`fa`、`he`、`mr`、`ta`、`te`、`th`、`ur`、`ms`、`fil`），无需额外依赖。语言区域解析依次检查 `--lang`、`LC_ALL`、`LC_MESSAGES` 和 `LANG`，最后回退到 `en`。

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## 开发

### 使用 Docker 测试

如果你倾向于使用隔离环境，可以完全在 Docker 中构建并运行测试套件。

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

这与 CI 中使用的配置以及维护者在本地进行健全性检查时的环境完全一致。

### Make 目标

为方便使用，项目提供了一些与 Docker 工作流对应的 make 目标：

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### 环境准备

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

### 使用 Tox 进行测试和代码检查

项目包含一个 `tox.ini` 文件，用于配置测试、代码风格检查（linting）和类型检查环境。这使你在提交变更前，可以在本地运行与 CI 流水线相同的检查。

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

### 手动测试

如果你希望手动运行测试和代码检查：

```bash
# Run tests
pytest

# Run linting
ruff check .
ruff format --check .

# Run type checking
mypy src
```

## 许可证

本项目采用 MIT 许可证授权，详见 [LICENSE](../../../LICENSE) 文件。

## 安全

有关安全策略和漏洞报告方式，请参阅 [SECURITY.md](../../../SECURITY.md)。

## 贡献指南

欢迎贡献代码！请随时提交 Pull Request。
