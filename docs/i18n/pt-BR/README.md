# Cloudflare UFW Sync

[![Tests](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/somethingwithproof/cloudflare-ufw-sync/actions/workflows/tests.yml)
[![Quality Gate](https://sonarcloud.io/api/project_badges/measure?project=somethingwithproof_cloudflare-ufw-sync&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=somethingwithproof_cloudflare-ufw-sync)
[![Release](https://img.shields.io/github/v/release/somethingwithproof/cloudflare-ufw-sync)](https://github.com/somethingwithproof/cloudflare-ufw-sync/releases)
[![Python](https://img.shields.io/python/required-version-toml?tomlFilePath=https://raw.githubusercontent.com/somethingwithproof/cloudflare-ufw-sync/main/pyproject.toml)](../../../pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-blue)](../../../LICENSE)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/somethingwithproof/cloudflare-ufw-sync/badge)](https://scorecard.dev/viewer/?uri=github.com/somethingwithproof/cloudflare-ufw-sync)

**Languages:** [English](../../../README.md) · [Deutsch](../de/README.md) · [Español](../es/README.md) · [Français](../fr/README.md) · [Italiano](../it/README.md) · **Português (BR)** · [Nederlands](../nl/README.md) · [Русский](../ru/README.md) · [Українська](../uk/README.md) · [日本語](../ja/README.md) · [한국어](../ko/README.md) · [简体中文](../zh-CN/README.md) · [繁體中文](../zh-TW/README.md) · [العربية](../ar/README.md) · [हिन्दी](../hi/README.md) · [Polski](../pl/README.md) · [Türkçe](../tr/README.md) · [Svenska](../sv/README.md) · [Tiếng Việt](../vi/README.md) · [Bahasa Indonesia](../id/README.md)

<details><summary>More languages (25 African &amp; Asian locales)</summary>

[Afrikaans](../af-ZA/README.md) · [አማርኛ](../am-ET/README.md) · [العربية (مصر)](../ar-EG/README.md) · [العربية (المغرب)](../ar-MA/README.md) · [বাংলা](../bn/README.md) · [فارسی](../fa/README.md) · [Filipino](../fil/README.md) · [Français (Maroc)](../fr-MA/README.md) · [Français (Sénégal)](../fr-SN/README.md) · [Hausa](../ha-NG/README.md) · [עברית](../he/README.md) · [Igbo](../ig-NG/README.md) · [Malagasy](../mg-MG/README.md) · [मराठी](../mr/README.md) · [Bahasa Melayu](../ms/README.md) · [Kinyarwanda](../rw-RW/README.md) · [Soomaali](../so-SO/README.md) · [Kiswahili](../sw-KE/README.md) · [தமிழ்](../ta/README.md) · [తెలుగు](../te/README.md) · [ไทย](../th/README.md) · [اردو](../ur/README.md) · [isiXhosa](../xh-ZA/README.md) · [Yorùbá](../yo-NG/README.md) · [isiZulu](../zu-ZA/README.md)

</details>

Sincronização de IPs da Cloudflare para o UFW.

## Visão geral

O `cloudflare-ufw-sync` sincroniza os intervalos de IP da Cloudflare com as regras do seu UFW (Uncomplicated Firewall). O sincronizador gerencia suas regras configuradas do UFW; restringir o acesso à origem também depende da política padrão e de quaisquer outras regras de permissão. A sincronização por si só não garante que o acesso direto à origem esteja bloqueado.

## Arquitetura

![Diagrama de Arquitetura](../../../architecture.png)

## Funcionalidades

- 🔄 Sincronização automática dos intervalos de IP da Cloudflare com as regras do UFW
- 🔒 Gerenciamento seguro das regras do UFW com tratamento adequado de permissões
- 🛠️ Suporte a intervalos de endereços IPv4 e IPv6
- 🔍 Registro detalhado em log para auditoria e solução de problemas
- 🔧 Configuração personalizável
- 🧪 Suíte de testes

## Instalação

### A partir do código-fonte

```bash
git clone https://github.com/somethingwithproof/cloudflare-ufw-sync.git
cd cloudflare-ufw-sync
pip install .
```

## Configuração

Crie um arquivo de configuração em `/etc/cloudflare-ufw-sync/config.yml` ou `~/.config/cloudflare-ufw-sync/config.yml`:

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

## Uso

### Linha de comando

```bash
# Run a sync operation
cloudflare-ufw-sync sync

# Run in daemon mode
cloudflare-ufw-sync daemon

# View current status
cloudflare-ufw-sync status
```

### Como serviço

Um arquivo de serviço systemd é fornecido para executar a sincronização como um serviço:

```bash
sudo cp scripts/cloudflare-ufw-sync.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable cloudflare-ufw-sync
sudo systemctl start cloudflare-ufw-sync
```

## Localização

A ajuda da CLI, os resumos de status e as mensagens operacionais oferecem suporte a 45 idiomas (`en`, `de`, `es`, `fr`, `it`, `pt-BR`, `nl`, `ru`, `uk`, `ja`, `ko`, `zh-CN`, `zh-TW`, `ar`, `hi`, `pl`, `tr`, `sv`, `vi`, `id`, `af-ZA`, `am-ET`, `ar-EG`, `ar-MA`, `fr-MA`, `fr-SN`, `ha-NG`, `ig-NG`, `mg-MG`, `rw-RW`, `so-SO`, `sw-KE`, `xh-ZA`, `yo-NG`, `zu-ZA`, `bn`, `fa`, `he`, `mr`, `ta`, `te`, `th`, `ur`, `ms`, `fil`) sem dependências extras. A resolução verifica `--lang`, depois `LC_ALL`, `LC_MESSAGES` e `LANG`, recorrendo a `en` como padrão.

```bash
cloudflare-ufw-sync --lang de status
LANG=fr_FR.UTF-8 cloudflare-ufw-sync --help
```

## Desenvolvimento

### Testes com Docker

Se você preferir um ambiente isolado, pode compilar e executar a suíte de testes inteiramente no Docker.

```bash
# Build the dev image (includes dev dependencies and package in editable mode)
docker build -t cloudflare-ufw-sync:dev .

# Run tests with pytest (quiet mode, stop on first failure)
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q --maxfail=1 --disable-warnings
```

Esta é exatamente a configuração usada na CI e pelos mantenedores ao fazer verificações rápidas das alterações localmente.

### Alvos do Make

Por conveniência, alguns alvos do Make espelham o fluxo de trabalho do Docker:

```bash
# Build the dev image
make docker-build

# Run the test suite inside the container
make docker-test

# Run tox (lint + mypy per tox.ini) inside the container
make docker-tox
```

### Configuração do ambiente

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

### Testes e linting com Tox

O projeto inclui um arquivo `tox.ini` que configura ambientes para testes, linting e verificação de tipos. Isso permite executar localmente as mesmas verificações realizadas no pipeline de CI antes de enviar seus commits.

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

### Testes manuais

Se preferir executar os testes e o linting manualmente:

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

## Licença

Este projeto é licenciado sob a Licença MIT - consulte o arquivo [LICENSE](../../../LICENSE) para mais detalhes.

## Segurança

Consulte [SECURITY.md](../../../SECURITY.md) para ver a política de segurança e como relatar vulnerabilidades.

## Contribuição

Contribuições são bem-vindas! Sinta-se à vontade para enviar um Pull Request.
