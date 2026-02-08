# CLAUDE.md

Automated Cloudflare IP range synchronization for UFW firewall rules.

## Stack
- Python 3.8+

## Lint & Test
```bash
# Run tests
pytest

# Linting
black .
isort .
flake8

# Type checking
mypy src

# Full tox suite
tox
```

## Docker Test
```bash
docker build -t cloudflare-ufw-sync:dev .
docker run --rm -t --entrypoint pytest cloudflare-ufw-sync:dev -q
```
