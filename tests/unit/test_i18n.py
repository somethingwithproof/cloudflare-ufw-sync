# SPDX-FileCopyrightText: 2026 Thomas Vincent <thomasvincent@gmail.com>
# SPDX-License-Identifier: MIT

"""Tests for 20-locale i18n support in cloudflare-ufw-sync."""

import re

import pytest

from cloudflare_ufw_sync.cli import main, parse_args
from cloudflare_ufw_sync.i18n import (
    DEFAULT_LOCALE,
    SUPPORTED_LOCALES,
    detect_locale,
    get_locale,
    load_catalog,
    normalize_locale,
    set_locale,
    t,
)

PLACEHOLDER_RE = re.compile(r"\{[a-zA-Z0-9_]+\}")


@pytest.fixture(autouse=True)
def _reset_locale(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("LC_ALL", "LC_MESSAGES", "LANG"):
        monkeypatch.delenv(var, raising=False)
    set_locale(None)
    yield
    set_locale(None)


def test_all_20_locales_load_with_key_and_placeholder_parity() -> None:
    assert len(SUPPORTED_LOCALES) == 20
    en = load_catalog(DEFAULT_LOCALE)
    assert len(en) > 0
    for locale in SUPPORTED_LOCALES:
        catalog = load_catalog(locale)
        assert set(catalog.keys()) == set(en.keys()), locale
        for key, en_val in en.items():
            assert catalog[key].strip(), (locale, key)
            assert sorted(PLACEHOLDER_RE.findall(catalog[key])) == sorted(
                PLACEHOLDER_RE.findall(en_val)
            ), (locale, key)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, "en"),
        ("", "en"),
        ("C", "en"),
        ("POSIX", "en"),
        ("de_DE.UTF-8", "de"),
        ("zh_TW", "zh-TW"),
        ("zh_HK", "zh-TW"),
        ("zh-Hant-TW", "zh-TW"),
        ("zh_CN.UTF-8", "zh-CN"),
        ("zh", "zh-CN"),
        ("pt_BR.UTF-8", "pt-BR"),
        ("pt", "pt-BR"),
        ("xx_YY", "en"),
    ],
)
def test_normalize_locale(raw: str | None, expected: str) -> None:
    assert normalize_locale(raw) == expected


def test_env_precedence_and_override(monkeypatch: pytest.MonkeyPatch) -> None:
    assert detect_locale() == "en"
    monkeypatch.setenv("LANG", "es_ES.UTF-8")
    assert detect_locale() == "es"
    monkeypatch.setenv("LC_MESSAGES", "fr_FR.UTF-8")
    assert detect_locale() == "fr"
    monkeypatch.setenv("LC_ALL", "de_DE.UTF-8")
    assert detect_locale() == "de"
    assert detect_locale("it") == "it"

    assert set_locale("nl") == "nl"
    assert get_locale() == "nl"
    assert set_locale(None) == "de"
    assert get_locale() == "de"


def test_cli_lang_flag_and_default_english(capsys: pytest.CaptureFixture[str]) -> None:
    assert (
        t("cli.no_command") == "No command specified. Use --help for usage information."
    )
    assert t("missing.key") == "missing.key"

    assert main(["--lang", "de"]) == 1
    assert t("cli.no_command", locale="de") in capsys.readouterr().out

    ns = parse_args(["--lang=ja", "status"])
    assert ns.lang == "ja"
    assert get_locale() == "ja"
