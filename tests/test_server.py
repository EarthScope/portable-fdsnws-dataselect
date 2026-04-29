"""
Unit tests for server configuration helpers.
"""

from __future__ import annotations

from configparser import ConfigParser

import pytest

from portable_fdsnws_dataselect.server import _get_int

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cfg(section: str, key: str, value: str) -> ConfigParser:
    config = ConfigParser()
    config.add_section(section)
    config.set(section, key, value)
    return config


# ---------------------------------------------------------------------------
# _get_int
# ---------------------------------------------------------------------------

def test_get_int_returns_default_when_missing():
    config = ConfigParser()
    config.add_section("server")
    assert _get_int(config, "server", "port", 80) == 80


def test_get_int_parses_valid_integer():
    assert _get_int(_cfg("server", "port", "8080"), "server", "port", 80) == 8080


def test_get_int_parses_zero():
    assert _get_int(_cfg("server", "request_limit", "0"), "server", "request_limit", 0) == 0


def test_get_int_non_integer_exits():
    with pytest.raises(SystemExit):
        _get_int(_cfg("server", "port", "abc"), "server", "port", 80)


def test_get_int_float_string_exits():
    with pytest.raises(SystemExit):
        _get_int(_cfg("server", "port", "8.5"), "server", "port", 80)


def test_get_int_min_val_ok_at_boundary():
    assert _get_int(_cfg("server", "port", "1"), "server", "port", 80, min_val=1) == 1


def test_get_int_min_val_violation_exits():
    with pytest.raises(SystemExit):
        _get_int(_cfg("server", "port", "0"), "server", "port", 80, min_val=1)


def test_get_int_min_val_negative_exits():
    with pytest.raises(SystemExit):
        _get_int(_cfg("server", "request_limit", "-1"), "server", "request_limit", 0, min_val=0)


def test_get_int_max_exclusive_boundary_ok():
    """With max_exclusive=True and min_val=1, val=1 must pass (val > 0)."""
    assert (
        _get_int(_cfg("server", "port", "1"), "server", "port", 80, min_val=1, max_exclusive=True)
        == 1
    )


def test_get_int_max_exclusive_zero_exits():
    """With max_exclusive=True and min_val=1, val=0 must exit (0 <= 0)."""
    with pytest.raises(SystemExit):
        _get_int(
            _cfg("server", "port", "0"), "server", "port", 80, min_val=1, max_exclusive=True
        )


def test_get_int_missing_section_key():
    """An entirely absent section should use the default."""
    config = ConfigParser()
    assert _get_int(config, "server", "port", 9999) == 9999
