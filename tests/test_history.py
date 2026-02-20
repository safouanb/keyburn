from __future__ import annotations

import pytest
import typer

from keyburn.cli import _parse_history_arg
from keyburn.history import _parse_diff_hunks


def test_parse_history_arg_all() -> None:
    assert _parse_history_arg("all") is None


def test_parse_history_arg_positive_integer() -> None:
    assert _parse_history_arg("50") == 50


@pytest.mark.parametrize("value", ["0", "-1", "abc"])
def test_parse_history_arg_invalid(value: str) -> None:
    with pytest.raises(typer.BadParameter):
        _parse_history_arg(value)


def test_parse_diff_hunks_extracts_added_lines() -> None:
    diff = """diff --git a/src/app.py b/src/app.py
index 123..456 100644
--- a/src/app.py
+++ b/src/app.py
@@ -1,2 +1,3 @@
 first_line
+secret = "abc123"
 second_line
@@ -10,0 +12,1 @@
+another = "xyz"
"""
    parsed = _parse_diff_hunks(diff)

    assert ("src/app.py", 2, 'secret = "abc123"') in parsed
    assert ("src/app.py", 12, 'another = "xyz"') in parsed

