"""Execute the Python examples in the README.

The original README's headline example raised `KeyError` and shipped that way
for a long time, because documentation is the one part of a project nobody
runs. `tests/test_examples.py` checks that example *imports* resolve; this
closes the gap between importing and working.

Blocks containing obvious placeholders (`YOUR_ID`, `"..."`) are skipped: they
are illustrative configuration, not runnable code.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest

README = Path(__file__).parent.parent / "README.md"

PLACEHOLDERS = ("YOUR_ID", "YOUR_KEY", "your_api_key", '"..."', "addresses.csv")


def _python_blocks() -> list[tuple[int, str]]:
    """Extract fenced ```python blocks from the README.

    Returns:
        (line number, source) for each block, so a failure points at the spot
        in the README rather than at an anonymous snippet.
    """
    text = README.read_text()
    blocks = []
    for match in re.finditer(r"```python\n(.*?)```", text, re.DOTALL):
        line = text[: match.start()].count("\n") + 2
        blocks.append((line, match.group(1)))
    return blocks


def _runnable_blocks() -> list[tuple[int, str]]:
    return [
        (line, src)
        for line, src in _python_blocks()
        if not any(p in src for p in PLACEHOLDERS)
    ]


def test_readme_has_python_examples():
    """Guard against the extraction silently matching nothing."""
    assert len(_python_blocks()) >= 5


class TestReadmeBlocks:
    @pytest.mark.parametrize(
        ("line", "source"),
        _python_blocks(),
        ids=[f"line{line}" for line, _ in _python_blocks()],
    )
    def test_block_parses(self, line, source):
        ast.parse(source)

    @pytest.mark.network
    @pytest.mark.parametrize(
        ("line", "source"),
        _runnable_blocks(),
        ids=[f"line{line}" for line, _ in _runnable_blocks()],
    )
    def test_block_runs(self, line, source, tmp_path, monkeypatch):
        """Run the block as written, in a clean directory with no API keys.

        This is the state a new reader is in: fresh install, no accounts, no
        configuration. If a block needs more than that, the README is lying.
        """
        monkeypatch.chdir(tmp_path)
        for name in list(__import__("os").environ):
            if name.startswith("KNOW_YOUR_IP_"):
                monkeypatch.delenv(name, raising=False)

        try:
            # Executing documentation is the entire point of this test.
            exec(  # noqa: S102
                compile(source, f"README.md:{line}", "exec"),
                {"__name__": "__main__"},
            )
        except ImportError as exc:
            # A block demonstrating an optional feature is still correct when
            # the extra is absent - that is what the bare wheel job installs.
            # Anything else is a real failure.
            if "know_your_ip[" not in str(exc):
                raise
            pytest.skip(f"README block needs an optional extra: {exc}")
