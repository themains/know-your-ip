"""Tests that the shipped examples still match the package.

The notebook shipped broken in 0.4.0: it imported three functions removed in
0.3.0, so its first cell raised and nothing ran. `examples/output.csv` carried
columns from providers that no longer existed. Both are advertised in the README
as the way to learn the package, and nothing checked either.

These tests are offline and deterministic - notebooks are JSON, and `ast` covers
the scripts - so drift becomes a failing test rather than something a reader has
to discover.
"""

from __future__ import annotations

import ast
import csv
import importlib
import json
import tomllib
from pathlib import Path

import pytest

from know_your_ip import KnowYourIPConfig
from know_your_ip.providers import REGISTRY

EXAMPLES = Path(__file__).parent.parent / "examples"


def _unresolvable_imports(source: str) -> list[str]:
    """Find names imported from the package that no longer exist.

    Names are resolved against the module they are actually imported from, not
    against the top-level package: examples legitimately import from
    ``know_your_ip.cache`` and ``know_your_ip.providers``.

    Args:
        source: Python source.

    Returns:
        ``module.name`` strings for every import that cannot be resolved.
    """
    missing: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ImportFrom):
            continue
        module = node.module or ""
        if not module.startswith("know_your_ip"):
            continue
        try:
            imported = importlib.import_module(module)
        except ImportError:
            missing.append(f"{module} (module not found)")
            continue
        missing.extend(
            f"{module}.{alias.name}"
            for alias in node.names
            if not hasattr(imported, alias.name)
        )
    return sorted(missing)


def _notebook_source(path: Path) -> str:
    """Concatenate a notebook's code cells into one source string.

    Args:
        path: Notebook path.

    Returns:
        The joined source of every code cell.
    """
    notebook = json.loads(path.read_text())
    return "\n".join(
        "".join(cell.get("source", []))
        for cell in notebook["cells"]
        if cell["cell_type"] == "code"
    )


def _example_scripts() -> list[Path]:
    return sorted(EXAMPLES.glob("*.py"))


def _notebooks() -> list[Path]:
    return sorted(EXAMPLES.glob("*.ipynb"))


class TestExampleImports:
    """Every name an example imports must exist in the package."""

    @pytest.mark.parametrize("script", _example_scripts(), ids=lambda p: p.name)
    def test_script_imports_resolve(self, script):
        missing = _unresolvable_imports(script.read_text())

        assert not missing, (
            f"{script.name} imports names that no longer exist: {missing}"
        )

    @pytest.mark.parametrize("notebook", _notebooks(), ids=lambda p: p.name)
    def test_notebook_imports_resolve(self, notebook):
        """This is the check that fails against the 0.4.0 notebook."""
        missing = _unresolvable_imports(_notebook_source(notebook))

        assert not missing, (
            f"{notebook.name} imports names that no longer exist: {missing}"
        )

    @pytest.mark.parametrize("notebook", _notebooks(), ids=lambda p: p.name)
    def test_notebook_code_parses(self, notebook):
        ast.parse(_notebook_source(notebook))


class TestExampleConfig:
    def test_sample_config_validates(self):
        """It is generated from the models, but a stale committed copy would
        drift silently - which is how the Censys uid/secret block survived."""
        raw = tomllib.loads((EXAMPLES / "know_your_ip.toml").read_text())

        KnowYourIPConfig(**raw)


class TestSampleOutput:
    def test_columns_belong_to_registered_providers(self):
        """Catches a sample output left behind by a removed provider."""
        with (EXAMPLES / "output.csv").open(newline="") as fh:
            header = next(csv.reader(fh))

        known = {p.name for p in REGISTRY.providers} | {"ip", "timezone"}
        unknown = sorted({c.split(".")[0] for c in header if "." in c} - known)

        assert not unknown, f"output.csv has columns from unknown providers: {unknown}"

    def test_has_data_rows(self):
        """A header over empty rows is not a sample."""
        with (EXAMPLES / "output.csv").open(newline="") as fh:
            rows = list(csv.DictReader(fh))

        assert rows
        assert all(any(v for v in row.values()) for row in rows)
