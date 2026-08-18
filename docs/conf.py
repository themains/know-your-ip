"""Sphinx configuration — fleet standard via py-canon."""

from py_canon.sphinx import configure

configure(
    globals(),
    # Docstring examples use the public API; expose it once for the doctest
    # builder instead of repeating imports in every example.
    doctest_global_setup="from know_your_ip import *  # noqa: F403",
)
