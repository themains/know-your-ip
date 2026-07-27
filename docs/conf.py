"""Sphinx configuration — fleet standard via py-canon."""

from py_canon.sphinx import configure

configure(
    globals(),
    # Docstring examples are written against the package's public API, so make
    # it available to the doctest builder without repeating imports in every
    # docstring.
    doctest_global_setup="from know_your_ip import *  # noqa: F403",
)
