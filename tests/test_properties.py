"""Property-based tests, where the invariant is real rather than decorative.

Example-based tests check the cases someone thought of. These check claims that
must hold for all input: that validation agrees with the standard library, that
flattening never loses or collides keys, that column selection never invents
data, and that the cache fingerprint is stable under reordering but sensitive
to values.
"""

from __future__ import annotations

import ipaddress

from hypothesis import given, settings
from hypothesis import strategies as st

from know_your_ip import InvalidIPError, select_columns, validate_ip
from know_your_ip.cache import config_fingerprint
from know_your_ip.core import flatten_dict

# Keep values JSON-ish: these dicts stand in for decoded API responses.
scalars = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(),
    st.text(max_size=20),
    st.floats(allow_nan=False),
)
nested = st.recursive(
    scalars,
    lambda children: st.dictionaries(
        st.text(min_size=1, max_size=8).filter(lambda k: "." not in k),
        children,
        max_size=4,
    ),
    max_leaves=12,
)


class TestValidateIP:
    @given(st.ip_addresses())
    def test_accepts_everything_the_stdlib_accepts(self, address):
        assert validate_ip(str(address)) == str(address)

    @given(st.ip_addresses())
    def test_is_idempotent(self, address):
        once = validate_ip(str(address))

        assert validate_ip(once) == once

    @given(st.ip_addresses())
    def test_tolerates_surrounding_whitespace(self, address):
        """CSV columns routinely carry stray spaces."""
        assert validate_ip(f"  {address}\t") == str(address)

    @given(st.text(max_size=30))
    @settings(max_examples=200)
    def test_rejects_exactly_what_the_stdlib_rejects(self, text):
        try:
            ipaddress.ip_address(text.strip())
        except ValueError:
            try:
                validate_ip(text)
            except InvalidIPError:
                return
            raise AssertionError(f"accepted {text!r} which ipaddress rejects") from None
        assert validate_ip(text) == str(ipaddress.ip_address(text.strip()))


class TestFlattenDict:
    @given(st.dictionaries(st.text(min_size=1, max_size=8), scalars, max_size=6))
    def test_flat_input_is_unchanged(self, data):
        assert flatten_dict(data) == data

    @given(nested)
    def test_never_returns_a_nested_value(self, data):
        if not isinstance(data, dict):
            return

        assert not any(isinstance(v, dict) for v in flatten_dict(data).values())

    @given(nested)
    def test_preserves_every_leaf(self, data):
        """Flattening must not drop data, only rename it.

        Empty dicts are not leaves: they carry no value, so they contribute no
        column. See test_empty_branches_are_dropped.
        """
        if not isinstance(data, dict):
            return

        def leaves(d):
            for v in d.values():
                if isinstance(v, dict):
                    yield from leaves(v)
                else:
                    yield v

        assert len(list(leaves(data))) == len(flatten_dict(data))

    def test_empty_branches_are_dropped(self):
        """Found by hypothesis, and correct: a provider returning
        ``{"location": {}}`` should produce no location column rather than a
        cell containing an empty dict."""
        assert flatten_dict({"location": {}}) == {}
        assert flatten_dict({"a": 1, "b": {}}) == {"a": 1}

    @given(nested)
    def test_output_keys_are_always_strings(self, data):
        """They become CSV column names."""
        if not isinstance(data, dict):
            return

        assert all(isinstance(k, str) for k in flatten_dict(data, separator="."))


class TestSelectColumns:
    @given(
        st.dictionaries(st.text(min_size=1, max_size=8), scalars, max_size=8),
        st.lists(st.text(min_size=1, max_size=8), max_size=8),
    )
    def test_never_invents_a_key(self, record, columns):
        assert set(select_columns(record, columns)) <= set(record)

    @given(
        st.dictionaries(st.text(min_size=1, max_size=8), scalars, max_size=8),
        st.lists(st.text(min_size=1, max_size=8), max_size=8),
    )
    def test_never_alters_a_value(self, record, columns):
        selected = select_columns(record, columns)

        assert all(selected[k] == record[k] for k in selected)

    @given(st.dictionaries(st.text(min_size=1, max_size=8), scalars, max_size=8))
    def test_selecting_everything_is_identity(self, record):
        assert select_columns(record, list(record)) == record


class TestConfigFingerprint:
    @given(st.dictionaries(st.text(min_size=1, max_size=8), scalars, max_size=6))
    def test_is_deterministic(self, values):
        assert config_fingerprint(values) == config_fingerprint(values)

    @given(
        st.dictionaries(
            st.text(min_size=1, max_size=8), scalars, min_size=2, max_size=6
        )
    )
    def test_is_insensitive_to_key_order(self, values):
        """Otherwise a cache entry would miss purely because a dict was built
        in a different order."""
        reordered = dict(reversed(list(values.items())))

        assert config_fingerprint(values) == config_fingerprint(reordered)

    @given(
        st.dictionaries(
            st.text(min_size=1, max_size=8), st.integers(), min_size=1, max_size=4
        ),
        st.integers(),
    )
    def test_changes_when_a_value_changes(self, values, delta):
        """A settings change must invalidate the cache - a result fetched under
        a 30-day window cannot answer a 365-day question."""
        key = next(iter(values))
        changed = {**values, key: values[key] + delta}

        if changed[key] != values[key]:
            assert config_fingerprint(values) != config_fingerprint(changed)
