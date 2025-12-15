"""Tests for utility functions."""

from know_your_ip.know_your_ip import clean_colname, flatten_dict


class TestCleanColname:
    """Test the clean_colname function."""

    def test_basic_cleanup(self):
        """Test basic column name cleanup."""
        assert clean_colname("Test Column") == "test_column"
        assert clean_colname("test-column!") == "test_column_"
        assert clean_colname("123_test") == "_123_test"

    def test_multiple_underscores(self):
        """Test cleanup of multiple consecutive underscores."""
        assert clean_colname("test___column") == "test_column"
        assert clean_colname("test--column!!") == "test_column_"


class TestFlattenDict:
    """Test the flatten_dict function."""

    def test_simple_dict(self):
        """Test flattening of simple nested dictionary."""
        nested = {"a": {"b": 1, "c": 2}}
        expected = {"a_b": 1, "a_c": 2}
        assert flatten_dict(nested) == expected

    def test_empty_dict(self):
        """Test flattening of empty dictionary."""
        assert flatten_dict({}) == {}

    def test_flat_dict(self):
        """Test flattening of already flat dictionary."""
        flat = {"a": 1, "b": 2}
        assert flatten_dict(flat) == flat

    def test_custom_separator(self):
        """Test flattening with custom separator."""
        nested = {"a": {"b": 1}}
        expected = {"a.b": 1}
        assert flatten_dict(nested, separator=".") == expected
