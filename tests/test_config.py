"""Tests for configuration loading."""

import pytest
import tempfile
from pathlib import Path
from know_your_ip.know_your_ip import load_config


class TestLoadConfig:
    """Test the load_config function."""
    
    def test_load_default_config(self):
        """Test loading default configuration."""
        # This should not raise an error if the default config file exists
        args = load_config()
        assert hasattr(args, 'maxmind_enable')
        assert hasattr(args, 'output_columns')
        
    def test_load_nonexistent_config(self):
        """Test loading non-existent configuration file."""
        with pytest.raises(Exception):  # ConfigParser will raise an exception
            load_config("/nonexistent/config.cfg")