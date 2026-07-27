"""Tests for the command line interface."""

from __future__ import annotations

import csv

import pytest
import responses

from know_your_ip.core import main, read_ip_file

VT_URL_TEMPLATE = "https://www.virustotal.com/api/v3/ip_addresses/{}"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Run in a temp directory with no inherited configuration."""
    for key in list(__import__("os").environ):
        if key.startswith("KNOW_YOUR_IP_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)
    return tmp_path


class TestReadIPFile:
    def test_skips_blanks_and_comments(self, tmp_path):
        path = tmp_path / "ips.txt"
        path.write_text("8.8.8.8\n\n# comment\n1.1.1.1\n")

        assert read_ip_file(path) == ["8.8.8.8", "1.1.1.1"]


class TestMain:
    def test_writes_header_and_rows(self, isolated):
        out = isolated / "out.csv"

        assert main(["8.8.8.8", "-o", str(out)]) == 0

        with out.open(newline="") as fh:
            rows = list(csv.DictReader(fh))

        assert len(rows) == 1
        assert rows[0]["ip"] == "8.8.8.8"

    def test_no_header_flag(self, isolated):
        out = isolated / "out.csv"

        main(["8.8.8.8", "-o", str(out), "--no-header"])

        assert not out.read_text().startswith("ip,")

    def test_invalid_ip_skipped_not_fatal(self, isolated):
        """A malformed address in a large batch must not abort the run."""
        out = isolated / "out.csv"

        assert main(["not-an-ip", "8.8.8.8", "-o", str(out)]) == 0

        with out.open(newline="") as fh:
            assert len(list(csv.DictReader(fh))) == 1

    def test_all_invalid_returns_error(self, isolated):
        assert main(["not-an-ip", "-o", str(isolated / "out.csv")]) == 1

    def test_requires_input(self):
        with pytest.raises(SystemExit):
            main([])

    def test_rejects_zero_concurrency(self):
        with pytest.raises(SystemExit):
            main(["8.8.8.8", "-n", "0"])

    def test_row_range(self, isolated):
        out = isolated / "out.csv"
        ips = isolated / "ips.txt"
        ips.write_text("8.8.8.8\n1.1.1.1\n9.9.9.9\n")

        main(["--file", str(ips), "--from", "1", "--to", "2", "-o", str(out)])

        with out.open(newline="") as fh:
            rows = list(csv.DictReader(fh))

        assert [r["ip"] for r in rows] == ["1.1.1.1"]

    def test_empty_range_returns_error(self, isolated):
        ips = isolated / "ips.txt"
        ips.write_text("8.8.8.8\n")

        assert main(["--file", str(ips), "--from", "5", "-o", "out.csv"]) == 1

    def test_no_blank_rows_between_records(self, isolated):
        """Opening the CSV without newline='' produces blank rows on Windows."""
        out = isolated / "out.csv"
        ips = isolated / "ips.txt"
        ips.write_text("8.8.8.8\n1.1.1.1\n")

        main(["--file", str(ips), "-o", str(out)])

        assert "" not in out.read_text().splitlines()

    @responses.activate
    def test_all_columns_includes_unlisted_fields(self, isolated):
        """--all-columns bypasses the [output] column list."""
        for ip in ("8.8.8.8",):
            responses.add(
                responses.GET,
                VT_URL_TEMPLATE.format(ip),
                json={"data": {"attributes": {"reputation": 42}}},
                status=200,
            )
        config = isolated / "c.toml"
        config.write_text(
            "[maxmind]\nenabled = false\n\n"
            '[virustotal]\nenabled = true\napi_key = "k"\n\n'
            '[output]\ncolumns = ["ip"]\n'
        )
        out = isolated / "out.csv"

        main(["8.8.8.8", "-c", str(config), "-o", str(out), "--all-columns"])

        assert "virustotal.reputation" in out.read_text()

    def test_log_file_written(self, isolated):
        log = isolated / "run.log"

        main(["8.8.8.8", "-o", str(isolated / "out.csv"), "--log-file", str(log)])

        assert log.exists()
        assert log.read_text().strip()


class TestProviderSelection:
    def test_list_providers(self, capsys):
        assert main(["--list-providers"]) == 0

        out = capsys.readouterr().out
        assert "virustotal" in out
        assert "key required" in out

    def test_explicit_providers_override_enabled_flags(self, isolated):
        out = isolated / "out.csv"

        assert main(["8.8.8.8", "--providers", "ping", "-o", str(out)]) == 0

    def test_unknown_provider_is_rejected(self):
        with pytest.raises(SystemExit):
            main(["8.8.8.8", "--providers", "nosuchprovider"])

    def test_malformed_as_of_is_rejected(self):
        with pytest.raises(SystemExit):
            main(["8.8.8.8", "--as-of", "march 2019"])

    def test_as_of_skips_unsupported_providers(self, isolated, caplog):
        """Rather than answering a historical question with current data."""
        out = isolated / "out.csv"

        main(["8.8.8.8", "--as-of", "2019-03-14", "-o", str(out)])

        assert "historical support" in caplog.text


class TestCacheFlag:
    def test_cache_file_is_created_and_reused(self, isolated):
        db = isolated / "obs.sqlite"
        out = isolated / "out.csv"

        main(["8.8.8.8", "--providers", "ping", "--cache", str(db), "-o", str(out)])

        assert db.exists()

    def test_max_age_accepted(self, isolated):
        db = isolated / "obs.sqlite"
        out = isolated / "out.csv"

        code = main(
            [
                "8.8.8.8",
                "--providers",
                "ping",
                "--cache",
                str(db),
                "--max-age",
                "24",
                "-o",
                str(out),
            ]
        )

        assert code == 0
