"""Download the GeoLite2 databases MaxMind requires an account to obtain.

MaxMind is the package's default geolocation source, but anonymous downloads
ended in 2019: using it at all now requires a free account and a license key.
Nothing in the package previously helped with that, so the flagship provider
failed on every fresh install.

Two things about the download are easy to get wrong. Since January 2024 the
files are served by redirect to Cloudflare R2, so redirects must be followed --
a proxy that blocks that host is the most common real-world failure. And the
payload is a tar archive whose member paths come from a remote server, so it is
extracted a single validated member at a time rather than wholesale.
"""

from __future__ import annotations

import logging
import tarfile
import tempfile
from pathlib import Path

from . import http
from .cache import user_cache_dir

logger = logging.getLogger(__name__)

DOWNLOAD_URL = "https://download.maxmind.com/geoip/databases/{edition}/download"

# The editions worth having: city implies country, and ASN is a separate file.
EDITIONS = ("GeoLite2-City", "GeoLite2-ASN")


def database_dir() -> Path:
    """Where downloaded databases are kept.

    Returns:
        A directory under the user cache directory. Not created.
    """
    return user_cache_dir() / "maxmind"


def _safe_mmdb_member(archive: tarfile.TarFile, edition: str) -> tarfile.TarInfo:
    """Find the single ``.mmdb`` member, rejecting unsafe paths.

    Member names come from a remote archive, so they are treated as untrusted.
    ``extractall`` is deliberately not used: tar path traversal is a real attack,
    and the ``filter=`` argument's default behavior differs across the Python
    versions this package supports.

    Args:
        archive: The opened tar archive.
        edition: Edition name, used in the error message.

    Returns:
        The ``.mmdb`` member.

    Raises:
        ValueError: If no safe ``.mmdb`` member is present.
    """
    for member in archive.getmembers():
        if not member.name.endswith(".mmdb") or not member.isfile():
            continue
        name = Path(member.name).name
        if member.name.startswith("/") or ".." in Path(member.name).parts:
            raise ValueError(f"Refusing unsafe archive member: {member.name!r}")
        member.name = name  # flatten; we extract to a directory of our choosing
        return member

    raise ValueError(f"No .mmdb file found in the {edition} archive")


def download_database(
    account_id: str,
    license_key: str,
    edition: str = "GeoLite2-City",
    target_dir: Path | None = None,
) -> Path:
    """Fetch one GeoLite2 database and write it to disk.

    Args:
        account_id: MaxMind account ID.
        license_key: MaxMind license key.
        edition: Edition to fetch, e.g. ``GeoLite2-City`` or ``GeoLite2-ASN``.
        target_dir: Where to write the ``.mmdb``. Defaults to
            :func:`database_dir`.

    Returns:
        Path to the written database.

    Raises:
        RuntimeError: If the download fails.
        ValueError: If the archive contains no safe ``.mmdb`` member.

    Note:
        GeoLite2 accounts are limited to 30 downloads per 24 hours.
    """
    target_dir = target_dir or database_dir()
    target_dir.mkdir(parents=True, exist_ok=True)

    result = http.request(
        "maxmind-download",
        "GET",
        DOWNLOAD_URL.format(edition=edition),
        params={"suffix": "tar.gz"},
        auth=(account_id, license_key),
        timeout=300,
        # Redirects to Cloudflare R2 since January 2024.
        allow_redirects=True,
    )

    if not result.ok:
        if result.status_code == 401:
            raise RuntimeError(
                "MaxMind rejected the credentials. Check the account ID and "
                "license key at https://www.maxmind.com/en/accounts/current/license-key"
            )
        if result.status_code == 429:
            raise RuntimeError(
                "MaxMind download limit reached (GeoLite2 allows 30 per 24 hours)"
            )
        raise RuntimeError(
            f"MaxMind download failed: {result.error or f'HTTP {result.status_code}'}"
        )

    assert result.response is not None  # noqa: S101 - result.ok implies a response

    with tempfile.TemporaryDirectory() as tmp:
        archive_path = Path(tmp) / f"{edition}.tar.gz"
        archive_path.write_bytes(result.response.content)

        with tarfile.open(archive_path, "r:gz") as archive:
            member = _safe_mmdb_member(archive, edition)
            extracted = archive.extractfile(member)
            if extracted is None:  # pragma: no cover - member.isfile() checked
                raise ValueError(f"Could not read {member.name} from the archive")
            destination = target_dir / member.name
            destination.write_bytes(extracted.read())

    size_mb = destination.stat().st_size / 1_000_000
    logger.info("Wrote %s (%.1f MB)", destination, size_mb)
    return destination


def download_all(
    account_id: str,
    license_key: str,
    target_dir: Path | None = None,
) -> list[Path]:
    """Fetch every edition in :data:`EDITIONS`.

    A failure on one edition does not prevent the others from being fetched.

    Args:
        account_id: MaxMind account ID.
        license_key: MaxMind license key.
        target_dir: Where to write the databases.

    Returns:
        Paths that were written successfully.
    """
    written = []
    for edition in EDITIONS:
        try:
            written.append(
                download_database(account_id, license_key, edition, target_dir)
            )
        except (RuntimeError, ValueError) as exc:
            logger.error("%s: %s", edition, exc)
    return written


def find_database(configured: Path, filename: str = "GeoLite2-City.mmdb") -> Path:
    """Locate a database, falling back to the download directory.

    This is what lets ``download-db`` then a plain run work with no further
    configuration: the configured path wins if it holds a database, and the
    downloaded copy is used otherwise.

    Args:
        configured: The directory named in configuration.
        filename: Database file to look for.

    Returns:
        The path that exists, or the configured one if neither does, so the
        caller's error message names what the user actually configured.
    """
    candidate = configured / filename
    if candidate.exists():
        return candidate

    downloaded = database_dir() / filename
    if downloaded.exists():
        logger.debug("Using downloaded database at %s", downloaded)
        return downloaded

    return candidate
