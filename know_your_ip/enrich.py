"""Batch enrichment: hand it addresses, get back a table.

``query_ip`` handles one address. Real work is a list of them, which brings
problems a loop does not solve on its own: staying inside published rate limits,
not paying for the same lookup twice, and not losing a row because one service
was unhealthy. This module is the batch entry point, and it records enough about
the run that the resulting table can be defended later.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from multiprocessing.pool import ThreadPool
from pathlib import Path
from typing import Any

from .cache import Cache, config_fingerprint
from .config import KnowYourIPConfig, load_config
from .core import InvalidIPError, read_ip_file, validate_ip
from .core import query_ip as _query_ip
from .providers import REGISTRY

logger = logging.getLogger(__name__)

DEFAULT_WORKERS = 5


@dataclass
class EnrichResult:
    """The records from an enrichment run, plus how they were produced.

    Returned rather than a bare DataFrame for two reasons: ``pandas`` is an
    optional extra, so the core path must not require it; and the manifest needs
    somewhere to live that a plain list of dicts does not provide.
    """

    records: list[dict[str, Any]] = field(default_factory=list)
    manifest: dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        """Number of records."""
        return len(self.records)

    def __iter__(self) -> Iterator[dict[str, Any]]:
        """Iterate the records."""
        return iter(self.records)

    @property
    def columns(self) -> list[str]:
        """Every field name present across the records, in first-seen order.

        Providers return different fields for different addresses, so the union
        is what a table needs.

        Returns:
            Ordered field names.
        """
        seen: dict[str, None] = {}
        for record in self.records:
            seen.update(dict.fromkeys(record))
        return list(seen)

    @property
    def errors(self) -> dict[str, int]:
        """How many records carry an error, per provider.

        Returns:
            Provider name to affected record count.
        """
        return _error_counts(self.records)

    def to_dataframe(self) -> Any:
        """Return the records as a pandas DataFrame.

        Returns:
            A DataFrame with one row per address.

        Raises:
            ImportError: If the optional ``pandas`` extra is not installed.
        """
        try:
            import pandas as pd
        except ImportError as exc:  # pragma: no cover - depends on extras
            raise ImportError(
                "to_dataframe() requires pandas. Install it with: "
                "pip install 'know_your_ip[pandas]'"
            ) from exc

        return pd.DataFrame(self.records, columns=self.columns)

    def to_csv(self, path: str | Path, columns: list[str] | None = None) -> Path:
        """Write the records to a CSV file.

        Args:
            path: Destination file.
            columns: Column order. Defaults to every field collected.

        Returns:
            The path written.
        """
        import csv

        destination = Path(path)
        fieldnames = columns or self.columns
        with destination.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self.records)
        return destination


def _build_manifest(
    config: KnowYourIPConfig,
    provider_names: list[str],
    as_of: date | None,
    started: datetime,
    records: list[dict[str, Any]],
    requested: int,
    skipped: list[str],
) -> dict[str, Any]:
    """Describe the run precisely enough to defend or repeat it.

    Args:
        config: Configuration used.
        provider_names: Providers that actually ran.
        as_of: Historical date requested, if any.
        started: When the run began.
        records: The records produced.
        requested: How many addresses were supplied.
        skipped: Addresses rejected as invalid.

    Returns:
        A JSON-serializable manifest.
    """
    from . import __version__

    cached = sum(1 for r in records if any(k.endswith(".from_cache") for k in r))
    return {
        "know_your_ip_version": __version__,
        "started_at": started.isoformat(),
        "finished_at": datetime.now(UTC).isoformat(),
        "providers": provider_names,
        "config_fingerprint": config_fingerprint(
            {
                name: getattr(config, name).model_dump(
                    exclude={"api_key", "username", "organization_id"}
                )
                for name in provider_names
                if hasattr(config, name)
            }
        ),
        "as_of": as_of.isoformat() if as_of else None,
        "addresses_requested": requested,
        "addresses_enriched": len(records),
        "addresses_skipped_invalid": skipped,
        "records_served_from_cache": cached,
        "provider_errors": dict(sorted(_error_counts(records).items())),
    }


def _error_counts(records: list[dict[str, Any]]) -> dict[str, int]:
    """Count records carrying an error, per provider.

    Args:
        records: Enriched records.

    Returns:
        Provider name to affected record count.
    """
    counts: dict[str, int] = {}
    for record in records:
        for key in record:
            if key.endswith(".error"):
                provider = key.rsplit(".", 1)[0]
                counts[provider] = counts.get(provider, 0) + 1
    return counts


def enrich(
    ips: Iterable[str],
    *,
    config: KnowYourIPConfig | None = None,
    providers: list[str] | None = None,
    as_of: date | None = None,
    cache: Cache | str | Path | None = None,
    max_age: timedelta | None = None,
    max_workers: int = DEFAULT_WORKERS,
) -> EnrichResult:
    """Enrich many IP addresses concurrently.

    Requests are paced to each provider's published rate limit, so raising
    ``max_workers`` does not produce rate-limit errors. Invalid addresses are
    skipped and recorded in the manifest rather than aborting the run, and a
    provider failing on one address does not affect the others.

    Args:
        ips: The addresses to enrich.
        config: Configuration. Loaded from the standard locations if omitted.
        providers: Provider names to run. Defaults to those enabled in config.
        as_of: Ask what was true on this date. Providers without historical
            support are skipped rather than answering with current data.
        cache: A :class:`~know_your_ip.cache.Cache`, or a path to open one at.
            Re-running over cached addresses costs no API quota.
        max_age: How stale a cached observation may be before it is refetched.
        max_workers: Concurrent lookups.

    Returns:
        An :class:`EnrichResult` holding the records and a run manifest.

    Raises:
        ValueError: If ``max_workers`` is less than one.

    Example:
        >>> result = enrich(["8.8.8.8", "1.1.1.1"], providers=["network"])
        >>> len(result)
        2
    """
    if max_workers < 1:
        raise ValueError("max_workers must be at least 1")

    started = datetime.now(UTC)
    config = config if config is not None else load_config()

    owns_cache = False
    if isinstance(cache, str | Path):
        cache = Cache(Path(cache))
        owns_cache = True

    valid: list[str] = []
    skipped: list[str] = []
    requested = 0
    for candidate in ips:
        requested += 1
        try:
            valid.append(validate_ip(candidate))
        except InvalidIPError:
            logger.warning("Skipping invalid address: %r", candidate)
            skipped.append(str(candidate))

    selected = REGISTRY.for_as_of(REGISTRY.selected(config, providers), as_of)
    provider_names = [p.name for p in selected]

    def run(ip: str) -> dict[str, Any]:
        return _query_ip(
            config,
            ip,
            providers=providers,
            as_of=as_of,
            cache=cache,
            max_age=max_age,
        )

    records: list[dict[str, Any]] = []
    try:
        if valid:
            with ThreadPool(processes=min(max_workers, len(valid))) as pool:
                records = list(pool.imap(run, valid))
    finally:
        if owns_cache and isinstance(cache, Cache):
            cache.close()

    return EnrichResult(
        records=records,
        manifest=_build_manifest(
            config, provider_names, as_of, started, records, requested, skipped
        ),
    )


def enrich_csv(
    input_path: str | Path,
    output_path: str | Path | None = None,
    *,
    column: str | None = None,
    columns: list[str] | None = None,
    **kwargs: Any,
) -> EnrichResult:
    """Enrich the addresses in a file and optionally write a CSV.

    Args:
        input_path: A text file of addresses, one per line, or a CSV.
        output_path: Where to write results. No file is written if omitted.
        column: Column holding addresses when the input is a CSV with a header.
            If omitted, the file is read as one address per line.
        columns: Column order for the output. Defaults to every field collected.
        **kwargs: Passed to :func:`enrich`.

    Returns:
        An :class:`EnrichResult`.

    Example:
        >>> enrich_csv("ips.csv", "out.csv", column="ip")  # doctest: +SKIP
    """
    source = Path(input_path)
    if column is not None:
        import csv

        with source.open(newline="", encoding="utf-8") as fh:
            addresses = [row[column] for row in csv.DictReader(fh) if row.get(column)]
    else:
        addresses = read_ip_file(source)

    result = enrich(addresses, **kwargs)

    if output_path is not None:
        result.to_csv(output_path, columns=columns)

    return result
