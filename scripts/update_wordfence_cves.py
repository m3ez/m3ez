#!/usr/bin/env python3
"""Synchronize Supakiad S.'s published Wordfence CVEs into README.md."""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlparse
from urllib.request import Request, urlopen


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
PROFILE_URL = "https://www.wordfence.com/threat-intel/vulnerabilities/researchers/supakiad-s"
START_MARKER = "<!-- WORDFENCE-CVES:START -->"
END_MARKER = "<!-- WORDFENCE-CVES:END -->"
PRODUCTION_FEED_URL = "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production"
RESEARCHER_ALIASES = frozenset(
    {
        "supakiad s. (m3ez)",
        "supakiad s.",
        "m3ez",
    }
)


@dataclass(frozen=True)
class CVERecord:
    cve: str
    published: datetime
    link: str


def _normalize_researcher(value: str) -> str:
    return " ".join(value.split()).casefold()


def _parse_published(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = f"{normalized[:-1]}+00:00"
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _is_public_http_url(value: object) -> bool:
    if not isinstance(value, str):
        return False
    parsed = urlparse(value)
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def choose_link(record: Mapping[str, object], cve: str) -> str:
    references = record.get("references")
    if isinstance(references, list):
        for reference in references:
            if not _is_public_http_url(reference):
                continue
            parsed = urlparse(reference)
            hostname = (parsed.hostname or "").casefold()
            if (
                (hostname == "wordfence.com" or hostname.endswith(".wordfence.com"))
                and parsed.path.startswith("/threat-intel/vulnerabilities/")
                and "/researchers/" not in parsed.path
            ):
                return reference

    cve_link = record.get("cve_link")
    if _is_public_http_url(cve_link):
        return str(cve_link)

    return f"https://www.cve.org/CVERecord?id={cve}"


def select_cves(feed: Mapping[str, object]) -> list[CVERecord]:
    selected: dict[str, CVERecord] = {}

    for raw_record in feed.values():
        if not isinstance(raw_record, Mapping):
            continue

        researchers = raw_record.get("researchers")
        if not isinstance(researchers, list):
            continue
        normalized_researchers = {
            _normalize_researcher(researcher)
            for researcher in researchers
            if isinstance(researcher, str)
        }
        if RESEARCHER_ALIASES.isdisjoint(normalized_researchers):
            continue

        raw_cve = raw_record.get("cve")
        cve = raw_cve.strip().upper() if isinstance(raw_cve, str) else ""
        raw_published = raw_record.get("published")
        if not CVE_PATTERN.fullmatch(cve) or not isinstance(raw_published, str):
            continue

        candidate = CVERecord(
            cve=cve,
            published=_parse_published(raw_published),
            link=choose_link(raw_record, cve),
        )
        existing = selected.get(cve)
        if existing is None or candidate.published > existing.published:
            selected[cve] = candidate

    return sorted(
        selected.values(),
        key=lambda record: (record.published, record.cve),
        reverse=True,
    )


def render_cves(records: Sequence[CVERecord]) -> str:
    if not records:
        raise ValueError("Wordfence feed contained no matching published CVEs")

    noun = "CVE" if len(records) == 1 else "CVEs"
    links = " · ".join(f"[{record.cve}]({record.link})" for record in records)
    return (
        f"[**{len(records)} {noun}**]({PROFILE_URL}) "
        "· newest first, because archaeology can wait.\n\n"
        f"{links}"
    )


def replace_generated_block(readme: str, generated: str) -> str:
    if readme.count(START_MARKER) != 1 or readme.count(END_MARKER) != 1:
        raise ValueError("README must contain exactly one Wordfence CVE marker pair")
    if START_MARKER in generated or END_MARKER in generated:
        raise ValueError("Generated content cannot contain README markers")

    start = readme.index(START_MARKER)
    end = readme.index(END_MARKER)
    if start >= end:
        raise ValueError("Wordfence CVE markers are reversed")

    prefix = readme[: start + len(START_MARKER)]
    suffix = readme[end:]
    return f"{prefix}\n{generated.strip()}\n{suffix}"


def fetch_feed(
    api_key: str,
    timeout: int = 180,
    opener: Callable[..., Any] = urlopen,
) -> Mapping[str, object]:
    key = api_key.strip()
    if not key:
        raise ValueError("WORDFENCE_API_KEY is not configured")

    request = Request(
        PRODUCTION_FEED_URL,
        headers={
            "Accept": "application/json",
            "Authorization": f"Bearer {key}",
            "User-Agent": "m3ez-profile-cve-updater/1.0",
        },
    )
    with opener(request, timeout=timeout) as response:
        payload = json.loads(response.read().decode("utf-8"))

    if not isinstance(payload, dict):
        raise ValueError("Wordfence production feed root must be a JSON object")
    return payload


def update_readme(readme_path: Path, feed: Mapping[str, object]) -> bool:
    generated = render_cves(select_cves(feed))
    original = readme_path.read_text(encoding="utf-8")
    updated = replace_generated_block(original, generated)
    if updated == original:
        return False

    readme_path.write_text(updated, encoding="utf-8")
    return True


def main() -> int:
    try:
        feed = fetch_feed(os.environ.get("WORDFENCE_API_KEY", ""))
        changed = update_readme(Path("README.md"), feed)
    except (OSError, ValueError) as error:
        print(f"Wordfence CVE update failed: {error}", file=sys.stderr)
        return 1

    print("README.md updated" if changed else "README.md already current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
