from __future__ import annotations

import json
import io
import os
import tempfile
import unittest
from contextlib import chdir, redirect_stderr
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.request import Request

from scripts.update_wordfence_cves import (
    CVERecord,
    choose_link,
    fetch_feed,
    main,
    render_cves,
    replace_generated_block,
    select_cves,
    update_readme,
)


def vulnerability(
    *,
    record_id: str,
    cve: str | None,
    researchers: list[str],
    published: str | None,
    references: list[str] | None = None,
    cve_link: str | None = None,
) -> dict[str, object]:
    return {
        "id": record_id,
        "title": f"Test vulnerability {record_id}",
        "software": [
            {
                "type": "plugin",
                "name": "Test Plugin",
                "slug": "test-plugin",
                "affected_versions": {},
                "patched": True,
                "patched_versions": ["2.0.0"],
                "remediation": "Update to version 2.0.0.",
            }
        ],
        "informational": False,
        "description": "A complete deterministic test record.",
        "references": references or [],
        "cwe": {
            "id": 284,
            "name": "Improper Access Control",
            "description": "Authorization is not enforced.",
        },
        "cvss": {
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
            "score": 5.3,
            "rating": "Medium",
        },
        "cve": cve,
        "cve_link": cve_link,
        "researchers": researchers,
        "published": published,
        "updated": published,
        "copyrights": None,
    }


class SelectCVEsTests(unittest.TestCase):
    def test_accepts_known_aliases_and_rejects_unrelated_researchers(self) -> None:
        feed = {
            "full-name": vulnerability(
                record_id="full-name",
                cve="CVE-2026-1001",
                researchers=["  Supakiad   S. (m3ez)  "],
                published="2026-01-01 00:00:00",
            ),
            "handle": vulnerability(
                record_id="handle",
                cve="CVE-2026-1002",
                researchers=["m3ez"],
                published="2026-01-02 00:00:00",
            ),
            "unrelated": vulnerability(
                record_id="unrelated",
                cve="CVE-2026-9999",
                researchers=["Another Researcher"],
                published="2026-01-03 00:00:00",
            ),
        }

        records = select_cves(feed)

        self.assertEqual(
            [record.cve for record in records],
            ["CVE-2026-1002", "CVE-2026-1001"],
        )

    def test_rejects_missing_invalid_and_unpublished_cves(self) -> None:
        feed = {
            "valid": vulnerability(
                record_id="valid",
                cve="CVE-2026-1001",
                researchers=["Supakiad S."],
                published="2026-01-01T00:00:00Z",
            ),
            "missing": vulnerability(
                record_id="missing",
                cve=None,
                researchers=["Supakiad S."],
                published="2026-01-02T00:00:00Z",
            ),
            "invalid": vulnerability(
                record_id="invalid",
                cve="2026-1002",
                researchers=["Supakiad S."],
                published="2026-01-03T00:00:00Z",
            ),
            "unpublished": vulnerability(
                record_id="unpublished",
                cve="CVE-2026-1003",
                researchers=["Supakiad S."],
                published=None,
            ),
        }

        records = select_cves(feed)

        self.assertEqual([record.cve for record in records], ["CVE-2026-1001"])

    def test_keeps_newest_duplicate_and_sorts_by_publication_date(self) -> None:
        feed = {
            "older-duplicate": vulnerability(
                record_id="older-duplicate",
                cve="CVE-2026-1001",
                researchers=["m3ez"],
                published="2026-01-01 00:00:00",
                cve_link="https://old.example/CVE-2026-1001",
            ),
            "newest": vulnerability(
                record_id="newest",
                cve="CVE-2026-1002",
                researchers=["m3ez"],
                published="2026-01-03 00:00:00",
            ),
            "newer-duplicate": vulnerability(
                record_id="newer-duplicate",
                cve="CVE-2026-1001",
                researchers=["m3ez"],
                published="2026-01-02 00:00:00",
                cve_link="https://new.example/CVE-2026-1001",
            ),
        }

        records = select_cves(feed)

        self.assertEqual(
            [(record.cve, record.link) for record in records],
            [
                ("CVE-2026-1002", "https://www.cve.org/CVERecord?id=CVE-2026-1002"),
                ("CVE-2026-1001", "https://new.example/CVE-2026-1001"),
            ],
        )


class ChooseLinkTests(unittest.TestCase):
    def test_prefers_public_wordfence_vulnerability_record(self) -> None:
        record = vulnerability(
            record_id="preferred-link",
            cve="CVE-2026-1001",
            researchers=["m3ez"],
            published="2026-01-01 00:00:00",
            references=[
                "https://vendor.example/advisory",
                "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/test-plugin/test-record",
            ],
            cve_link="https://www.cve.org/CVERecord?id=CVE-2026-1001",
        )

        self.assertEqual(
            choose_link(record, "CVE-2026-1001"),
            "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/test-plugin/test-record",
        )

    def test_falls_back_to_cve_link_then_canonical_cve_url(self) -> None:
        provided = vulnerability(
            record_id="provided-link",
            cve="CVE-2026-1001",
            researchers=["m3ez"],
            published="2026-01-01 00:00:00",
            cve_link="https://example.cve.test/CVE-2026-1001",
        )
        canonical = vulnerability(
            record_id="canonical-link",
            cve="CVE-2026-1002",
            researchers=["m3ez"],
            published="2026-01-02 00:00:00",
        )

        self.assertEqual(
            choose_link(provided, "CVE-2026-1001"),
            "https://example.cve.test/CVE-2026-1001",
        )
        self.assertEqual(
            choose_link(canonical, "CVE-2026-1002"),
            "https://www.cve.org/CVERecord?id=CVE-2026-1002",
        )


class RenderCVEsTests(unittest.TestCase):
    def test_renders_count_caption_and_every_link_in_given_order(self) -> None:
        records = [
            CVERecord(
                cve="CVE-2026-1002",
                published=datetime(2026, 1, 2, tzinfo=timezone.utc),
                link="https://wordfence.example/CVE-2026-1002",
            ),
            CVERecord(
                cve="CVE-2026-1001",
                published=datetime(2026, 1, 1, tzinfo=timezone.utc),
                link="https://wordfence.example/CVE-2026-1001",
            ),
        ]

        rendered = render_cves(records)

        self.assertEqual(
            rendered,
            "[**2 CVEs**](https://www.wordfence.com/threat-intel/vulnerabilities/researchers/supakiad-s) "
            "· newest first, because archaeology can wait.\n\n"
            "[CVE-2026-1002](https://wordfence.example/CVE-2026-1002) · "
            "[CVE-2026-1001](https://wordfence.example/CVE-2026-1001)",
        )

    def test_rejects_empty_record_list(self) -> None:
        with self.assertRaises(ValueError):
            render_cves([])


class ReplaceGeneratedBlockTests(unittest.TestCase):
    def test_replaces_only_content_between_single_marker_pair(self) -> None:
        readme = (
            "before\n"
            "<!-- WORDFENCE-CVES:START -->\n"
            "old generated content\n"
            "<!-- WORDFENCE-CVES:END -->\n"
            "after\n"
        )

        updated = replace_generated_block(readme, "new generated content")

        self.assertEqual(
            updated,
            "before\n"
            "<!-- WORDFENCE-CVES:START -->\n"
            "new generated content\n"
            "<!-- WORDFENCE-CVES:END -->\n"
            "after\n",
        )

    def test_rejects_missing_duplicated_or_reversed_markers(self) -> None:
        invalid_readmes = [
            "no markers\n",
            (
                "<!-- WORDFENCE-CVES:START -->\n"
                "<!-- WORDFENCE-CVES:START -->\n"
                "<!-- WORDFENCE-CVES:END -->\n"
            ),
            (
                "<!-- WORDFENCE-CVES:START -->\n"
                "<!-- WORDFENCE-CVES:END -->\n"
                "<!-- WORDFENCE-CVES:END -->\n"
            ),
            (
                "<!-- WORDFENCE-CVES:END -->\n"
                "<!-- WORDFENCE-CVES:START -->\n"
            ),
        ]

        for readme in invalid_readmes:
            with self.subTest(readme=readme), self.assertRaises(ValueError):
                replace_generated_block(readme, "new generated content")


class FakeResponse:
    def __init__(self, payload: object) -> None:
        self.body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.body


class FetchFeedTests(unittest.TestCase):
    def test_rejects_missing_key_without_opening_network(self) -> None:
        opened = False

        def forbidden_opener(*_args: object, **_kwargs: object) -> Any:
            nonlocal opened
            opened = True
            raise AssertionError("network must not be opened without an API key")

        with self.assertRaises(ValueError):
            fetch_feed("", opener=forbidden_opener)

        self.assertFalse(opened)

    def test_sends_bearer_header_and_returns_json_object(self) -> None:
        captured: dict[str, object] = {}
        payload = {"record-id": {"id": "record-id"}}

        def opener(request: Request, *, timeout: int) -> FakeResponse:
            captured["authorization"] = request.get_header("Authorization")
            captured["accept"] = request.get_header("Accept")
            captured["timeout"] = timeout
            return FakeResponse(payload)

        result = fetch_feed("test-api-key", timeout=17, opener=opener)

        self.assertEqual(result, payload)
        self.assertEqual(captured["authorization"], "Bearer test-api-key")
        self.assertEqual(captured["accept"], "application/json")
        self.assertEqual(captured["timeout"], 17)

    def test_rejects_non_object_json_feed(self) -> None:
        def opener(_request: Request, *, timeout: int) -> FakeResponse:
            self.assertEqual(timeout, 180)
            return FakeResponse(["not", "an", "object"])

        with self.assertRaises(ValueError):
            fetch_feed("test-api-key", opener=opener)


class UpdateReadmeTests(unittest.TestCase):
    def test_writes_validated_generated_content_and_reports_change(self) -> None:
        feed = {
            "record": vulnerability(
                record_id="record",
                cve="CVE-2026-1001",
                researchers=["Supakiad S. (m3ez)"],
                published="2026-01-01 00:00:00",
                references=[
                    "https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/test-plugin/test-record"
                ],
            )
        }
        original = (
            "# Profile\n\n"
            "<!-- WORDFENCE-CVES:START -->\n"
            "old content\n"
            "<!-- WORDFENCE-CVES:END -->\n"
        )

        with tempfile.TemporaryDirectory() as directory:
            readme = Path(directory) / "README.md"
            readme.write_text(original, encoding="utf-8")

            changed = update_readme(readme, feed)

            self.assertTrue(changed)
            self.assertEqual(
                readme.read_text(encoding="utf-8"),
                "# Profile\n\n"
                "<!-- WORDFENCE-CVES:START -->\n"
                "[**1 CVE**](https://www.wordfence.com/threat-intel/vulnerabilities/researchers/supakiad-s) "
                "· newest first, because archaeology can wait.\n\n"
                "[CVE-2026-1001](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/test-plugin/test-record)\n"
                "<!-- WORDFENCE-CVES:END -->\n",
            )

    def test_does_not_rewrite_identical_content(self) -> None:
        feed = {
            "record": vulnerability(
                record_id="record",
                cve="CVE-2026-1001",
                researchers=["m3ez"],
                published="2026-01-01 00:00:00",
            )
        }
        original = (
            "<!-- WORDFENCE-CVES:START -->\n"
            "[**1 CVE**](https://www.wordfence.com/threat-intel/vulnerabilities/researchers/supakiad-s) "
            "· newest first, because archaeology can wait.\n\n"
            "[CVE-2026-1001](https://www.cve.org/CVERecord?id=CVE-2026-1001)\n"
            "<!-- WORDFENCE-CVES:END -->\n"
        )

        with tempfile.TemporaryDirectory() as directory:
            readme = Path(directory) / "README.md"
            readme.write_text(original, encoding="utf-8")

            changed = update_readme(readme, feed)

            self.assertFalse(changed)
            self.assertEqual(readme.read_text(encoding="utf-8"), original)


class MainTests(unittest.TestCase):
    def test_missing_key_returns_failure_without_touching_readme(self) -> None:
        original = (
            "<!-- WORDFENCE-CVES:START -->\n"
            "existing public data\n"
            "<!-- WORDFENCE-CVES:END -->\n"
        )

        with tempfile.TemporaryDirectory() as directory:
            readme = Path(directory) / "README.md"
            readme.write_text(original, encoding="utf-8")

            stderr = io.StringIO()
            with (
                chdir(directory),
                patch.dict(os.environ, {}, clear=True),
                redirect_stderr(stderr),
            ):
                result = main()

            self.assertEqual(result, 1)
            self.assertIn("WORDFENCE_API_KEY is not configured", stderr.getvalue())
            self.assertEqual(readme.read_text(encoding="utf-8"), original)

    def test_leaves_readme_untouched_when_feed_has_no_matching_cves(self) -> None:
        feed = {
            "unrelated": vulnerability(
                record_id="unrelated",
                cve="CVE-2026-9999",
                researchers=["Another Researcher"],
                published="2026-01-01 00:00:00",
            )
        }
        original = (
            "<!-- WORDFENCE-CVES:START -->\n"
            "existing public data\n"
            "<!-- WORDFENCE-CVES:END -->\n"
        )

        with tempfile.TemporaryDirectory() as directory:
            readme = Path(directory) / "README.md"
            readme.write_text(original, encoding="utf-8")

            with self.assertRaises(ValueError):
                update_readme(readme, feed)

            self.assertEqual(readme.read_text(encoding="utf-8"), original)


if __name__ == "__main__":
    unittest.main()
