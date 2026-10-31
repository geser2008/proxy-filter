from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from proxyfilter.known_working import load_known_working, update_known_working
from proxyfilter.io import write_jsonl
from proxyfilter.model import ProxyConfig, SourceInfo


SOURCE = SourceInfo("test", "Test", "plain")


def make_proxy(suffix: int) -> ProxyConfig:
    proxy = ProxyConfig(
        SOURCE,
        "ss",
        f"203.0.113.{suffix}",
        8388,
        params={"method": "aes-256-gcm", "password": f"secret-{suffix}"},
    )
    proxy.ensure_id()
    return proxy


class KnownWorkingTests(unittest.TestCase):
    def test_new_proxy_enters_state_only_after_pass(self):
        now = datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc)
        passed = make_proxy(1)
        failed_new = make_proxy(2)

        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            counts = update_known_working(
                data_dir,
                [],
                [passed],
                [failed_new],
                seen_ids={passed.id, failed_new.id},
                retention_days=30,
                now=now,
            )

            retained, _ = load_known_working(data_dir)
            self.assertEqual([proxy.id for proxy in retained], [passed.id])
            self.assertEqual(counts["new_working"], 1)
            self.assertEqual(retained[0].lifecycle["consecutive_failures"], 0)
            self.assertEqual(retained[0].lifecycle["last_working"], "2026-10-27T08:00:00Z")

    def test_failed_known_proxy_is_retained_within_retention(self):
        now = datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc)
        old = make_proxy(3)
        old.lifecycle = {
            "first_seen": "2026-10-01T08:00:00Z",
            "last_seen": "2026-10-20T08:00:00Z",
            "last_working": "2026-10-10T08:00:00Z",
            "last_tested": "2026-10-20T08:00:00Z",
            "consecutive_failures": 1,
        }
        failed = make_proxy(3)
        failed.tests.status = "rejected_latency_error"

        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            counts = update_known_working(
                data_dir,
                [old],
                [],
                [failed],
                seen_ids=set(),
                retention_days=30,
                now=now,
            )
            retained, _ = load_known_working(data_dir)
            self.assertEqual(len(retained), 1)
            self.assertEqual(retained[0].lifecycle["consecutive_failures"], 2)
            self.assertEqual(retained[0].lifecycle["last_working"], "2026-10-10T08:00:00Z")
            self.assertEqual(counts["failing_retained"], 1)
            self.assertEqual(counts["expired"], 0)

    def test_failed_known_proxy_expires_after_retention(self):
        now = datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc)
        old = make_proxy(4)
        old.lifecycle = {
            "first_seen": "2026-09-01T08:00:00Z",
            "last_seen": "2026-09-20T08:00:00Z",
            "last_working": "2026-09-20T08:00:00Z",
            "last_tested": "2026-10-20T08:00:00Z",
            "consecutive_failures": 3,
        }
        failed = make_proxy(4)

        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            counts = update_known_working(
                data_dir,
                [old],
                [],
                [failed],
                seen_ids=set(),
                retention_days=30,
                now=now,
            )
            retained, _ = load_known_working(data_dir)
            self.assertEqual(retained, [])
            self.assertEqual(counts["expired"], 1)

    def test_recovered_proxy_resets_failure_counter(self):
        now = datetime(2026, 10, 27, 8, 0, tzinfo=timezone.utc)
        old = make_proxy(5)
        old.lifecycle = {
            "first_seen": "2026-10-01T08:00:00Z",
            "last_seen": "2026-10-20T08:00:00Z",
            "last_working": "2026-10-20T08:00:00Z",
            "last_tested": "2026-10-26T08:00:00Z",
            "consecutive_failures": 2,
        }
        passed = make_proxy(5)

        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            counts = update_known_working(
                data_dir,
                [old],
                [passed],
                [],
                seen_ids=set(),
                retention_days=30,
                now=now,
            )
            retained, _ = load_known_working(data_dir)
            self.assertEqual(retained[0].lifecycle["consecutive_failures"], 0)
            self.assertEqual(retained[0].lifecycle["last_working"], "2026-10-27T08:00:00Z")
            self.assertEqual(counts["recovered"], 1)

    def test_legacy_working_file_is_migrated_once_to_authoritative_state(self):
        proxy = make_proxy(6)
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            legacy = data_dir / "state" / "working.jsonl"
            primary = data_dir / "state" / "known-working.jsonl"
            write_jsonl(legacy, [proxy])

            retained, path = load_known_working(data_dir)

            self.assertEqual(path, primary)
            self.assertTrue(primary.is_file())
            self.assertEqual(len(retained), 1)
            self.assertTrue(retained[0].lifecycle["last_working"])
            self.assertEqual(retained[0].lifecycle["consecutive_failures"], 0)

    def test_legacy_changes_after_migration_are_ignored(self):
        migrated = make_proxy(10)
        later_legacy = make_proxy(11)
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            legacy = data_dir / "state" / "working.jsonl"
            primary = data_dir / "state" / "known-working.jsonl"
            write_jsonl(legacy, [migrated])

            first, first_path = load_known_working(data_dir)
            write_jsonl(legacy, [later_legacy])
            second, second_path = load_known_working(data_dir)

            self.assertEqual(first_path, primary)
            self.assertEqual(second_path, primary)
            self.assertEqual([proxy.id for proxy in first], [migrated.id])
            self.assertEqual([proxy.id for proxy in second], [migrated.id])

    def test_existing_authoritative_state_never_falls_back_to_legacy(self):
        authoritative = make_proxy(7)
        legacy_only = make_proxy(8)
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            primary = data_dir / "state" / "known-working.jsonl"
            legacy = data_dir / "state" / "working.jsonl"
            write_jsonl(primary, [authoritative])
            write_jsonl(legacy, [legacy_only])

            retained, path = load_known_working(data_dir)

            self.assertEqual(path, primary)
            self.assertEqual([proxy.id for proxy in retained], [authoritative.id])

    def test_empty_authoritative_state_does_not_resurrect_legacy_entries(self):
        legacy_only = make_proxy(9)
        with TemporaryDirectory() as tmp:
            data_dir = Path(tmp)
            primary = data_dir / "state" / "known-working.jsonl"
            legacy = data_dir / "state" / "working.jsonl"
            write_jsonl(primary, [])
            write_jsonl(legacy, [legacy_only])

            retained, path = load_known_working(data_dir)

            self.assertEqual(path, primary)
            self.assertEqual(retained, [])


if __name__ == "__main__":
    unittest.main()
