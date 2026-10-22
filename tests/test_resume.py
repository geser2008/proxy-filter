import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from proxyfilter.model import ProxyConfig, SourceInfo
from proxyfilter.resume import load_stage, stage_should_run, validate_resume_range


class ResumeTests(unittest.TestCase):
    def test_load_stage_round_trip(self):
        proxy = ProxyConfig(SourceInfo("test", "Test"), "vless", "example.com", 443, params={"uuid": "abc"})
        proxy.tests.status = "exit_ip_pass"
        proxy.ensure_id()

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "work" / "test" / "10-geo.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(proxy.to_dict()) + "\n", encoding="utf-8")

            loaded, loaded_path = load_stage(Path(tmp), "test", "geo")

        self.assertEqual(loaded_path.name, "10-geo.jsonl")
        self.assertEqual(len(loaded), 1)
        self.assertEqual(loaded[0].id, proxy.id)
        self.assertEqual(loaded[0].identity_payload(), proxy.identity_payload())

    def test_missing_resume_file_fails(self):
        with TemporaryDirectory() as tmp:
            with self.assertRaises(FileNotFoundError):
                load_stage(Path(tmp), "test", "geo")

    def test_invalid_json_fails(self):
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "work" / "test" / "10-geo.jsonl"
            path.parent.mkdir(parents=True)
            path.write_text("{broken\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_stage(Path(tmp), "test", "geo")

    def test_only_later_stages_run(self):
        self.assertFalse(stage_should_run("geo", "geo"))
        self.assertFalse(stage_should_run("download", "geo"))
        self.assertTrue(stage_should_run("geo", "exit-ip"))

    def test_until_before_resume_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_resume_range("geo", "upload")

    def test_until_equal_resume_is_allowed(self):
        validate_resume_range("geo", "geo")


if __name__ == "__main__":
    unittest.main()
