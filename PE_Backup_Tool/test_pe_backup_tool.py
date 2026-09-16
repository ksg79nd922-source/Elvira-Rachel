import json
import tempfile
import unittest
from pathlib import Path

from pe_backup_tool import discover_jobs, main, report


class BackupWorkflowTests(unittest.TestCase):
    def test_report_copy_and_detect_changed_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, backup, output = (root / name for name in ("source", "backup", "output"))
            (source / "JobA" / "nested").mkdir(parents=True)
            (source / "JobA" / "nested" / "result.txt").write_text("first", encoding="utf-8")
            backup.mkdir()
            config = root / "config.json"
            config.write_text(json.dumps({"source_root": str(source), "backup_root": str(backup),
                                          "report_dir": str(output)}))
            self.assertEqual(main(["--config", str(config), "--job", "JobA"]), 2)
            self.assertEqual(json.loads((output / "report.json").read_text())["jobs"][0]["status"],
                             "NOT_BACKED_UP")
            self.assertEqual(main(["--config", str(config), "--job", "JobA", "--copy"]), 0)
            self.assertEqual((backup / "JobA" / "nested" / "result.txt").read_text(), "first")
            (backup / "JobA" / "nested" / "result.txt").write_text("other", encoding="utf-8")
            self.assertEqual(main(["--config", str(config), "--job", "JobA", "--copy"]), 2)
            self.assertEqual((backup / "JobA" / "nested" / "result.txt").read_text(), "other")
            row = json.loads((output / "report.json").read_text())["jobs"][0]
            self.assertEqual(row["different_files"], 1)
            self.assertEqual(row["copy_result"]["conflicts"], ["nested/result.txt"])

    def test_missing_backup_drive_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "source" / "JobA").mkdir(parents=True)
            with self.assertRaises(FileNotFoundError):
                report(root / "source", root / "unavailable", ["JobA"], False)

    def test_same_size_different_bytes_are_detected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for drive, content in (("source", "abcd"), ("backup", "wxyz")):
                job = root / drive / "JobA"
                job.mkdir(parents=True)
                (job / "result.bin").write_bytes(content.encode())
            row = report(root / "source", root / "backup", ["JobA"], False)["jobs"][0]
            self.assertEqual(row["status"], "DIFFERENT")
            self.assertEqual(row["different_files"], 1)

    def test_jobs_are_sorted_by_size_and_storage_fields_are_present(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, backup = root / "source", root / "backup"
            for job, content in (("Small", b"1"), ("Large", b"123456")):
                path = source / job
                path.mkdir(parents=True)
                (path / "result.bin").write_bytes(content)
            backup.mkdir()
            data = report(source, backup, ["Small", "Large"], False)
            self.assertEqual([row["job"] for row in data["jobs"]], ["Large", "Small"])
            self.assertIn("free_bytes", data["source_disk"])
            self.assertIn("free_bytes", data["backup_disk"])
            self.assertTrue(data["jobs"][0]["folder_modified"])
            self.assertTrue(data["jobs"][0]["latest_file_modified"])
            self.assertTrue(data["jobs"][0]["scanned_at"])

    def test_root_files_and_per_file_sizes_are_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, backup = root / "source", root / "backup"
            source.mkdir()
            backup.mkdir()
            (source / "loose.pdf").write_bytes(b"12345")
            (backup / "loose.pdf").write_bytes(b"123")
            data = report(source, backup, [], False)
            self.assertEqual(data["jobs"][0]["job"], "[ROOT FILES]")
            item = data["jobs"][0]["file_results"][0]
            self.assertEqual(item["path"], "loose.pdf")
            self.assertEqual(item["source_size_bytes"], 5)
            self.assertEqual(item["backup_size_bytes"], 3)
            self.assertFalse(item["size_equal"])
            self.assertEqual(item["status"], "SIZE_DIFFERENT")

    def test_new_jobs_are_discovered_and_system_files_are_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, backup = root / "source", root / "backup"
            (source / "Job001").mkdir(parents=True)
            (source / "3911").mkdir()
            backup.mkdir()
            (source / ".DS_Store").write_bytes(b"metadata")
            jobs = discover_jobs(source, None)
            self.assertEqual(jobs, ["3911", "Job001"])
            data = report(source, backup, jobs, False)
            self.assertNotIn("[ROOT FILES]", [row["job"] for row in data["jobs"]])


if __name__ == "__main__":
    unittest.main()
