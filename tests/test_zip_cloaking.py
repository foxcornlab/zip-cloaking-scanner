#!/usr/bin/env python3
"""Tests for zip_cloaking.py. All fixtures live in temp directories.

No test extracts an archive to disk and no test overwrites a real file: the
header check reads headers only, and the crafted archive is built by patching
a Central Directory filename in place inside a temp file that is never
extracted.
"""

import os
import subprocess
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import zip_cloaking  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "zip_cloaking.py")


def make_benign_archive(path):
    """One file, Central and Local names agree."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("hello.txt", "hello\n")


def make_cloaked_archive(path):
    """CDFH says doc_report.pdf, LFH says cron_worker.sh.

    Both names are 14 bytes, so the Central Directory filename can be patched
    in place without shifting any offsets. The file is never extracted.
    """
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("cron_worker.sh", "#!/bin/sh\necho hi\n")
    with open(path, "r+b") as handle:
        data = handle.read()
        central = data.find(b"PK\x01\x02")
        assert central >= 0, "no central directory entry found"
        # Central header is 46 bytes; filename starts right after it.
        name_start = central + 46
        name_end = name_start + len(b"cron_worker.sh")
        assert data[name_start:name_end] == b"cron_worker.sh"
        handle.seek(name_start)
        handle.write(b"doc_report.pdf")
    # Local header still says cron_worker.sh; nothing was extracted.


def make_cargo_lock(path, version):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(
            "# test fixture, not a real lockfile\n"
            "[[package]]\n"
            'name = "serde"\n'
            'version = "1.0.0"\n'
            "\n"
            "[[package]]\n"
            'name = "zip"\n'
            'version = "%s"\n' % version
        )


class TestCargoCheck(unittest.TestCase):
    def test_lock_9_0_4_vulnerable(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = os.path.join(tmp, "Cargo.lock")
            make_cargo_lock(lock, "9.0.4")
            findings = zip_cloaking.scan_cargo_lock(lock)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["status"], "VULNERABLE")

    def test_lock_9_0_5_fixed(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = os.path.join(tmp, "Cargo.lock")
            make_cargo_lock(lock, "9.0.5")
            findings = zip_cloaking.scan_cargo_lock(lock)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["status"], "FIXED")

    def test_lock_no_zip_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            lock = os.path.join(tmp, "Cargo.lock")
            with open(lock, "w", encoding="utf-8") as handle:
                handle.write('[[package]]\nname = "serde"\nversion = "1.0.0"\n')
            findings = zip_cloaking.scan_cargo_lock(lock)
            self.assertEqual(findings[0]["status"], "UNKNOWN")

    def test_toml_requirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            toml = os.path.join(tmp, "Cargo.toml")
            with open(toml, "w", encoding="utf-8") as handle:
                handle.write('[dependencies]\nzip = "9.0.3"\n')
            findings = zip_cloaking.scan_cargo_toml(toml)
            self.assertEqual(findings[0]["status"], "VULNERABLE")

    def test_version_compare(self):
        self.assertEqual(zip_cloaking.grade_zip_version((9, 0, 4)),
                         "VULNERABLE")
        self.assertEqual(zip_cloaking.grade_zip_version((9, 0, 5)), "FIXED")
        self.assertEqual(zip_cloaking.grade_zip_version((10, 0, 0)), "FIXED")
        self.assertEqual(zip_cloaking.grade_zip_version(None), "UNKNOWN")


class TestZipHeaders(unittest.TestCase):
    def test_benign_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "benign.zip")
            make_benign_archive(archive)
            findings = zip_cloaking.scan_zip_headers(archive)
            self.assertTrue(findings)
            self.assertTrue(all(f["status"] == "CLEAN" for f in findings))
            # Guard against a vacuous pass: the real entry must be inspected.
            detail = " ".join(f["detail"] for f in findings)
            self.assertIn("hello.txt", detail)

    def test_cloaked_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "cloaked.zip")
            make_cloaked_archive(archive)
            findings = zip_cloaking.scan_zip_headers(archive)
            self.assertTrue(any(f["status"] == "CLOAKED" for f in findings))
            detail = " ".join(f["detail"] for f in findings)
            self.assertIn("doc_report.pdf", detail)
            self.assertIn("cron_worker.sh", detail)
            # Nothing was extracted: no cron_worker.sh file appeared.
            self.assertFalse(os.path.exists(os.path.join(tmp, "cron_worker.sh")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "doc_report.pdf")))

    def test_malformed_is_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.zip")
            with open(bad, "wb") as handle:
                handle.write(b"this is not a zip archive at all, just text")
            with self.assertRaises(zip_cloaking.ScanError):
                zip_cloaking.scan_zip_headers(bad)

    def test_missing_file_is_error(self):
        with self.assertRaises(zip_cloaking.ScanError):
            zip_cloaking.scan_zip_headers("/nonexistent/nope.zip")


class TestCli(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, SCRIPT, *args],
            capture_output=True, text=True, timeout=60)

    def test_help(self):
        result = self.run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("CVE-2026-115905", result.stdout)

    def test_no_args_is_error(self):
        result = self.run_cli()
        self.assertEqual(result.returncode, 1)

    def test_benign_cli_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "benign.zip")
            make_benign_archive(archive)
            result = self.run_cli("--zip", archive)
            self.assertEqual(result.returncode, 0)
            self.assertIn("verdict: CLEAN", result.stdout)

    def test_cloaked_cli_vulnerable(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "cloaked.zip")
            make_cloaked_archive(archive)
            result = self.run_cli("--zip", archive)
            self.assertEqual(result.returncode, 2)
            self.assertIn("verdict: VULNERABLE", result.stdout)
            self.assertIn("CLOAKED", result.stdout)

    def test_lock_cli_vulnerable_and_fixed(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = os.path.join(tmp, "Cargo.lock")
            make_cargo_lock(old, "9.0.4")
            result = self.run_cli("--cargo-lock", old)
            self.assertEqual(result.returncode, 2)
            new = os.path.join(tmp, "Cargo2.lock")
            make_cargo_lock(new, "9.0.5")
            result = self.run_cli("--cargo-lock", new)
            self.assertEqual(result.returncode, 0)

    def test_malformed_cli_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, "bad.zip")
            with open(bad, "wb") as handle:
                handle.write(b"not a zip")
            result = self.run_cli("--zip", bad)
            self.assertEqual(result.returncode, 1)

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "benign.zip")
            make_benign_archive(archive)
            result = self.run_cli("--zip", archive, "--json")
            self.assertEqual(result.returncode, 0)
            self.assertIn('"verdict": "CLEAN"', result.stdout)


if __name__ == "__main__":
    unittest.main()
