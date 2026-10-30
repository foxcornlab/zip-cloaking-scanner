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


def make_zip64_force_archive(path):
    """One file written with force_zip64 (ZIP64 extra in the local header)."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        with archive.open("hello.txt", "w", force_zip64=True) as handle:
            handle.write(b"hello\n")


def _rewrite_to_zip64(src, dst):
    """Rewrite a standard archive as a full ZIP64 archive.

    Every central entry gets saturated size/offset fields resolved by a
    ZIP64 extra field (0x0001), and the standard EOCD is replaced by a
    ZIP64 EOCD record plus locator plus a saturated standard EOCD.
    Local headers and their offsets are unchanged, so the rewrite only
    changes how the directory describes the same files.
    """
    import struct
    with open(src, "rb") as handle:
        data = handle.read()
    eocd_at = data.rfind(b"PK\x05\x06")
    assert eocd_at >= 0, "no EOCD in base archive"
    eocd = struct.unpack("<IHHHHIIH", data[eocd_at:eocd_at + 22])
    cd_offset, cd_size, entries = eocd[6], eocd[5], eocd[4]
    prefix = data[:cd_offset]
    cd = data[cd_offset:cd_offset + cd_size]
    new_cd = bytearray()
    pos = 0
    while pos < len(cd):
        fields = list(struct.unpack("<IHHHHHHIIIHHHHHII",
                                    cd[pos:pos + 46]))
        fname_len, extra_len, comment_len = fields[10], fields[11], fields[12]
        fname_start = pos + 46
        fname = cd[fname_start:fname_start + fname_len]
        extra_start = fname_start + fname_len
        extra = cd[extra_start:extra_start + extra_len]
        comment_start = extra_start + extra_len
        comment = cd[comment_start:comment_start + comment_len]
        real_comp, real_uncomp, real_local = fields[8], fields[9], fields[16]
        zip64_data = struct.pack("<QQQ", real_uncomp, real_comp, real_local)
        zip64_extra = struct.pack("<HH", 0x0001, len(zip64_data)) + zip64_data
        new_extra = extra + zip64_extra
        fields[8] = 0xFFFFFFFF
        fields[9] = 0xFFFFFFFF
        fields[11] = len(new_extra)
        fields[16] = 0xFFFFFFFF
        new_cd += struct.pack("<IHHHHHHIIIHHHHHII", *fields)
        new_cd += fname + new_extra + comment
        pos += 46 + fname_len + extra_len + comment_len
    new_cd_size = len(new_cd)
    zip64_eocd_offset = cd_offset + new_cd_size
    zip64_eocd = struct.pack("<IQHHIIQQQQ", 0x06064b50, 44, 45, 45,
                             0, 0, entries, entries, new_cd_size, cd_offset)
    locator = struct.pack("<IIQI", 0x07064b50, 0, zip64_eocd_offset, 1)
    eocd_new = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0)
    with open(dst, "wb") as handle:
        handle.write(prefix + bytes(new_cd) + zip64_eocd + locator + eocd_new)


def _saturate_eocd(src, dst):
    """Keep central entries standard, saturate only the EOCD.

    Exercises the ZIP64 EOCD record + locator path without per-entry
    ZIP64 extras.
    """
    import struct
    with open(src, "rb") as handle:
        data = handle.read()
    eocd_at = data.rfind(b"PK\x05\x06")
    assert eocd_at >= 0, "no EOCD in base archive"
    eocd = struct.unpack("<IHHHHIIH", data[eocd_at:eocd_at + 22])
    cd_offset, cd_size, entries = eocd[6], eocd[5], eocd[4]
    zip64_eocd = struct.pack("<IQHHIIQQQQ", 0x06064b50, 44, 45, 45,
                             0, 0, entries, entries, cd_size, cd_offset)
    locator = struct.pack("<IIQI", 0x07064b50, 0, eocd_at, 1)
    eocd_new = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, 0xFFFF, 0xFFFF,
                           0xFFFFFFFF, 0xFFFFFFFF, 0)
    with open(dst, "wb") as handle:
        handle.write(data[:eocd_at] + zip64_eocd + locator + eocd_new)


def make_full_zip64_archive(path, cloaked=False):
    base = path + ".base"
    if cloaked:
        make_cloaked_archive(base)
    else:
        make_benign_archive(base)
    try:
        _rewrite_to_zip64(base, path)
    finally:
        if os.path.exists(base):
            os.remove(base)


def make_saturated_eocd_archive(path, cloaked=False):
    base = path + ".base"
    if cloaked:
        make_cloaked_archive(base)
    else:
        make_benign_archive(base)
    try:
        _saturate_eocd(base, path)
    finally:
        if os.path.exists(base):
            os.remove(base)


class TestZip64(unittest.TestCase):
    def test_force_zip64_benign_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "z64.zip")
            make_zip64_force_archive(archive)
            findings = zip_cloaking.scan_zip_headers(archive)
            self.assertTrue(findings)
            self.assertTrue(all(f["status"] == "CLEAN" for f in findings))
            detail = " ".join(f["detail"] for f in findings)
            self.assertIn("hello.txt", detail)

    def test_full_zip64_benign_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "z64full.zip")
            make_full_zip64_archive(archive)
            with open(archive, "rb") as handle:
                raw = handle.read()
            # Guard: this really is a ZIP64 archive, not a standard one.
            self.assertIn(b"PK\x06\x06", raw)
            self.assertIn(b"PK\x06\x07", raw)
            findings = zip_cloaking.scan_zip_headers(archive)
            self.assertTrue(findings)
            self.assertTrue(all(f["status"] == "CLEAN" for f in findings))
            detail = " ".join(f["detail"] for f in findings)
            self.assertIn("hello.txt", detail)

    def test_full_zip64_cloaked_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "z64cloaked.zip")
            make_full_zip64_archive(archive, cloaked=True)
            findings = zip_cloaking.scan_zip_headers(archive)
            self.assertTrue(any(f["status"] == "CLOAKED" for f in findings))
            detail = " ".join(f["detail"] for f in findings)
            self.assertIn("doc_report.pdf", detail)
            self.assertIn("cron_worker.sh", detail)
            self.assertFalse(os.path.exists(os.path.join(tmp, "cron_worker.sh")))
            self.assertFalse(os.path.exists(os.path.join(tmp, "doc_report.pdf")))

    def test_saturated_eocd_only_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "sat.zip")
            make_saturated_eocd_archive(archive)
            findings = zip_cloaking.scan_zip_headers(archive)
            self.assertTrue(findings)
            self.assertTrue(all(f["status"] == "CLEAN" for f in findings))
            detail = " ".join(f["detail"] for f in findings)
            self.assertIn("hello.txt", detail)

    def test_saturated_eocd_only_cloaked(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "satcloaked.zip")
            make_saturated_eocd_archive(archive, cloaked=True)
            findings = zip_cloaking.scan_zip_headers(archive)
            self.assertTrue(any(f["status"] == "CLOAKED" for f in findings))

    def test_truncated_zip64_is_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "trunc.zip")
            make_full_zip64_archive(archive)
            # Cut the file inside the ZIP64 EOCD record region.
            with open(archive, "r+b") as handle:
                handle.truncate(os.path.getsize(archive) - 30)
            with self.assertRaises(zip_cloaking.ScanError):
                zip_cloaking.scan_zip_headers(archive)


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

    def test_zip64_cli_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "z64.zip")
            make_full_zip64_archive(archive)
            result = self.run_cli("--zip", archive)
            self.assertEqual(result.returncode, 0)
            self.assertIn("verdict: CLEAN", result.stdout)

    def test_zip64_cli_cloaked(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "z64cloaked.zip")
            make_full_zip64_archive(archive, cloaked=True)
            result = self.run_cli("--zip", archive)
            self.assertEqual(result.returncode, 2)
            self.assertIn("verdict: VULNERABLE", result.stdout)
            self.assertIn("CLOAKED", result.stdout)

    def test_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            archive = os.path.join(tmp, "benign.zip")
            make_benign_archive(archive)
            result = self.run_cli("--zip", archive, "--json")
            self.assertEqual(result.returncode, 0)
            self.assertIn('"verdict": "CLEAN"', result.stdout)


if __name__ == "__main__":
    unittest.main()
