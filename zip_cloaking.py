#!/usr/bin/env python3
"""Detection-only triage scanner for Rust zip cloaking, CVE-2026-115905.

Two checks, no payloads, no exploitation, no extraction to disk:

1. Cargo check: scan Cargo.lock / Cargo.toml for a `zip` dependency at or
   below 9.0.4 (vulnerable) versus 9.0.5 and above (fixed).
2. ZIP header check: parse a ZIP file's Central Directory entries and Local
   File Header entries without extracting any payload, and compare filenames
   entry by entry. A Central vs Local filename mismatch is flagged CLOAKED.
   ZIP64 archives are graded the same way: saturated EOCD fields are
   resolved via the ZIP64 EOCD record and locator, and saturated per-entry
   fields via the ZIP64 extra field (0x0001).

The flaw (GHSA-m665-v7pm-7grj): ZipArchive reads filenames from the Central
Directory File Header (CDFH) and ignores the Local File Header (LFH), while
ZipStreamReader extracts using the LFH filename without reconciling them. A
crafted archive can therefore look benign to a CDFH-first inspector but write
a different attacker-selected path on streaming extraction.

Exit codes: 0 = clean or unknown, 2 = vulnerable finding, 1 = scan error.
A vulnerable finding outranks an error in the verdict, so a bad file never
hides a vulnerable one; a pure error with no vulnerable finding exits 1.

This tool reads archive headers only. It never writes extracted files to disk.
"""

import argparse
import json
import os
import re
import struct
import sys

VULNERABLE_MAX = (9, 0, 4)
FIXED_MIN = (9, 0, 5)

EOCD_SIG = b"PK\x05\x06"
CENTRAL_SIG = b"PK\x01\x02"
LOCAL_SIG = b"PK\x03\x04"
ZIP64_EOCD_SIG = b"PK\x06\x06"
ZIP64_LOCATOR_SIG = b"PK\x06\x07"

# Structs include the 4-byte signature, so field indices match the layout:
# EOCD: sig, disk, cd_disk, entries_disk, entries_total, cd_size,
#   cd_offset, comment_len (22 bytes).
# Central: sig, ver_made, ver_needed, flags, method, time, date, crc,
#   comp_size, uncomp_size, fname_len, extra_len, comment_len, disk_start,
#   int_attrs, ext_attrs, local_offset (46 bytes).
# Local: sig, ver_needed, flags, method, time, date, crc, comp_size,
#   uncomp_size, fname_len, extra_len (30 bytes).
EOCD_STRUCT = struct.Struct("<IHHHHIIH")
CENTRAL_STRUCT = struct.Struct("<IHHHHHHIIIHHHHHII")
LOCAL_STRUCT = struct.Struct("<IHHHHHIIIHH")
# ZIP64 End of Central Directory record (56 bytes, before any extensible
# data): sig, record size, version made by, version needed, disk number,
# disk with CD start, entries on this disk, entries total, CD size,
# CD offset.
ZIP64_EOCD_STRUCT = struct.Struct("<IQHHIIQQQQ")
# ZIP64 End of Central Directory locator (20 bytes): sig, disk with the
# ZIP64 EOCD record, offset of the ZIP64 EOCD record, total disks.
ZIP64_LOCATOR_STRUCT = struct.Struct("<IIQI")


class ScanError(Exception):
    """Raised for unreadable, missing, or malformed inputs (not a verdict)."""


class UsageError(Exception):
    """Raised for missing inputs (exit 1, not a verdict)."""


def parse_version(text):
    """Parse a dotted version into a tuple of ints, or None if unparseable.

    Strips requirement prefixes (^, ~, =, >=, <=) and pre-release/build
    suffixes, and takes the first dotted-numeric token found.
    """
    if text is None:
        return None
    match = re.search(r"(\d+(?:\.\d+)*)", str(text))
    if not match:
        return None
    parts = []
    for piece in match.group(1).split("."):
        try:
            parts.append(int(piece))
        except ValueError:
            return None
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def format_version(version):
    return ".".join(str(p) for p in version)


def grade_zip_version(version):
    """Grade a parsed zip version tuple. Returns VULNERABLE, FIXED, UNKNOWN."""
    if version is None:
        return "UNKNOWN"
    if version <= VULNERABLE_MAX:
        return "VULNERABLE"
    return "FIXED"


def scan_cargo_lock(path):
    """Scan a Cargo.lock for `zip` package entries.

    Returns a list of finding dicts. Cargo.lock is authoritative when present:
    it pins the exact resolved version, unlike Cargo.toml ranges.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        raise ScanError("cannot read Cargo.lock %s: %s" % (path, exc))
    findings = []
    # Split on [[package]] blocks; each block carries its own name/version.
    blocks = re.split(r"\[\[package\]\]", text)
    for block in blocks[1:]:
        name = re.search(r'^\s*name\s*=\s*"([^"]+)"', block, re.MULTILINE)
        version = re.search(r'^\s*version\s*=\s*"([^"]+)"', block, re.MULTILINE)
        if name and name.group(1) == "zip" and version:
            parsed = parse_version(version.group(1))
            status = grade_zip_version(parsed)
            findings.append({
                "check": "cargo-lock",
                "target": path,
                "detail": "zip %s" % version.group(1),
                "status": status,
            })
    if not findings:
        findings.append({
            "check": "cargo-lock",
            "target": path,
            "detail": "no zip dependency found",
            "status": "UNKNOWN",
        })
    return findings


def scan_cargo_toml(path):
    """Scan a Cargo.toml for a `zip` dependency requirement.

    Cargo.toml requirements are ranges, so the graded version is the minimum
    version token found in the requirement. When a Cargo.lock is available,
    prefer it: it pins the exact resolved version.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        raise ScanError("cannot read Cargo.toml %s: %s" % (path, exc))
    versions = []
    # zip = "9.0.4" and zip = { version = "9.0.4", ... } forms.
    for match in re.finditer(
        r'(?m)^\s*zip\s*=\s*(?:"([^"]+)"|\{\s*[^}]*?version\s*=\s*"([^"]+)")',
        text,
    ):
        raw = match.group(1) or match.group(2)
        parsed = parse_version(raw)
        if parsed is not None:
            versions.append((raw, parsed))
    findings = []
    for raw, parsed in versions:
        findings.append({
            "check": "cargo-toml",
            "target": path,
            "detail": "zip requirement %s (graded minimum %s)"
            % (raw, format_version(parsed)),
            "status": grade_zip_version(parsed),
        })
    if not findings:
        findings.append({
            "check": "cargo-toml",
            "target": path,
            "detail": "no zip dependency found",
            "status": "UNKNOWN",
        })
    return findings


def parse_zip64_extra(extra, comp_size, uncomp_size, local_offset,
                      disk_start, path, index):
    """Resolve saturated fields from a ZIP64 extra field (0x0001).

    The extra field carries values only for fields that were saturated, in
    the standard order: uncompressed size, compressed size, local header
    offset, disk start number. Values for unsaturated fields are absent,
    so they must not be consumed. Returns the resolved
    (comp_size, uncomp_size, local_offset, disk_start) tuple.
    """
    pos = 0
    while pos + 4 <= len(extra):
        header_id, data_size = struct.unpack_from("<HH", extra, pos)
        pos += 4
        if pos + data_size > len(extra):
            raise ScanError(
                "%s: truncated extra field at entry %d" % (path, index))
        data = extra[pos:pos + data_size]
        pos += data_size
        if header_id != 0x0001:
            continue
        cursor = 0

        def take(size, field_name):
            nonlocal cursor
            if cursor + size > len(data):
                raise ScanError(
                    "%s: truncated ZIP64 extra field at entry %d (%s)"
                    % (path, index, field_name))
            value = struct.unpack_from("<Q" if size == 8 else "<I",
                                       data, cursor)[0]
            cursor += size
            return value

        if uncomp_size == 0xFFFFFFFF:
            uncomp_size = take(8, "uncompressed size")
        if comp_size == 0xFFFFFFFF:
            comp_size = take(8, "compressed size")
        if local_offset == 0xFFFFFFFF:
            local_offset = take(8, "local header offset")
        if disk_start == 0xFFFF:
            disk_start = take(4, "disk start number")
    if pos != len(extra):
        raise ScanError(
            "%s: truncated extra field at entry %d" % (path, index))
    return comp_size, uncomp_size, local_offset, disk_start


def parse_zip64_eocd(handle, size, eocd_start, path):
    """Resolve a saturated standard EOCD via the ZIP64 EOCD record.

    The locator sits in the 20 bytes immediately before the standard EOCD
    and points at the ZIP64 EOCD record. Returns
    (entries_total, cd_size, cd_offset). Multi-disk archives are an error,
    not a clean verdict.
    """
    if eocd_start < ZIP64_LOCATOR_STRUCT.size:
        raise ScanError("%s: truncated ZIP64 locator" % path)
    handle.seek(eocd_start - ZIP64_LOCATOR_STRUCT.size)
    locator = handle.read(ZIP64_LOCATOR_STRUCT.size)
    if len(locator) < ZIP64_LOCATOR_STRUCT.size:
        raise ScanError("%s: truncated ZIP64 locator" % path)
    if locator[:4] != ZIP64_LOCATOR_SIG:
        raise ScanError("%s: missing ZIP64 locator" % path)
    (_sig, _disk, zip64_offset, _total_disks) = \
        ZIP64_LOCATOR_STRUCT.unpack(locator)
    if zip64_offset >= size or \
            zip64_offset + ZIP64_EOCD_STRUCT.size > size:
        raise ScanError("%s: ZIP64 record offset out of range" % path)
    handle.seek(zip64_offset)
    record = handle.read(ZIP64_EOCD_STRUCT.size)
    if len(record) < ZIP64_EOCD_STRUCT.size:
        raise ScanError("%s: truncated ZIP64 record" % path)
    if record[:4] != ZIP64_EOCD_SIG:
        raise ScanError("%s: bad ZIP64 record signature" % path)
    (_sig, _rec_size, _ver_made, _ver_needed, disk, cd_disk,
     _entries_disk, entries_total, cd_size, cd_offset) = \
        ZIP64_EOCD_STRUCT.unpack(record)
    if disk != 0 or cd_disk != 0:
        raise ScanError("%s: multi-disk ZIP64 archive not supported" % path)
    return entries_total, cd_size, cd_offset


def scan_zip_headers(path):
    """Compare CDFH vs LFH filenames for every entry, without extracting.

    Reads headers by seeking; payload bytes are never read and never written
    to disk. Returns a list of finding dicts, one per entry plus a summary
    finding when the archive is empty.
    """
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise ScanError("cannot stat %s: %s" % (path, exc))
    if size < EOCD_STRUCT.size:
        raise ScanError("%s: too small to be a ZIP archive" % path)
    try:
        handle = open(path, "rb")
    except OSError as exc:
        raise ScanError("cannot open %s: %s" % (path, exc))
    with handle:
        # Find the End of Central Directory record: last occurrence in the
        # trailing chunk (comment can be up to 64 KiB).
        tail_start = max(0, size - (65557 + EOCD_STRUCT.size))
        handle.seek(tail_start)
        tail = handle.read()
        offset = tail.rfind(EOCD_SIG)
        if offset < 0:
            raise ScanError("%s: no End of Central Directory record" % path)
        eocd = tail[offset:offset + EOCD_STRUCT.size]
        if len(eocd) < EOCD_STRUCT.size:
            raise ScanError("%s: truncated End of Central Directory" % path)
        (_sig, _disk, _cd_disk, entries_disk, entries_total, cd_size,
         cd_offset, _comment_len) = EOCD_STRUCT.unpack(eocd)
        # Any saturated EOCD field means the real values live in the ZIP64
        # record; resolve them instead of rejecting the archive.
        if (entries_disk == 0xFFFF or entries_total == 0xFFFF
                or cd_size == 0xFFFFFFFF or cd_offset == 0xFFFFFFFF):
            eocd_start = tail_start + offset
            entries_total, cd_size, cd_offset = parse_zip64_eocd(
                handle, size, eocd_start, path)
        if cd_offset >= size:
            raise ScanError(
                "%s: central directory offset out of range" % path)
        findings = []
        handle.seek(cd_offset)
        for index in range(entries_total):
            header = handle.read(CENTRAL_STRUCT.size)
            if len(header) < CENTRAL_STRUCT.size:
                raise ScanError(
                    "%s: truncated central directory entry %d" % (path, index))
            if header[:4] != CENTRAL_SIG:
                raise ScanError(
                    "%s: bad central directory signature at entry %d"
                    % (path, index))
            fields = CENTRAL_STRUCT.unpack(header)
            comp_size = fields[8]
            uncomp_size = fields[9]
            fname_len = fields[10]
            extra_len = fields[11]
            comment_len = fields[12]
            disk_start = fields[13]
            local_offset = fields[16]
            central_name = handle.read(fname_len)
            if len(central_name) < fname_len:
                raise ScanError(
                    "%s: truncated central filename at entry %d" % (path, index))
            # Read the extra field (rather than skipping it) so a ZIP64
            # extra field can resolve saturated size/offset fields. This
            # is per entry, so standard and ZIP64 entries can mix.
            extra = handle.read(extra_len)
            if len(extra) < extra_len:
                raise ScanError(
                    "%s: truncated central extra field at entry %d"
                    % (path, index))
            (_comp, _uncomp, local_offset, disk_start) = parse_zip64_extra(
                extra, comp_size, uncomp_size, local_offset, disk_start,
                path, index)
            if disk_start != 0:
                raise ScanError(
                    "%s: multi-disk archive not supported at entry %d"
                    % (path, index))
            # Skip the comment to reach the next entry.
            handle.seek(comment_len, os.SEEK_CUR)
            if local_offset >= size:
                raise ScanError(
                    "%s: local header offset out of range at entry %d"
                    % (path, index))
            # Read the Local File Header for this entry directly by offset.
            saved = handle.tell()
            try:
                handle.seek(local_offset)
                local = handle.read(LOCAL_STRUCT.size)
                if len(local) < LOCAL_STRUCT.size:
                    raise ScanError(
                        "%s: truncated local header at entry %d" % (path, index))
                if local[:4] != LOCAL_SIG:
                    raise ScanError(
                        "%s: bad local header signature at entry %d"
                        % (path, index))
                local_fields = LOCAL_STRUCT.unpack(local)
                local_fname_len = local_fields[9]
                local_name = handle.read(local_fname_len)
                if len(local_name) < local_fname_len:
                    raise ScanError(
                        "%s: truncated local filename at entry %d"
                        % (path, index))
            finally:
                handle.seek(saved)
            if central_name == local_name:
                findings.append({
                    "check": "zip-headers",
                    "target": path,
                    "detail": "entry %d: CDFH and LFH agree on %r"
                    % (index, central_name.decode("utf-8", "replace")),
                    "status": "CLEAN",
                })
            else:
                findings.append({
                    "check": "zip-headers",
                    "target": path,
                    "detail": "entry %d: CLOAKED, CDFH %r vs LFH %r"
                    % (index,
                       central_name.decode("utf-8", "replace"),
                       local_name.decode("utf-8", "replace")),
                    "status": "CLOAKED",
                })
        if not findings:
            findings.append({
                "check": "zip-headers",
                "target": path,
                "detail": "archive has no entries",
                "status": "CLEAN",
            })
    return findings


def run_checks(args):
    """Run all requested checks. Returns (verdict, findings, errors)."""
    findings = []
    errors = []
    inputs = []
    for path in args.cargo_lock:
        inputs.append(("lock", path))
    for path in args.cargo_toml:
        inputs.append(("toml", path))
    for path in args.cargo:
        if os.path.basename(path) == "Cargo.lock":
            inputs.append(("lock", path))
        else:
            inputs.append(("toml", path))
    for path in args.zip:
        inputs.append(("zip", path))
    if not inputs:
        raise UsageError(
            "no input given: pass --cargo-lock, --cargo-toml, --cargo, "
            "or --zip (see --help)")
    for kind, path in inputs:
        try:
            if kind == "lock":
                findings.extend(scan_cargo_lock(path))
            elif kind == "toml":
                findings.extend(scan_cargo_toml(path))
            else:
                findings.extend(scan_zip_headers(path))
        except ScanError as exc:
            errors.append(str(exc))
    vulnerable = [f for f in findings
                  if f["status"] in ("VULNERABLE", "CLOAKED")]
    if vulnerable:
        verdict = "VULNERABLE"
    elif errors:
        verdict = "ERROR"
    elif any(f["status"] in ("FIXED", "CLEAN") for f in findings):
        verdict = "CLEAN"
    else:
        verdict = "UNKNOWN"
    return verdict, findings, errors


class Parser(argparse.ArgumentParser):
    """ArgumentParser that exits 1 (not argparse's 2) on bad usage.

    Exit 2 is reserved for a vulnerable finding, so a usage error must not
    share it.
    """

    def error(self, message):
        self.print_usage(sys.stderr)
        print("%s: error: %s" % (self.prog, message), file=sys.stderr)
        raise SystemExit(1)


def main(argv=None):
    parser = Parser(
        description="Detection-only triage for Rust zip cloaking, "
        "CVE-2026-115905. No payloads, no extraction, no exploitation.")
    parser.add_argument("--cargo-lock", action="append", default=[],
                        help="Cargo.lock file to scan (repeatable)")
    parser.add_argument("--cargo-toml", action="append", default=[],
                        help="Cargo.toml file to scan (repeatable)")
    parser.add_argument("--cargo", action="append", default=[],
                        help="Cargo.lock or Cargo.toml file (repeatable)")
    parser.add_argument("--zip", action="append", default=[],
                        help="ZIP archive to header-check (repeatable)")
    parser.add_argument("--json", action="store_true",
                        help="print machine-readable JSON output")
    args = parser.parse_args(argv)
    try:
        verdict, findings, errors = run_checks(args)
    except UsageError as exc:
        print("error: %s" % exc, file=sys.stderr)
        parser.print_help(sys.stderr)
        return 1
    exit_code = {"VULNERABLE": 2, "ERROR": 1}.get(verdict, 0)
    if args.json:
        print(json.dumps({
            "verdict": verdict,
            "findings": findings,
            "errors": errors,
        }, indent=2))
    else:
        for finding in findings:
            print("[%s] %s %s: %s" % (
                finding["status"], finding["check"],
                finding["target"], finding["detail"]))
        for error in errors:
            print("[ERROR] %s" % error, file=sys.stderr)
        print("verdict: %s" % verdict)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
