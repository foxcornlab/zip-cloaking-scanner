# `zip-cloaking-scanner`

Detection-only triage scanner for `Rust` zip cloaking, `CVE-2026-115905`. It checks whether a project depends on a vulnerable `zip` crate, and whether a `ZIP` archive hides a different filename in its `Local` header than in its `Central` directory. It never exploits anything.

## `The flaw`

| `Detail` | `Value` |
| --- | --- |
| `CVE` | `CVE-2026-115905` |
| `Advisory` | `GHSA-m665-v7pm-7grj` (`zip-rs/zip2`) |
| `Bug` | `Central` vs `Local` header filename mismatch (`CWE-436`), `Zip` cloaking |
| `Impact` | `Security` control bypass, arbitrary file overwrite, possible `RCE` |
| `Severity` | `10.0 / 9.9` critical, as listed in the advisory |

`ZipArchive` reads filenames from the `Central Directory File Header` (`CDFH`) and ignores the `Local File Header` (`LFH`). `ZipStreamReader` does the opposite: it extracts using the `LFH` filename without reconciling it with the `CDFH`. A crafted archive can therefore pass a `CDFH`-first gateway inspection looking benign, then write a different attacker-selected path when a streaming extractor runs.

The advisory's own `PoC` test makes it concrete: `CDFH` says `doc_report.pdf`, `LFH` says `cron_worker.sh`, the gateway approves the `PDF`, streaming extraction overwrites `cron_worker.sh`.

## `Fixed versions`

| `Branch` | `Status` |
| --- | --- |
| `zip <= 9.0.4` | `Vulnerable` |
| `zip >= 9.0.5` | `Fixed` |

Updating the `zip` dependency to `9.0.5` or newer is the fix. If an immediate upgrade is impossible, do not run `ZipStreamReader` on untrusted archives, and make gateways validate both headers before extraction.

## `What it checks`

- `Cargo.lock` for a `zip` package at or below `9.0.4` (`vulnerable`) versus `9.0.5` and above (`fixed`). `Cargo.lock` pins the exact resolved version, so it is authoritative when present.
- `Cargo.toml` for a `zip` dependency requirement, graded on the minimum version token found. `TOML` requirements are ranges, so treat this as a hint and confirm with the lockfile.
- `ZIP` archives, header only: it parses every `Central Directory` entry and reads the matching `Local File Header` by offset, then compares the two filenames byte for byte. A mismatch is flagged `CLOAKED`, a full match is `CLEAN`.

## `What it never does`

No payloads. No exploitation. No extraction to disk: payload bytes are never read and extracted files are never written, so a cloaked archive cannot overwrite anything through this tool. It only reads headers and dependency files you point it at.

## `Grading`

| `Finding` | `Severity` |
| --- | --- |
| `zip <= 9.0.4`, or any `CDFH`/`LFH` filename mismatch | `VULNERABLE` |
| `zip >= 9.0.5` and clean headers | `CLEAN` |
| No `zip` version found and no archive given a verdict | `UNKNOWN`, not vulnerable |
| Unreadable or malformed input | `ERROR`, not clean |

## `Usage`

```
# Cargo dependency check
python3 zip_cloaking.py --cargo-lock Cargo.lock
python3 zip_cloaking.py --cargo-toml Cargo.toml

# ZIP header check (headers only, nothing extracted)
python3 zip_cloaking.py --zip suspicious.zip

# Both checks, machine-readable output
python3 zip_cloaking.py --cargo-lock Cargo.lock --zip suspicious.zip --json
```

Exit codes: `0` = clean or unknown, `2` = vulnerable finding, `1` = scan error.

## `Honest caveats`

- A public `PoC` exists, in the advisory itself. Wild exploitation is not confirmed. This scanner does triage, not proof of exploitability.
- A version check alone does not prove a project is exploitable: the risk needs a `CDFH`-first inspector feeding a `ZipStreamReader` extractor, or a similar decoupled pipeline. A header mismatch alone does not prove compromise either, only that the archive is cloaked and must not be trusted.
- `ZIP64` archives are supported and graded like standard archives: saturated `EOCD` fields are resolved via the `ZIP64` record and locator, and saturated per-entry fields via the `ZIP64` extra field. Malformed or truncated `ZIP64` structures are still reported as errors, not clean.
- `Cargo.toml` requirements are ranges. Grade the lockfile when you have it.

## `References`

- `GHSA-m665-v7pm-7grj` (`zip-rs/zip2` advisory, mechanism and `PoC` test)
- `CVE-2026-115905` record (published `2026-10-26`, affected through `9.0.4`, fixed in `9.0.5`)

## `Thanks to`

- The `zip-rs` maintainers for the advisory and the `9.0.5` fix
- `ByGh00st` and `Pr0methean`, credited in the disclosure for the fix and review
- Everyone publishing `ZIP` parser-differential research

## `Disclaimer`

Built for defensive triage and authorized testing only. Scan only systems and files you own or are authorized to test. The authors are not responsible for misuse.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
