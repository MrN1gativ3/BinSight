# Binsight

`binsight` is a small C disassembler/inspector built on top of `libbfd` and `libopcodes`. It targets ELF and PE-family binaries and is intended to make reverse-engineering, debugging, and malware triage workflows easier by showing:

- high-level binary metadata
- file hashes and quick identity data:
  linkage style, loader/interpreter, UPX packed identity, broader packer/protector hints, and a best-effort language guess
- dependency summaries:
  ELF `DT_NEEDED` / `SONAME` / `RPATH` / `RUNPATH`, plus PE import and delay-import summaries when present
- extracted strings:
  ASCII plus native-endian UTF-16 strings from non-code sections, with file offsets
- raw byte inspection:
  hex + ASCII view over arbitrary file offsets, including malformed binaries
- raw byte search:
  exact ASCII, UTF-16, and hex-pattern search across the whole file
- hardening and loader context:
  ELF PIE/NX/RELRO/canary/FORTIFY/TLS hints, plus PE ASLR/NX/CFG/TLS/subsystem/CLR hints
- provenance hints:
  ELF build-id/debuglink/compiler comments and PE timestamp/Rich header/Authenticode/PDB hints
- PE resource parsing:
  leaf-level resource enumeration with type/id/language/size/offset details
- machine-readable report output:
  JSON and NDJSON for report-backed views
- native format header details for ELF and PE files
- detailed section-header information
- disassembly for executable sections
- overlay and embedded payload analysis:
  appended-data sizing, entropy, CRC32, and simple embedded magic-signature hints
- malware-oriented section triage:
  entropy, CRC32, entry-point mapping, suspicious section-name matches, writable+executable section detection, and suspicious API/function clues from symbols
- packer/protector hinting:
  conservative markers for common packers, protectors, bundlers, and packed-payload heuristics with evidence and confidence labels
- safe byte patching:
  apply explicit offset-based hex edits and write a patched copy without touching the source file
- common UPX repair workflow support for damaged packed samples:
  restore common anti-UPX tampering in ELF and PE files so the sample can be unpacked with normal UPX tooling later

## Requirements

- a C compiler
- Binutils development headers and libraries

On Ubuntu/Debian:

```sh
sudo apt-get install binutils-dev
```

## Build

```sh
make
```

## Usage

```sh
./binsight /path/to/binary
```

Focused commands:

- `./binsight inspect /path/to/binary`: full output; same as the default mode
- `./binsight fileinfo /path/to/binary`: file overview, hashes, linkage, loader, packer/protector hints, and language guess
- `./binsight imports /path/to/binary`: overview plus import/dependency summary
- `./binsight headers /path/to/binary`: overview plus native ELF/PE headers
- `./binsight triage /path/to/binary`: overview plus malware triage
- `./binsight security /path/to/binary`: overview plus hardening and loader context
- `./binsight provenance /path/to/binary`: overview plus signature/provenance hints
- `./binsight resources /path/to/binary`: overview plus PE resource summary
- `./binsight overlay /path/to/binary`: overview plus overlay and embedded payload hints
- `./binsight sections /path/to/binary`: overview plus section headers
- `./binsight strings /path/to/binary`: overview plus extracted strings
- `./binsight disasm /path/to/binary`: overview plus disassembly
- `./binsight hex /path/to/binary`: raw hex + ASCII view
- `./binsight search /path/to/binary`: raw byte-pattern and string search

Useful flags:

- `-n`, `--no-disasm`: skip disassembly in the default full inspection mode
- `-s`, `--section NAME`: restrict section, disassembly, or strings output to a specific section; repeat as needed
- `-a`, `--all-sections`: disassemble every matched section that has contents
- `-m`, `--min-string-len N`: minimum extracted string length; default `4`
- `--summary`, `--overview`: show only the file overview block
- `--imports`: show only the import/dependency block
- `--headers`: show only native ELF/PE header details
- `--triage`: show only the malware triage block
- `--sections`: show only section-header details
- `--strings`: show only extracted strings
- `--security`: show only hardening and loader context
- `--provenance`: show only signature/provenance hints
- `--resources`: show only PE resource summary
- `--overlay`: show only overlay and embedded payload hints
- `--disasm`: show only disassembly output
- `--hex`: show only raw hex + ASCII output
- `--search`: show only byte-pattern and string search results
- `--hex-start OFF`: start byte offset for hex view; accepts decimal or `0x...`
- `--hex-length N`: number of bytes to display in hex view; default `256`
- `--hex-width N`: bytes per hex row; default `16`
- `--find-ascii TEXT`: search for an exact ASCII/UTF-8 byte string
- `--find-utf16 TEXT`: search for UTF-16LE and UTF-16BE forms of a text literal; odd one-byte mirror hits are suppressed when they duplicate an even-aligned opposite-endian match
- `--find-hex HEXBYTES`: search for an exact byte pattern such as `4d5a90`
- `--max-search-hits N`: cap printed hits per search query; default `64`
- `--json`: emit one JSON document for report-backed views
- `--ndjson`: emit newline-delimited JSON records for report-backed views
- focused view flags are composable, for example `--summary --imports --security`
- `--patch OFFSET:HEXBYTES`: queue a byte patch such as `0x3c:9090`; repeat as needed
- `--patch-out OUT`: write the patched copy to `OUT`; required with `--patch`
- `--repair-upx OUT`: write a repaired UPX-packed ELF or PE to `OUT`
- `--repair-upx-elf OUT`: compatibility alias for `--repair-upx`
- `--repair-and-unpack-upx OUT`: repair first, then call external `upx -d` to write an unpacked file to `OUT`

UPX identity reporting:

- `fileinfo` and other overview-backed views now report whether a sample looks UPX-packed
- when the packed file still embeds a UPX release string, the tool reports that release identifier and normalizes compact forms such as `5.11` to `5.1.1`
- when an exact release string is not present, the tool still reports the UPX pack-header version and format so the analyst can distinguish older and newer packed layouts

Packer/protector hinting:

- `fileinfo`, `triage`, and JSON overview/triage output include `packer_protector_hints` when conservative markers are found
- supported hints include common packers/protectors such as UPX, ASPack, Themida, WinLicense, VMProtect, Enigma, MPRESS, PECompact, Petite, FSG, NsPack, kkrunchy, plus bundler/runtime markers such as PyInstaller, Nuitka, PyArmor, cx_Freeze, Go, and Rust
- each hint includes the family name, hint kind, confidence, and evidence string; low-confidence generic hints are heuristics, not verdicts

Current JSON/NDJSON scope:

- supported: overview, imports, triage, sections, strings, security, provenance, resources, overlay
- not yet supported: native header text dump, disassembly output, raw hex view, and raw search output

Examples:

```sh
./binsight /bin/ls
./binsight fileinfo /bin/ls
./binsight imports /bin/ls
./binsight triage /bin/ls
./binsight security /bin/ls
./binsight provenance /bin/ls
./binsight resources test/SteamSetup.exe
./binsight overlay test/SteamSetup.exe
./binsight headers /bin/ls
./binsight sections --section .text /bin/ls
./binsight strings --min-string-len 12 /bin/ls
./binsight hex --hex-start 0x200 --hex-length 128 /bin/ls
./binsight search --find-ascii ELF test/test-elf.packed.noelf
./binsight fileinfo --find-hex 4d5a test/SteamSetup.exe
./binsight --summary --imports --security --json /bin/ls
./binsight --summary --resources --overlay --json test/SteamSetup.exe
./binsight --imports --ndjson /bin/ls
./binsight --summary --triage /bin/ls
./binsight --no-disasm /usr/lib/shim/shimx64.efi
./binsight disasm --section .init /bin/ls
./binsight --patch 0x0:00 --patch-out sample.patched ./sample.bin
./binsight --repair-upx sample.fixed ./sample.corrupted
./binsight --repair-and-unpack-upx sample.unpacked ./sample.corrupted
```

## Notes On UPX Repair

The UPX repair mode is intentionally scoped to common anti-unpacking tampering seen in UPX-packed ELF and PE samples. It is not a generic executable reconstruction engine.

The ELF repair logic is modeled around the anti-UPX pattern described by JPCERT/CC: the sample keeps a valid UPX-packed ELF layout, but changes `l_info.l_magic` away from `UPX!` and sometimes also zeroes `p_info.p_filesize` and `p_info.p_blocksize`. Some samples also corrupt the leading ELF magic or append junk bytes after the trailing UPX pack header.

The PE repair logic targets the common Windows anti-UPX cases where malware changes the UPX section names and/or tampers with the pack-header magic near the second section's raw data. The tool validates the same small-section-layout assumptions the official UPX unpacker uses before applying PE repairs.

Current repair coverage:

- restored ELF magic if only the leading magic bytes were removed
- restored ELF magic for validated real UPX-packed ELF files even when the inline loader metadata is not stored immediately after the program-header table
- restored `l_info.l_magic` / `UPX!`
- restored the trailing UPX `PackHeader` magic when it was tampered with
- restored `p_info.p_filesize` and `p_info.p_blocksize` from the trailing UPX pack header metadata
- trimmed trailing overlay bytes after the final UPX pack header
- recomputed the trailing UPX pack-header checksum for newer header versions
- rejected non-plausible trailing header candidates instead of trying to "repair" ordinary ELF files
- restored PE `UPX0` / `UPX1` section names in validated UPX-like PE layouts
- restored PE pack-header magic in the official UPX scan window used by the unpacker

Important limits:

- it is best-effort, not guaranteed for every custom-packed sample
- full ELF metadata repair still prefers samples whose UPX loader metadata can be located from the program-header layout; other ELF layouts currently fall back to the safer "restore ELF magic only after validating a trailing UPX pack header" path
- it targets common anti-UPX header tampering, not arbitrary byte-level corruption
- the PE repair path is intentionally conservative and only accepts small UPX-like PE layouts instead of trying to rewrite arbitrary PE files
- `--repair-and-unpack-upx` depends on an external `upx` binary being installed and available in `PATH`

Version-matrix notes from `test/`:

- the bundled matrix runner is `test/run_upx_version_matrix.sh`
- the latest matrix log is `test/UPX_VERSION_MATRIX_2026-05-15.md`
- `test/` now mirrors the full official amd64 Linux release set that GitHub currently publishes for UPX, from `3.91` through `5.1.1`
- in local testing, `binsight` successfully repaired every produced sample from the real ELF and PE fixtures across UPX `3.94` through `5.1.1`
- UPX `3.91`, `3.92`, and `3.93` still repaired the PE EXE fixture correctly, but those historical packers did not reliably produce the supplied ELF test sample in this environment, so those ELF rows are logged as packer-side test gaps rather than repair failures
- the forced `ntdll.dll` packing path only became available starting with UPX `3.96`; where that DLL packed successfully, repair also succeeded
