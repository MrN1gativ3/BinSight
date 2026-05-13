# Binsight

`binsight` is a small C disassembler/inspector built on top of `libbfd` and `libopcodes`. It targets ELF and PE-family binaries and is intended to make reverse-engineering, debugging, and malware triage workflows easier by showing:

- high-level binary metadata
- file hashes and quick identity data:
  linkage style, loader/interpreter, and a best-effort language guess
- dependency summaries:
  ELF `DT_NEEDED` / `SONAME` / `RPATH` / `RUNPATH`, plus PE import and delay-import summaries when present
- extracted strings:
  ASCII, UTF-16LE, and UTF-16BE file strings with file offsets
- hardening and loader context:
  ELF PIE/NX/RELRO/canary/FORTIFY/TLS hints, plus PE ASLR/NX/CFG/TLS/subsystem/CLR hints
- provenance hints:
  ELF build-id/debuglink/compiler comments and PE timestamp/Rich header/Authenticode/PDB hints
- machine-readable report output:
  JSON and NDJSON for report-backed views
- native format header details for ELF and PE files
- detailed section-header information
- disassembly for executable sections
- malware-oriented section triage:
  entropy, CRC32, entry-point mapping, suspicious section-name matches, writable+executable section detection, and suspicious API/function clues from symbols
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
- `./binsight fileinfo /path/to/binary`: file overview, hashes, linkage, loader, and language guess
- `./binsight imports /path/to/binary`: overview plus import/dependency summary
- `./binsight headers /path/to/binary`: overview plus native ELF/PE headers
- `./binsight triage /path/to/binary`: overview plus malware triage
- `./binsight security /path/to/binary`: overview plus hardening and loader context
- `./binsight provenance /path/to/binary`: overview plus signature/provenance hints
- `./binsight sections /path/to/binary`: overview plus section headers
- `./binsight strings /path/to/binary`: overview plus extracted strings
- `./binsight disasm /path/to/binary`: overview plus disassembly

Useful flags:

- `-n`, `--no-disasm`: skip disassembly in the default full inspection mode
- `-s`, `--section NAME`: restrict output to a specific section; repeat as needed
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
- `--disasm`: show only disassembly output
- `--json`: emit one JSON document for report-backed views
- `--ndjson`: emit newline-delimited JSON records for report-backed views
- focused view flags are composable, for example `--summary --imports --security`
- `--repair-upx OUT`: write a repaired UPX-packed ELF or PE to `OUT`
- `--repair-upx-elf OUT`: compatibility alias for `--repair-upx`
- `--repair-and-unpack-upx OUT`: repair first, then call external `upx -d` to write an unpacked file to `OUT`

Current JSON/NDJSON scope:

- supported: overview, imports, triage, sections, strings, security, provenance
- not yet supported: native header text dump and disassembly output

Examples:

```sh
./binsight /bin/ls
./binsight fileinfo /bin/ls
./binsight imports /bin/ls
./binsight triage /bin/ls
./binsight security /bin/ls
./binsight provenance /bin/ls
./binsight headers /bin/ls
./binsight sections --section .text /bin/ls
./binsight strings --min-string-len 12 /bin/ls
./binsight --summary --imports --security --json /bin/ls
./binsight --imports --ndjson /bin/ls
./binsight --summary --triage /bin/ls
./binsight --no-disasm /usr/lib/shim/shimx64.efi
./binsight disasm --section .init /bin/ls
./binsight --repair-upx sample.fixed ./sample.corrupted
./binsight --repair-and-unpack-upx sample.unpacked ./sample.corrupted
```

## Notes On UPX Repair

The UPX repair mode is intentionally scoped to common anti-unpacking tampering seen in UPX-packed ELF and PE samples. It is not a generic executable reconstruction engine.

The ELF repair logic is modeled around the anti-UPX pattern described by JPCERT/CC: the sample keeps a valid UPX-packed ELF layout, but changes `l_info.l_magic` away from `UPX!` and sometimes also zeroes `p_info.p_filesize` and `p_info.p_blocksize`. Some samples also corrupt the leading ELF magic or append junk bytes after the trailing UPX pack header.

The PE repair logic targets the common Windows anti-UPX cases where malware changes the UPX section names and/or tampers with the pack-header magic near the second section's raw data. The tool validates the same small-section-layout assumptions the official UPX unpacker uses before applying PE repairs.

Current repair coverage:

- restored ELF magic if only the leading magic bytes were removed
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
- it assumes the binary still contains enough intact ELF program-header data to locate UPX loader metadata
- it targets common anti-UPX header tampering, not arbitrary byte-level corruption
- the PE repair path is intentionally conservative and only accepts small UPX-like PE layouts instead of trying to rewrite arbitrary PE files
- `--repair-and-unpack-upx` depends on an external `upx` binary being installed and available in `PATH`
