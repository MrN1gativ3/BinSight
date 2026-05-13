# Binsight Internals

This document explains how `binsight` works internally so you can describe the tool to another engineer, reverse engineer, or malware analyst without reading the code line by line.

## What The Tool Is

`binsight` is a native C binary-inspection tool built on:

- `libbfd` for loading object/executable formats such as ELF and PE/COFF
- `libopcodes` for architecture-aware instruction disassembly
- built-in MD5 and SHA-256 helpers for whole-file fingerprints
- `zlib` for CRC32 calculation
- `libm` for entropy calculation

At a high level, it does seven jobs:

1. Open a binary and let `libbfd` identify its format and architecture.
2. Parse native ELF or PE headers directly for file-format-specific detail output.
3. Collect file-level metadata such as hashes, loader/linkage hints, dependency summaries, strings, hardening data, provenance hints, and a language guess.
4. Run a malware-triage pass over sections and symbols.
5. Serialize the analyst-facing report either as text, JSON, or NDJSON depending on the selected view.
6. Optionally disassemble executable sections.
7. Optionally repair a narrow class of anti-UPX ELF or PE tampering so the sample can be unpacked later.

The goal is to give more analyst-oriented context than a raw structural tool like `readelf`.

## Main Execution Flow

The execution path is straightforward:

1. `main()` calls `bfd_init()`.
2. Command-line options are parsed into `options_t`.
3. If `--repair-upx` / `--repair-upx-elf` or `--repair-and-unpack-upx` is selected, the tool runs the raw-byte UPX repair path in `upx_repair.c` and exits after writing the repaired or unpacked file.
4. Otherwise `inspect_binary()` opens the file with `bfd_openr()`.
5. `bfd_check_format_matches()` confirms that the file is an object/executable format that BFD understands.
6. `load_symbols()` loads either the regular symbol table or the dynamic symbol table.
7. `build_analysis_report()` walks every section and computes the higher-level analysis state, then enriches the report with whole-file hashes, dependency parsing, string extraction, hardening context, and provenance hints.
8. `print_native_header_details()` parses the raw file bytes directly and prints ELF-specific or PE-specific header details that BFD does not expose in this shape.
9. Output views are selected from CLI options:
   - default inspection prints overview, dependencies, native headers, malware triage, security, provenance, detailed section headers, and disassembly
   - focused commands such as `imports`, `security`, `provenance`, `sections`, or `strings` enable a smaller preset
   - focused switches such as `--imports`, `--security`, `--strings`, or `--sections` can be combined to print only the requested blocks
   - `--json` and `--ndjson` reuse the same report-backed views for machine-readable output
10. If the disassembly view is enabled, matching sections are disassembled with `disassemble_section()`.

## Important Data Structures

The implementation is centered around a few internal structs:

### `options_t`

Stores CLI state:

- whether all content sections should be disassembled
- whether UPX repair or repair+unpack mode is active
- whether the user explicitly selected focused output views
- whether JSON or NDJSON output is enabled
- the input file path
- the output path used by repair mode
- any repeated `--section` filters
- the minimum extracted string length
- the current output-view bitmask for overview, dependencies, native headers, triage, sections, strings, security, provenance, and disassembly

### `symbol_table_t`

Represents the symbol table loaded from BFD:

- `symbols`: array of `asymbol *`
- `count`: number of symbols
- `dynamic`: whether they came from the dynamic symbol table

### `section_symbol_table_t`

Used only during disassembly. It stores the subset of symbols that belong to one section so symbol labels can be printed in address order.

### `section_report_t`

This is the core per-section analysis object. It stores:

- BFD section pointer and section name
- VMA/LMA, size, raw size, file offset, alignment, flags
- entropy
- CRC32
- whether the section contains the entry point
- whether the section name looks suspicious
- whether the section is writable and executable
- whether the section is high entropy

### `analysis_report_t`

This is the full triage summary for the binary. It stores:

- all `section_report_t` entries
- the section containing the entry point
- the highest-entropy section
- file size
- trailing bytes after the last PE-mapped section
- counts of suspicious sections and imported/external symbols
- a shortlist of suspicious API/function clues
- whole-file CRC32 / MD5 / SHA-256
- linkage and loader/interpreter hints
- dependency summaries:
  ELF `DT_NEEDED` / `SONAME` / `RPATH` / `RUNPATH`, PE imports, PE delay imports, and PE export count
- extracted strings with file offsets and encoding class
- security context:
  ELF execution model, NX/RELRO/canary/FORTIFY/TLS hints, or PE subsystem/ASLR/NX/CFG/TLS/CLR hints
- provenance hints:
  ELF build-id/debuglink/compiler comments, or PE timestamp/Rich header/Authenticode/CodeView data
- a best-effort implementation-language guess

## File Loading And Format Detection

The tool does not parse ELF or PE headers manually. Instead it delegates format handling to `libbfd`.

The sequence is:

- `bfd_openr(path, NULL)` opens the file
- `bfd_check_format_matches(..., bfd_object, ...)` tells BFD to recognize the file
- BFD exposes:
  - target name
  - flavour
  - architecture and machine type
  - endianness
  - entry point
  - file flags
  - section list

This design is important because it means the tool does not need separate parsers for ELF and PE. BFD abstracts both behind the same API.

## Symbol Loading

`load_symbols()` first tries the normal symbol table:

- `bfd_get_symtab_upper_bound()`
- `bfd_canonicalize_symtab()`

If that does not yield symbols, it falls back to the dynamic symbol table:

- `bfd_get_dynamic_symtab_upper_bound()`
- `bfd_canonicalize_dynamic_symtab()`

Why this matters:

- full symbol tables help disassembly labels and source-line lookup
- dynamic or unresolved symbols help malware triage because imported APIs often describe capability

## Section Analysis Pipeline

`build_analysis_report()` walks the full BFD section list once and records both raw metadata and higher-level findings.

For each section it records:

- section index and name
- virtual and load addresses
- file offset
- size, raw size, compressed size
- relocation count
- line-number count
- alignment
- flags such as code/data/readonly/loadable

Then it derives additional fields:

- whether the section has contents
- whether the section is compressed
- whether the section contains the binary entry point
- whether the section name matches a suspicious-name heuristic
- whether the section is writable and executable

If the section has bytes on disk, the tool also reads the full section contents with `bfd_get_full_section_contents()`.

That content is used to compute:

- Shannon entropy
- CRC32 hash

## Entropy Calculation

Entropy is computed directly from the section bytes:

1. Count occurrences of all 256 byte values.
2. Convert counts into probabilities.
3. Apply Shannon entropy: `-sum(p * log2(p))`.

Interpretation:

- low entropy often means structured data, relocation tables, strings, or zero-heavy content
- high entropy can indicate compression, encryption, or packed payloads

Current heuristic:

- a section is flagged as high entropy if:
  - size is at least 512 bytes
  - entropy is at least `7.20` bits/byte

This is intentionally a heuristic, not a proof of packing.

## CRC32 Calculation

CRC32 is computed with `zlib` over the exact section contents.

Why it is useful:

- quick section fingerprinting
- comparing similar samples
- spotting changed payload sections even when structure is stable

It is not a cryptographic hash. It is a fast analyst convenience value.

## Malware-Triage Logic

The malware-oriented output is produced by `print_triage_report()`, but the real logic is built earlier in `build_analysis_report()` and `analyze_symbols()`.

### Current Heuristics

The triage report looks for:

- entry point landing in a non-code section
- entry point landing in writable code
- writable + executable sections
- unusually high-entropy sections
- suspicious section names
- suspicious imported/external API names
- PE trailing bytes after the last mapped section

### Suspicious Section Names

The tool matches section names against a small case-insensitive rule set, such as:

- `upx`
- `aspack`
- `themida`
- `vmp`
- `packed`
- `crypt`
- `stub`

These are packer or loader hints, not verdicts.

### Suspicious API / Function Clues

The symbol matcher is intentionally conservative.

It only checks symbols that look import-like or external, for example:

- undefined ELF symbols
- PE import-style names such as `__imp_*`

It then matches against capability-oriented names such as:

- `VirtualAlloc`
- `VirtualProtect`
- `WriteProcessMemory`
- `CreateRemoteThread`
- `LoadLibrary`
- `GetProcAddress`
- `socket`
- `connect`
- `dlopen`
- `dlsym`
- `mprotect`
- `mmap`
- `execve`
- `fork`

This keeps the signal higher than naive substring matching across every symbol.

### PE Trailing Bytes

For PE-family targets, the tool estimates how many bytes exist after the last mapped section on disk.

Why this matters:

- PE files may contain a certificate table after the mapped image
- malware can also append hidden data after the normal section layout

The tool reports the byte count, but it does not classify the data. The analyst still needs to decide whether the tail is expected certificate data or suspicious appended payload.

## Section Header Output

`print_sections()` prints the raw structural details plus the computed analyst fields.

In addition to standard metadata, each section now shows:

- entropy
- CRC32
- whether it contains the entry point

This is the bridge between low-level structure and triage interpretation.

## Disassembly Internals

Disassembly is handled by `disassemble_section()`.

The flow is:

1. Read the full section bytes with `bfd_get_full_section_contents()`.
2. Collect symbols belonging to the section with `collect_section_symbols()`.
3. Initialize a `disassemble_info` object.
4. Ask `libopcodes` for the correct decoder using:
   - architecture
   - endianness
   - machine type
5. Feed instructions to the decoder one address at a time.

### Why `disassemble_info` Matters

`disassemble_info` is the structure that connects the generic tool to the target-specific disassembler in `libopcodes`.

It stores:

- architecture and machine type
- section pointer
- symbol table
- memory-read callback
- address-print callback
- formatting callbacks
- the section byte buffer and its base address

### Instruction Rendering

For each instruction:

- the tool asks the target decoder how many bytes the instruction consumed
- prints the virtual address
- prints the raw bytes
- prints the decoded mnemonic and operands

If decoding fails, the tool falls back to a `.byte 0xXX` style line instead of crashing or stopping.

### Symbol Labels And Line Information

The tool also adds context where available:

- section-local symbol labels are printed when instruction addresses match symbol values
- `bfd_find_nearest_line()` is used when BFD has line/debug context

This improves readability during reverse engineering.

### Styled Print Callback

`libopcodes` on this system expects both standard and styled print callbacks to be valid. The tool uses:

- `fprintf`
- a custom `styled_fprintf()` wrapper

Without the styled callback, disassembly may crash on some Binutils builds.

## UPX Repair Internals

The UPX repair path is intentionally separate from the BFD inspection path. It uses raw byte parsing because anti-UPX samples may no longer be accepted by normal tooling until a few header fields are repaired.

The implementation is in [src/upx_repair.c](/home/mintman/Project/Binsight/src/upx_repair.c).

### Threat Model

This logic is designed around two common anti-UPX families:

- ELF samples that keep the UPX-packed layout but tamper with `l_info` / `p_info`
- PE samples that keep a UPX-like section layout but tamper with section names and/or the nearby UPX pack-header magic

This is important because it means the problem is usually not “rebuild the executable from scratch.” The problem is “repair a mostly intact packed sample so standard UPX tooling can recognize it again.”

### ELF Layout Recovery

`infer_elf_layout()` does not fully parse ELF. It only extracts the fields needed to locate the UPX loader metadata:

- ELF class
- ELF endianness
- ELF header size
- program-header table offset
- program-header entry size
- program-header count

From those values it computes:

- `l_info` offset = `e_phoff + e_phentsize * e_phnum`
- `p_info` offset = `l_info + 12`

That matches the anti-UPX detection model used in the JPCERT write-up for ELF32 and ELF64.

The parser also accepts a file whose first four bytes are no longer `0x7fELF` if the rest of the ELF identification bytes and header layout are still plausible. That is how the tool can repair a sample after its ELF magic has been blanked.

### PE Layout Recovery

`infer_pe_layout()` validates the minimal PE structures needed for safe UPX repair:

- DOS header and `e_lfanew`
- `PE\\0\\0` signature
- COFF machine and section count
- optional-header size and magic
- section table entries and raw-data bounds

Then the repair code maps the PE machine to the UPX format ID that the official unpacker expects, for example:

- `UPX_F_W32PE_I386`
- `UPX_F_W64PE_AMD64`

The PE path is intentionally conservative. It only accepts the small section-count profiles that UPX itself expects during unpacking instead of trying to repair arbitrary PE files.

### UPX Pack Header Recovery

After locating `l_info`, the tool reads its current 4-byte magic.

Then it searches backward from the end of the file for the trailing UPX pack header:

- first it looks for a normal `UPX!` marker
- if that is not present, it looks for the same 4-byte marker found in `l_info`

That second step matters because many anti-UPX samples replace both occurrences with the same custom value.

From the trailing header it extracts:

- pack-header version
- pack-header format
- unpacked file size

For newer pack-header versions, it also recomputes the trailing header checksum after repairs.

The trailing candidate is not accepted blindly. It must also:

- sit after the `l_info` / `p_info` loader metadata area
- match the `l_info` version and format bytes
- have a sane non-zero unpacked file size
- pass the pack-header checksum check for newer header versions

That validation is what keeps ordinary ELF files from being misidentified as anti-UPX samples.

For PE files, the logic follows the same scan window that UPX uses while unpacking:

- primary window near `section[1].rawdataptr - 64`
- fallback window near `section[2].rawdataptr` for older layouts

Inside that window the repair code scans for a plausible pack header by validating:

- UPX format ID matches the PE machine
- version is sane
- `u_len`, `c_len`, and `u_file_size` are plausible
- the newer header checksum is valid when present

That allows the tool to recover from a tampered PE pack-header magic without needing the original 4-byte marker.

### What Gets Repaired

`repair_upx_elf_buffer()` applies a narrow set of fixes:

- restore ELF magic at offset `0` if it was removed
- restore `l_info.l_magic` to `UPX!`
- restore the trailing pack-header magic to `UPX!`
- restore `p_info.p_filesize` and `p_info.p_blocksize` from the trailing UPX metadata
- trim bytes that appear after the final UPX pack header

The `p_info` writes now respect the ELF endianness, which matters for big-endian packed samples as well as the more common little-endian ones.

For PE, the current repair set is:

- restore the pack-header magic to `UPX!`
- restore the first two PE section names to `UPX0` and `UPX1`
- recompute the pack-header checksum for newer header versions

### UPX Version Handling

The tool records two different version signals:

- pack-header version from the trailing UPX metadata
- UPX release major version from an embedded `$Id: UPX ...` string when present

If release major `4` is detected, the tool skips the `p_info` size rewrite to stay aligned with known UPX 4 behavior.

### Why The Tool Does Not “Reconstruct Headers”

This mode is deliberately conservative.

It does not attempt to synthesize missing ELF program headers, rebuild section tables, or guess arbitrary corrupted fields. That would create a high risk of producing output that looks repaired but is structurally wrong.

Instead, it assumes the packed sample is still mostly intact and repairs the small set of fields that anti-UPX tampering commonly targets.

## Why This Is More Than `readelf`

`readelf` is excellent at structural reporting, but it does not directly provide this specific triage layer:

- per-section entropy
- per-section CRC32
- entry-point-to-section mapping in the analysis summary
- suspicious writable/executable section highlighting
- suspicious section-name highlighting
- import-capability clues from unresolved/import-like symbols
- PE trailing-byte reporting framed as analyst triage

So the value of `binsight` is not “can it print section headers.” The value is “can it tell an analyst what deserves attention first.”

## Current Limitations

The tool is intentionally small and does not yet do everything a full malware triage framework would do.

Current limitations:

- no import table reconstruction beyond what symbols reveal
- no string extraction
- no relocation interpretation beyond counts
- no control-flow graphing
- no decompiler layer
- no yara/scanning integration
- no generic unpacking or emulation beyond the narrow UPX/ELF repair flow
- no certificate parsing for PE trailing data

It is a focused static triage tool, not a full reverse-engineering suite.

## Good Ways To Extend It

If you want to make it more useful for malware work later, the next strong additions would be:

- import table summary grouped by DLL/library
- ASCII/UTF-16 string extraction by section
- detection of executable code hidden in non-code sections
- relocation and TLS callback reporting
- PE certificate parsing
- ELF interpreter / DT_NEEDED summary
- simple opcode pattern statistics
- yara rule integration
- JSON output mode for automation

## Short Explanation You Can Reuse

If you need to explain the tool quickly to someone else:

`binsight` uses libbfd to open ELF and PE binaries through one unified API, then builds an analyst-oriented report on top of the section table and symbol table. It also parses native ELF and PE headers directly so it can print header fields such as ELF program headers and PE data directories in a human-friendly way. It computes entropy and CRC32 for each section, identifies where the entry point lives, highlights suspicious section properties such as writable code or packer-like names, and uses unresolved/import-like symbols to infer risky capabilities such as process injection, runtime API resolution, or networking. For anti-UPX samples, it also has a narrow raw-byte repair mode that restores the UPX fields malware commonly tampers with in both ELF and PE files so the analyst can unpack the sample with standard tooling. If needed, it then passes executable sections into libopcodes for architecture-aware disassembly.`
