#define _GNU_SOURCE

#include <bfd.h>
#include <dis-asm.h>

#include "digests.h"
#include "native_headers.h"
#include "upx_repair.h"

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <zlib.h>

typedef struct {
  bool disassemble_all_contents;
  bool repair_upx;
  bool repair_and_unpack_upx;
  bool explicit_view_selection;
  /* Hex view accepts an omitted start/length, so track whether the user set
     them explicitly instead of relying on zero as a sentinel. */
  bool hex_start_set;
  bool hex_length_set;
  bool json_output;
  bool ndjson_output;
  const char *path;
  const char *output_path;
  /* Patch mode writes to a separate path from UPX repair mode even though both
     are "write an output file" workflows. */
  const char *patch_output_path;
  const char **section_filters;
  size_t section_filter_count;
  size_t section_filter_capacity;
  size_t hex_start;
  size_t hex_length;
  size_t hex_bytes_per_line;
  size_t search_hit_limit;
  size_t min_string_length;
  struct search_query *search_queries;
  size_t search_query_count;
  size_t search_query_capacity;
  struct byte_patch *patches;
  size_t patch_count;
  size_t patch_capacity;
  unsigned int output_views;
} options_t;

typedef struct {
  asymbol **symbols;
  long count;
  bool dynamic;
} symbol_table_t;

typedef struct {
  asymbol **items;
  size_t count;
} section_symbol_table_t;

typedef struct {
  asection *section;
  const char *name;
  unsigned int index;
  flagword flags;
  bfd_vma vma;
  bfd_vma lma;
  bfd_size_type size;
  bfd_size_type rawsize;
  bfd_size_type compressed_size;
  file_ptr filepos;
  unsigned int reloc_count;
  unsigned int lineno_count;
  unsigned int entsize;
  unsigned int alignment_power;
  bool has_contents;
  bool is_compressed;
  bool content_loaded;
  double entropy;
  uint32_t crc32_value;
  bool contains_entry;
  bool suspicious_name;
  const char *suspicious_name_reason;
  bool writable_and_executable;
  bool high_entropy;
} section_report_t;

typedef struct {
  const char *name;
  const char *reason;
  bool undefined;
} symbol_clue_t;

typedef struct {
  char **items;
  size_t count;
  size_t capacity;
} string_list_t;

typedef struct {
  char *name;
  string_list_t symbols;
} import_library_t;

typedef struct {
  size_t offset;
  char *value;
  const char *encoding;
} extracted_string_t;

typedef enum {
  SEARCH_QUERY_ASCII = 0,
  SEARCH_QUERY_UTF16,
  SEARCH_QUERY_HEX,
} search_query_kind_t;

typedef struct search_query {
  search_query_kind_t kind;
  char *text;
  bfd_byte *bytes;
  size_t byte_count;
} search_query_t;

typedef struct byte_patch {
  size_t offset;
  bfd_byte *bytes;
  size_t length;
} byte_patch_t;

typedef struct {
  char type[32];
  char name[96];
  char language[32];
  uint32_t data_rva;
  uint32_t data_size;
  uint32_t codepage;
  size_t data_offset;
  bool data_offset_known;
} pe_resource_entry_t;

typedef struct {
  size_t offset;
  const char *kind;
} embedded_signature_t;

typedef struct {
  const char *name;
  const char *kind;
  const char *confidence;
  char evidence[160];
} protector_hint_t;

enum {
  MAX_SYMBOL_CLUES = 16,
  MAX_PROTECTOR_HINTS = 32,
  DEFAULT_HEX_VIEW_LENGTH = 256,
  DEFAULT_HEX_BYTES_PER_LINE = 16,
  MIN_HEX_BYTES_PER_LINE = 4,
  MAX_HEX_BYTES_PER_LINE = 64,
  DEFAULT_SEARCH_HIT_LIMIT = 64,
  MAX_SEARCH_HIT_LIMIT = 100000,
  MAX_EMBEDDED_SIGNATURE_HITS = 32,
  MAX_PE_RESOURCE_ENTRIES = 4096,
};

typedef struct {
  section_report_t *sections;
  size_t section_count;
  size_t matched_sections;
  section_report_t *entry_section;
  section_report_t *highest_entropy_section;
  uintmax_t file_size;
  uintmax_t trailing_bytes_after_sections;
  bool trailing_bytes_valid;
  size_t suspicious_section_count;
  size_t undefined_symbol_count;
  size_t external_symbol_count;
  uint32_t file_crc32_value;
  char file_md5[33];
  char file_sha256[65];
  bool file_hashes_available;
  bool upx_packed;
  bool upx_version_known;
  bool upx_version_normalized;
  char upx_version_raw[32];
  char upx_version[32];
  bool upx_pack_header_known;
  unsigned upx_pack_header_version;
  unsigned upx_pack_header_format;
  bool linking_known;
  char linking[64];
  bool loader_known;
  char loader[256];
  bool language_known;
  char language[64];
  char language_reason[160];
  bool pe_clr_runtime;
  bool dependency_summary_available;
  bool dependency_summary_is_elf;
  bool dependency_summary_is_pe;
  string_list_t elf_needed_libraries;
  char elf_soname[256];
  char elf_rpath[512];
  char elf_runpath[512];
  import_library_t *pe_imports;
  size_t pe_import_count;
  size_t pe_import_capacity;
  import_library_t *pe_delay_imports;
  size_t pe_delay_import_count;
  size_t pe_delay_import_capacity;
  size_t pe_export_count;
  bool pe_resources_available;
  pe_resource_entry_t *pe_resources;
  size_t pe_resource_count;
  size_t pe_resource_capacity;
  extracted_string_t *strings;
  size_t string_count;
  size_t string_capacity;
  bool security_context_available;
  bool security_context_is_elf;
  bool security_context_is_pe;
  char execution_model[64];
  bool nx_known;
  bool nx_enabled;
  char relro[32];
  bool canary_present;
  bool fortify_present;
  bool tls_present;
  bool aslr_known;
  bool aslr_enabled;
  bool cfg_known;
  bool cfg_enabled;
  bool high_entropy_va_known;
  bool high_entropy_va_enabled;
  bool force_integrity_known;
  bool force_integrity_enabled;
  bool no_seh_known;
  bool no_seh_enabled;
  bool pe_tls_callbacks_present;
  uint16_t pe_subsystem;
  bool provenance_available;
  bool provenance_is_elf;
  bool provenance_is_pe;
  char elf_build_id[129];
  char elf_debuglink[256];
  bool elf_debuglink_crc_known;
  uint32_t elf_debuglink_crc32;
  string_list_t compiler_comments;
  bool pe_timestamp_known;
  uint32_t pe_timestamp;
  char pe_timestamp_text[64];
  bool pe_rich_header_present;
  bool pe_authenticode_present;
  uint32_t pe_authenticode_offset;
  uint32_t pe_authenticode_size;
  bool pe_codeview_present;
  char pe_codeview_guid[64];
  uint32_t pe_codeview_age;
  char pe_pdb_path[512];
  bool pe_repro_debug_present;
  bool overlay_analysis_available;
  size_t overlay_offset;
  size_t overlay_size;
  bool overlay_hashes_available;
  double overlay_entropy;
  uint32_t overlay_crc32_value;
  embedded_signature_t *embedded_signatures;
  size_t embedded_signature_count;
  size_t embedded_signature_capacity;
  protector_hint_t protector_hints[MAX_PROTECTOR_HINTS];
  size_t protector_hint_count;
  symbol_clue_t symbol_clues[MAX_SYMBOL_CLUES];
  size_t symbol_clue_count;
} analysis_report_t;

typedef enum {
  PARSE_OK = 0,
  PARSE_HELP,
  PARSE_ERROR
} parse_result_t;

enum {
  OUTPUT_VIEW_OVERVIEW = 1U << 0,
  OUTPUT_VIEW_DEPENDENCIES = 1U << 1,
  OUTPUT_VIEW_HEADERS = 1U << 2,
  OUTPUT_VIEW_TRIAGE = 1U << 3,
  OUTPUT_VIEW_SECTIONS = 1U << 4,
  OUTPUT_VIEW_DISASSEMBLY = 1U << 5,
  OUTPUT_VIEW_STRINGS = 1U << 6,
  OUTPUT_VIEW_SECURITY = 1U << 7,
  OUTPUT_VIEW_PROVENANCE = 1U << 8,
  OUTPUT_VIEW_HEX = 1U << 9,
  OUTPUT_VIEW_RESOURCES = 1U << 10,
  OUTPUT_VIEW_OVERLAY = 1U << 11,
  OUTPUT_VIEW_SEARCH = 1U << 12,
  OUTPUT_VIEW_DEFAULT = OUTPUT_VIEW_OVERVIEW | OUTPUT_VIEW_HEADERS |
                        OUTPUT_VIEW_TRIAGE | OUTPUT_VIEW_SECTIONS |
                        OUTPUT_VIEW_DISASSEMBLY |
                        OUTPUT_VIEW_DEPENDENCIES | OUTPUT_VIEW_SECURITY |
                        OUTPUT_VIEW_PROVENANCE | OUTPUT_VIEW_RESOURCES |
                        OUTPUT_VIEW_OVERLAY,
};

typedef struct {
  flagword flag;
  const char *name;
} named_flag_t;

typedef struct {
  const char *needle;
  const char *reason;
} suspicious_rule_t;

typedef struct {
  const char *needle;
  const char *name;
  const char *kind;
  const char *confidence;
} protector_rule_t;

typedef struct {
  const char *name;
  unsigned int views;
  const char *description;
} inspect_command_t;

enum {
  EI_CLASS = 4,
  EI_DATA = 5,
  EI_VERSION = 6,
  ELFCLASS32 = 1,
  ELFCLASS64 = 2,
  ELFDATA2LSB = 1,
  ELFDATA2MSB = 2,
  ET_REL = 1,
  ET_EXEC = 2,
  ET_DYN = 3,
  PT_DYNAMIC = 2,
  PT_INTERP = 3,
  PT_LOAD = 1,
  PT_TLS = 7,
  PT_GNU_STACK = 0x6474e551,
  PT_GNU_RELRO = 0x6474e552,
  IMAGE_SUBSYSTEM_NATIVE = 1,
  IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
  IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
  IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
  IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
  IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
  IMAGE_SUBSYSTEM_EFI_ROM = 13,
  IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16,
  PE_DIRECTORY_IMPORT = 1,
  PE_DIRECTORY_EXPORT = 0,
  PE_DIRECTORY_RESOURCE = 2,
  PE_DIRECTORY_SECURITY = 4,
  PE_DIRECTORY_DEBUG = 6,
  PE_DIRECTORY_TLS = 9,
  PE_DIRECTORY_DELAY_IMPORT = 13,
  PE_DIRECTORY_CLR = 14,
  DT_NULL = 0,
  DT_NEEDED = 1,
  DT_STRTAB = 5,
  DT_STRSZ = 10,
  DT_SONAME = 14,
  DT_RPATH = 15,
  DT_BIND_NOW = 24,
  DT_RUNPATH = 29,
  DT_FLAGS = 30,
  DT_FLAGS_1 = 0x6ffffffb,
};

enum {
  DF_BIND_NOW = 0x8,
  DF_1_NOW = 0x1,
  IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020,
  IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040,
  IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
  IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100,
  IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
  IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
  IMAGE_DEBUG_TYPE_CODEVIEW = 2,
  IMAGE_DEBUG_TYPE_REPRO = 16,
};

static const named_flag_t k_file_flags[] = {
    {HAS_RELOC, "HAS_RELOC"},
    {EXEC_P, "EXEC_P"},
    {HAS_LINENO, "HAS_LINENO"},
    {HAS_DEBUG, "HAS_DEBUG"},
    {HAS_SYMS, "HAS_SYMS"},
    {HAS_LOCALS, "HAS_LOCALS"},
    {DYNAMIC, "DYNAMIC"},
    {WP_TEXT, "WP_TEXT"},
    {D_PAGED, "D_PAGED"},
    {BFD_IS_RELAXABLE, "RELAXABLE"},
};

static const named_flag_t k_section_flags[] = {
    {SEC_ALLOC, "ALLOC"},
    {SEC_LOAD, "LOAD"},
    {SEC_RELOC, "RELOC"},
    {SEC_READONLY, "READONLY"},
    {SEC_CODE, "CODE"},
    {SEC_DATA, "DATA"},
    {SEC_ROM, "ROM"},
    {SEC_HAS_CONTENTS, "HAS_CONTENTS"},
    {SEC_NEVER_LOAD, "NEVER_LOAD"},
    {SEC_THREAD_LOCAL, "THREAD_LOCAL"},
    {SEC_FIXED_SIZE, "FIXED_SIZE"},
    {SEC_IS_COMMON, "COMMON"},
    {SEC_DEBUGGING, "DEBUGGING"},
    {SEC_IN_MEMORY, "IN_MEMORY"},
    {SEC_EXCLUDE, "EXCLUDE"},
    {SEC_SORT_ENTRIES, "SORT_ENTRIES"},
    {SEC_LINK_ONCE, "LINK_ONCE"},
    {SEC_LINKER_CREATED, "LINKER_CREATED"},
    {SEC_KEEP, "KEEP"},
    {SEC_SMALL_DATA, "SMALL_DATA"},
    {SEC_MERGE, "MERGE"},
    {SEC_STRINGS, "STRINGS"},
    {SEC_GROUP, "GROUP"},
    {SEC_ELF_PURECODE, "PURECODE"},
    {SEC_ELF_LARGE, "ELF_LARGE"},
    {SEC_ELF_OCTETS, "ELF_OCTETS"},
};

static const suspicious_rule_t k_suspicious_section_name_rules[] = {
    {"upx", "packer marker"},
    {"aspack", "packer marker"},
    {"themida", "packer marker"},
    {"vmp", "packer marker"},
    {"petite", "packer marker"},
    {"mpress", "packer marker"},
    {"kkrunchy", "packer marker"},
    {"packed", "packed payload hint"},
    {"crypt", "encrypted payload hint"},
    {"stub", "loader/stub hint"},
};

static const protector_rule_t k_protector_section_rules[] = {
    {"upx", "UPX", "packer", "high"},
    {"aspack", "ASPack", "packer", "high"},
    {"adata", "ASPack", "packer", "medium"},
    {"themida", "Themida", "protector", "high"},
    {"winlic", "WinLicense", "protector", "high"},
    {"vmp", "VMProtect", "protector", "medium"},
    {"enigma", "Enigma Protector", "protector", "high"},
    {"mpress", "MPRESS", "packer", "high"},
    {"pec1", "PECompact", "packer", "medium"},
    {"pec2", "PECompact", "packer", "medium"},
    {"petite", "Petite", "packer", "high"},
    {"fsg", "FSG", "packer", "medium"},
    {"nsp", "NsPack", "packer", "medium"},
    {"kkrunchy", "kkrunchy", "packer", "high"},
};

static const protector_rule_t k_protector_marker_rules[] = {
    {"$Id: UPX ", "UPX", "packer", "high"},
    {"UPX!", "UPX", "packer", "medium"},
    {"ASPack", "ASPack", "packer", "high"},
    {"PECompact", "PECompact", "packer", "high"},
    {"MPRESS", "MPRESS", "packer", "high"},
    {"Themida", "Themida", "protector", "high"},
    {"WinLicense", "WinLicense", "protector", "high"},
    {"VMProtect", "VMProtect", "protector", "high"},
    {"Enigma Protector", "Enigma Protector", "protector", "high"},
    {"Obsidium", "Obsidium", "protector", "high"},
    {"ConfuserEx", "ConfuserEx", ".NET protector", "high"},
    {".NET Reactor", ".NET Reactor", ".NET protector", "high"},
    {"SmartAssembly", "SmartAssembly", ".NET protector", "high"},
    {"Costura", "Costura", ".NET bundler", "medium"},
    {"PyInstaller", "PyInstaller", "bundler", "high"},
    {"_MEIPASS", "PyInstaller", "bundler", "medium"},
    {"pyi-windows-manifest-filename", "PyInstaller", "bundler", "high"},
    {"Nuitka", "Nuitka", "compiler/bundler", "high"},
    {"__nuitka", "Nuitka", "compiler/bundler", "medium"},
    {"PyArmor", "PyArmor", "Python protector", "high"},
    {"cx_Freeze", "cx_Freeze", "Python bundler", "high"},
    {"Go build ID", "Go", "compiled runtime", "medium"},
    {"Go buildinf:", "Go", "compiled runtime", "medium"},
    {"rustc", "Rust", "compiled runtime", "medium"},
};

static const suspicious_rule_t k_suspicious_symbol_rules[] = {
    {"virtualalloc", "memory allocation"},
    {"virtualprotect", "memory protection change"},
    {"writeprocessmemory", "process injection primitive"},
    {"createremotethread", "remote thread creation"},
    {"ntcreatethreadex", "remote thread creation"},
    {"queueuserapc", "APC injection primitive"},
    {"loadlibrary", "runtime library loading"},
    {"getprocaddress", "dynamic API resolution"},
    {"urldownloadtofile", "payload download primitive"},
    {"internetopen", "networking primitive"},
    {"internetconnect", "networking primitive"},
    {"httpopenrequest", "networking primitive"},
    {"winexec", "process execution"},
    {"shellexecute", "process execution"},
    {"createprocess", "process execution"},
    {"openprocess", "process access"},
    {"socket", "networking primitive"},
    {"connect", "networking primitive"},
    {"send", "networking primitive"},
    {"recv", "networking primitive"},
    {"ptrace", "anti-debug or process inspection"},
    {"dlopen", "runtime library loading"},
    {"dlsym", "dynamic symbol resolution"},
    {"mprotect", "memory protection change"},
    {"mmap", "memory mapping"},
    {"execve", "process execution"},
    {"fork", "process creation"},
};

static const inspect_command_t k_inspect_commands[] = {
    {"inspect", OUTPUT_VIEW_DEFAULT,
     "full analyst view: overview, imports, headers, triage, security, provenance, resources, overlay, sections, and disassembly"},
    {"fileinfo", OUTPUT_VIEW_OVERVIEW,
     "file overview, hashes, linkage, loader, and language guess"},
    {"imports", OUTPUT_VIEW_OVERVIEW | OUTPUT_VIEW_DEPENDENCIES,
     "overview plus import/dependency summary"},
    {"headers", OUTPUT_VIEW_OVERVIEW | OUTPUT_VIEW_HEADERS,
     "overview plus native ELF/PE headers"},
    {"triage", OUTPUT_VIEW_OVERVIEW | OUTPUT_VIEW_TRIAGE,
     "overview plus malware triage"},
    {"security", OUTPUT_VIEW_OVERVIEW | OUTPUT_VIEW_SECURITY,
     "overview plus hardening and loader context"},
    {"provenance", OUTPUT_VIEW_OVERVIEW | OUTPUT_VIEW_PROVENANCE,
     "overview plus signature and provenance hints"},
    {"resources", OUTPUT_VIEW_OVERVIEW | OUTPUT_VIEW_RESOURCES,
     "overview plus PE resource summary"},
    {"overlay", OUTPUT_VIEW_OVERVIEW | OUTPUT_VIEW_OVERLAY,
     "overview plus overlay and embedded payload hints"},
    {"sections", OUTPUT_VIEW_OVERVIEW | OUTPUT_VIEW_SECTIONS,
     "overview plus section headers"},
    {"strings", OUTPUT_VIEW_OVERVIEW | OUTPUT_VIEW_STRINGS,
     "overview plus extracted ASCII and UTF-16 strings"},
    {"disasm", OUTPUT_VIEW_OVERVIEW | OUTPUT_VIEW_DISASSEMBLY,
     "overview plus disassembly"},
    {"hex", OUTPUT_VIEW_HEX, "raw hex and ASCII view"},
    {"search", OUTPUT_VIEW_SEARCH, "raw byte-pattern and string search"},
};

static uint32_t crc32_bytes(const bfd_byte *contents, bfd_size_type size);
static double shannon_entropy(const bfd_byte *contents, bfd_size_type size);
static uint32_t max_u32(uint32_t left, uint32_t right);
static const char *bounded_file_string(const bfd_byte *buffer, size_t size,
                                       size_t offset, size_t max_length);
static bool map_pe_rva_to_offset(const bfd_byte *section_table,
                                 uint16_t section_count,
                                 uint32_t size_of_headers, size_t size,
                                 uint32_t rva, size_t *offset_out);
static bool section_is_selected(const options_t *options,
                                const asection *section);
static bool parse_patch_bytes(const char *text, bfd_byte **bytes_out,
                              size_t *length_out);
static void print_byte_sequence(FILE *stream, const bfd_byte *bytes,
                                size_t count);

static void print_usage(FILE *stream, const char *argv0) {
  fprintf(stream,
          "Usage: %s [options] <binary>\n"
          "       %s <command> [options] <binary>\n"
          "\n"
          "Inspect ELF and PE binaries with libbfd, print file/section metadata,\n"
          "view or patch raw bytes, disassemble executable sections, or repair\n"
          "common UPX anti-unpacking damage in ELF and PE files.\n"
          "\n"
          "Commands:\n"
          "  inspect             full output (default when no command is given)\n"
          "  fileinfo            file overview, hashes, linkage,\n"
          "                      loader, UPX identity, and language guess\n"
          "  imports             overview plus import/dependency summary\n"
          "  headers             overview plus native ELF/PE headers\n"
          "  triage              overview plus malware triage\n"
          "  security            overview plus hardening and loader context\n"
          "  provenance          overview plus signature and provenance hints\n"
          "  resources           overview plus PE resource summary\n"
          "  overlay             overview plus overlay and embedded payload hints\n"
          "  sections            overview plus section headers\n"
          "  strings             overview plus extracted strings\n"
          "  disasm              overview plus disassembly\n"
          "  hex                 raw hex and ASCII view\n"
          "  search              raw byte-pattern and string search\n"
          "\n"
          "Options:\n"
          "  -a, --all-sections   disassemble every matched section with contents\n"
          "  -m, --min-string-len N\n"
          "                       minimum extracted string length (default: 4)\n"
          "  -s, --section NAME   limit section, disassembly, or strings output\n"
          "                       to the named section (repeatable)\n"
          "  -n, --no-disasm      skip disassembly in the default full view\n"
          "      --summary        show only the file overview block\n"
          "      --overview       alias for --summary\n"
          "      --imports        show only the import/dependency block\n"
          "      --headers        show only native ELF/PE header details\n"
          "      --triage         show only the malware triage block\n"
          "      --sections       show only section-header details\n"
          "      --strings        show only extracted strings\n"
          "      --security       show only hardening and loader context\n"
          "      --provenance     show only signature and provenance hints\n"
          "      --resources      show only PE resource summary\n"
          "      --overlay        show only overlay and embedded payload hints\n"
          "      --disasm         show only disassembly output\n"
          "      --hex            show only the raw hex/ASCII view\n"
          "      --search         show only byte-pattern and string search results\n"
          "      --hex-start OFF  start byte offset for hex view (decimal or 0x...)\n"
          "      --hex-length N   bytes to display in hex view (default: 256)\n"
          "      --hex-width N    bytes per hex row (default: 16, range: 4-64)\n"
          "      --find-ascii T   search for an exact ASCII/UTF-8 byte string\n"
          "      --find-utf16 T   search for the UTF-16LE/BE form of a text literal\n"
          "      --find-hex HEX   search for an exact byte pattern such as 4d5a90\n"
          "      --max-search-hits N\n"
          "                       maximum hits printed per search query (default: 64)\n"
          "                       if any of the focused view switches above are used,\n"
          "                       binsight prints only the requested blocks\n"
          "      --json           emit machine-readable JSON for report-backed views\n"
          "      --ndjson         emit newline-delimited JSON records for report-backed views\n"
          "      --patch SPEC     apply byte patch OFFSET:HEXBYTES, for example\n"
          "                       0x3c:9090 (repeatable)\n"
          "      --patch-out OUT  write the patched copy to OUT\n"
          "      --repair-upx OUT\n"
          "                       repair common UPX/ELF or UPX/PE tampering and\n"
          "                       write the repaired binary to OUT\n"
          "      --repair-upx-elf OUT\n"
          "                       compatibility alias for --repair-upx\n"
          "      --repair-and-unpack-upx OUT\n"
          "                       repair first, then call external 'upx -d' to\n"
          "                       write an unpacked binary to OUT\n"
          "  -h, --help           show this help text\n",
          argv0, argv0);
}

static void append_text(char *buffer, size_t size, size_t *used,
                        const char *text) {
  int written;

  if (*used >= size) {
    return;
  }

  written = snprintf(buffer + *used, size - *used, "%s", text);
  if (written < 0) {
    return;
  }

  if ((size_t)written >= size - *used) {
    *used = size - 1;
    return;
  }

  *used += (size_t)written;
}

static const char *format_flags(flagword flags, const named_flag_t *descriptors,
                                size_t descriptor_count, char *buffer,
                                size_t size) {
  size_t used = 0;
  bool first = true;

  if (size == 0) {
    return buffer;
  }

  buffer[0] = '\0';
  for (size_t index = 0; index < descriptor_count; ++index) {
    if ((flags & descriptors[index].flag) == 0) {
      continue;
    }

    if (!first) {
      append_text(buffer, size, &used, ", ");
    }
    append_text(buffer, size, &used, descriptors[index].name);
    first = false;
  }

  if (first) {
    append_text(buffer, size, &used, "none");
  }

  return buffer;
}

static const char *yes_no(bool value) {
  return value ? "yes" : "no";
}

static int styled_fprintf(void *stream, enum disassembler_style style,
                          const char *format, ...) {
  va_list arguments;
  int written;

  (void)style;

  va_start(arguments, format);
  written = vfprintf((FILE *)stream, format, arguments);
  va_end(arguments);
  return written;
}

static const char *section_attribute(bool condition, const char *enabled_name,
                                     const char *disabled_name) {
  return condition ? enabled_name : disabled_name;
}

static bool ci_contains(const char *haystack, const char *needle) {
  size_t needle_length;

  if (haystack == NULL || needle == NULL) {
    return false;
  }

  needle_length = strlen(needle);
  if (needle_length == 0) {
    return true;
  }

  for (; *haystack != '\0'; ++haystack) {
    size_t index = 0;

    while (index < needle_length && haystack[index] != '\0' &&
           tolower((unsigned char)haystack[index]) ==
               tolower((unsigned char)needle[index])) {
      ++index;
    }

    if (index == needle_length) {
      return true;
    }
  }

  return false;
}

static const char *match_suspicious_rule(const char *text,
                                         const suspicious_rule_t *rules,
                                         size_t rule_count) {
  for (size_t index = 0; index < rule_count; ++index) {
    if (ci_contains(text, rules[index].needle)) {
      return rules[index].reason;
    }
  }

  return NULL;
}

static unsigned int address_width_for_bfd(const bfd *abfd) {
  unsigned int bits = bfd_arch_bits_per_address(abfd);
  unsigned int width = bits == 0 ? 8U : (bits + 3U) / 4U;

  return width < 8U ? 8U : width;
}

static void print_hex(FILE *stream, unsigned int width, uintmax_t value) {
  fprintf(stream, "0x%0*" PRIxMAX, (int)width, value);
}

static unsigned int hex_width_for_value(uintmax_t value) {
  unsigned int width = 1;

  while (value > 0x0fU && width < sizeof(uintmax_t) * 2U) {
    value >>= 4;
    ++width;
  }

  /* Keep offsets stable at at least eight hex digits so short files still
     print in a conventional hexdump-style column. */
  return width < 8U ? 8U : width;
}

static uintmax_t alignment_value(unsigned int power) {
  if (power >= sizeof(uintmax_t) * CHAR_BIT) {
    return 0;
  }
  return UINTMAX_C(1) << power;
}

static bool file_size_from_path(const char *path, uintmax_t *size) {
  struct stat st;

  if (stat(path, &st) != 0) {
    return false;
  }

  *size = (uintmax_t)st.st_size;
  return true;
}

static bool read_file_bytes(const char *path, bfd_byte **buffer, size_t *size) {
  FILE *stream = NULL;
  bfd_byte *data = NULL;
  uintmax_t file_size;
  size_t total_read = 0;

  if (!file_size_from_path(path, &file_size) || file_size > SIZE_MAX) {
    return false;
  }

  stream = fopen(path, "rb");
  if (stream == NULL) {
    return false;
  }

  /* Hex viewing and patching should still behave sensibly on empty files, so
     return a successful zero-length read instead of treating it as an error. */
  if (file_size == 0) {
    fclose(stream);
    *buffer = NULL;
    *size = 0;
    return true;
  }

  data = malloc((size_t)file_size);
  if (data == NULL) {
    fclose(stream);
    return false;
  }

  while (total_read < (size_t)file_size) {
    size_t chunk =
        fread(data + total_read, 1, (size_t)file_size - total_read, stream);
    if (chunk == 0) {
      if (ferror(stream)) {
        free(data);
        fclose(stream);
        return false;
      }
      break;
    }
    total_read += chunk;
  }

  fclose(stream);
  if (total_read != (size_t)file_size) {
    free(data);
    return false;
  }

  *buffer = data;
  *size = total_read;
  return true;
}

static void format_error_message(char *buffer, size_t size, const char *format,
                                 ...) {
  va_list args;

  if (size == 0) {
    return;
  }

  va_start(args, format);
  vsnprintf(buffer, size, format, args);
  va_end(args);
  buffer[size - 1] = '\0';
}

static bool write_file_bytes(const char *path, const bfd_byte *buffer, size_t size,
                             char *error_buffer, size_t error_buffer_size) {
  FILE *stream = fopen(path, "wb");

  if (stream == NULL) {
    format_error_message(error_buffer, error_buffer_size,
                         "unable to open '%s' for writing: %s", path,
                         strerror(errno));
    return false;
  }

  if (size != 0 && fwrite(buffer, 1, size, stream) != size) {
    format_error_message(error_buffer, error_buffer_size,
                         "unable to write '%s': %s", path, strerror(errno));
    fclose(stream);
    return false;
  }

  if (fclose(stream) != 0) {
    format_error_message(error_buffer, error_buffer_size,
                         "unable to finalize '%s': %s", path,
                         strerror(errno));
    return false;
  }

  return true;
}

static uint16_t read_u16_le_bytes(const bfd_byte *buffer) {
  return (uint16_t)buffer[0] | ((uint16_t)buffer[1] << 8);
}

static uint32_t read_u32_le_bytes(const bfd_byte *buffer) {
  return (uint32_t)buffer[0] | ((uint32_t)buffer[1] << 8) |
         ((uint32_t)buffer[2] << 16) | ((uint32_t)buffer[3] << 24);
}

static uint64_t read_u64_le_bytes(const bfd_byte *buffer) {
  return (uint64_t)read_u32_le_bytes(buffer) |
         ((uint64_t)read_u32_le_bytes(buffer + 4) << 32);
}

static uint16_t read_u16_endian_bytes(const bfd_byte *buffer, bool big_endian) {
  if (big_endian) {
    return ((uint16_t)buffer[0] << 8) | (uint16_t)buffer[1];
  }
  return read_u16_le_bytes(buffer);
}

static uint32_t read_u32_endian_bytes(const bfd_byte *buffer, bool big_endian) {
  if (big_endian) {
    return ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
           ((uint32_t)buffer[2] << 8) | (uint32_t)buffer[3];
  }
  return read_u32_le_bytes(buffer);
}

static uint64_t read_u64_endian_bytes(const bfd_byte *buffer, bool big_endian) {
  if (big_endian) {
    return ((uint64_t)read_u32_endian_bytes(buffer, true) << 32) |
           (uint64_t)read_u32_endian_bytes(buffer + 4, true);
  }
  return read_u64_le_bytes(buffer);
}

static void set_report_text(char *buffer, size_t size, const char *text) {
  if (buffer == NULL || size == 0) {
    return;
  }
  snprintf(buffer, size, "%s", text != NULL ? text : "unknown");
}

static char *duplicate_text(const char *text) {
  size_t length;
  char *copy;

  if (text == NULL) {
    return NULL;
  }

  length = strlen(text);
  copy = malloc(length + 1);
  if (copy == NULL) {
    return NULL;
  }

  memcpy(copy, text, length + 1);
  return copy;
}

static ssize_t find_last_occurrence_bytes(const bfd_byte *buffer, size_t size,
                                          const bfd_byte *needle,
                                          size_t needle_size) {
  if (needle_size == 0 || size < needle_size) {
    return -1;
  }

  for (size_t index = size - needle_size + 1; index-- > 0;) {
    if (memcmp(buffer + index, needle, needle_size) == 0) {
      return (ssize_t)index;
    }
    if (index == 0) {
      break;
    }
  }

  return -1;
}

static size_t upx_pack_header_size(uint8_t version, uint8_t format) {
  if (version <= 3) {
    return 24;
  }
  if (version <= 9) {
    if (format == 1 || format == 2) {
      return 20;
    }
    if (format == 3 || format == 7) {
      return 25;
    }
    return 28;
  }
  if (format == 1 || format == 2) {
    return 22;
  }
  if (format == 3 || format == 7) {
    return 27;
  }
  return 32;
}

static uint8_t upx_pack_header_checksum(const bfd_byte *buffer, size_t size) {
  unsigned checksum = 0;

  for (size_t index = 4; index < size; ++index) {
    checksum += buffer[index];
  }

  return (uint8_t)(checksum % 251U);
}

static bool normalize_upx_version_token(const char *token, char *buffer,
                                        size_t size, bool *changed) {
  const char *dot;
  char major_text[16];
  char suffix[16];
  unsigned long major;
  char *end = NULL;
  size_t suffix_length;

  if (buffer == NULL || size == 0 || token == NULL || token[0] == '\0') {
    return false;
  }

  if (changed != NULL) {
    *changed = false;
  }

  dot = strchr(token, '.');
  if (dot == NULL || dot == token || dot[1] == '\0') {
    snprintf(buffer, size, "%s", token);
    return true;
  }

  if ((size_t)(dot - token) >= sizeof(major_text)) {
    snprintf(buffer, size, "%s", token);
    return true;
  }

  memcpy(major_text, token, (size_t)(dot - token));
  major_text[dot - token] = '\0';
  snprintf(suffix, sizeof(suffix), "%s", dot + 1);
  major = strtoul(major_text, &end, 10);
  if (major_text[0] == '\0' || end == NULL || *end != '\0') {
    snprintf(buffer, size, "%s", token);
    return true;
  }

  suffix_length = strlen(suffix);
  for (size_t index = 0; index < suffix_length; ++index) {
    if (!isdigit((unsigned char)suffix[index])) {
      snprintf(buffer, size, "%s", token);
      return true;
    }
  }

  if (major >= 4 && suffix_length == 2) {
    snprintf(buffer, size, "%lu.%c.%c", major, suffix[0], suffix[1]);
    if (changed != NULL) {
      *changed = strcmp(buffer, token) != 0;
    }
    return true;
  }

  snprintf(buffer, size, "%s", token);
  return true;
}

static bool detect_upx_embedded_version(const bfd_byte *buffer, size_t size,
                                        char *raw_buffer, size_t raw_size,
                                        char *normalized_buffer,
                                        size_t normalized_size,
                                        bool *normalized_changed) {
  static const char needle[] = "$Id: UPX ";

  if (raw_buffer == NULL || raw_size == 0 || normalized_buffer == NULL ||
      normalized_size == 0) {
    return false;
  }

  raw_buffer[0] = '\0';
  normalized_buffer[0] = '\0';
  if (normalized_changed != NULL) {
    *normalized_changed = false;
  }

  for (size_t index = 0; index + sizeof(needle) < size; ++index) {
    size_t cursor;
    size_t length = 0;

    if (memcmp(buffer + index, needle, sizeof(needle) - 1) != 0) {
      continue;
    }

    cursor = index + sizeof(needle) - 1;
    while (cursor < size && buffer[cursor] != '\0' &&
           !isspace((unsigned char)buffer[cursor]) &&
           length + 1 < raw_size) {
      raw_buffer[length++] = (char)buffer[cursor++];
    }
    raw_buffer[length] = '\0';

    if (length == 0) {
      continue;
    }

    normalize_upx_version_token(raw_buffer, normalized_buffer, normalized_size,
                                normalized_changed);
    return true;
  }

  return false;
}

static bool decode_upx_pack_header_at(const bfd_byte *buffer, size_t size,
                                      size_t offset, bool big_endian,
                                      unsigned *version_out,
                                      unsigned *format_out) {
  size_t header_size;
  uint8_t version;
  uint8_t format;
  uint32_t unpacked_file_size;

  if (offset + 28 > size || memcmp(buffer + offset, "UPX!", 4) != 0) {
    return false;
  }

  version = buffer[offset + 4];
  format = buffer[offset + 5];
  if (version == 0 || version > 20 || format == 0) {
    return false;
  }

  header_size = upx_pack_header_size(version, format);
  if (header_size < 28 || offset + header_size > size) {
    return false;
  }

  unpacked_file_size = read_u32_endian_bytes(buffer + offset + 24, big_endian);
  if (unpacked_file_size == 0) {
    return false;
  }

  if (version >= 10) {
    uint8_t expected = upx_pack_header_checksum(buffer + offset, header_size - 1);
    uint8_t current = buffer[offset + header_size - 1];
    if (expected != current) {
      return false;
    }
  }

  if (version_out != NULL) {
    *version_out = version;
  }
  if (format_out != NULL) {
    *format_out = format;
  }
  return true;
}

static bool detect_upx_elf_packing(const bfd_byte *buffer, size_t size,
                                   analysis_report_t *report) {
  bool is64;
  bool big_endian;
  uint64_t phoff;
  uint16_t phentsize;
  uint16_t phnum;
  size_t linfo_offset;
  uint8_t expected_version;
  uint8_t expected_format;
  const bfd_byte upx_magic[4] = {'U', 'P', 'X', '!'};
  ssize_t trailing;
  unsigned pack_version = 0;
  unsigned pack_format = 0;

  if (size < 64 || memcmp(buffer, "\x7f""ELF", 4) != 0 || buffer[EI_VERSION] != 1 ||
      (buffer[EI_CLASS] != ELFCLASS32 && buffer[EI_CLASS] != ELFCLASS64) ||
      (buffer[EI_DATA] != ELFDATA2LSB && buffer[EI_DATA] != ELFDATA2MSB)) {
    return false;
  }

  is64 = buffer[EI_CLASS] == ELFCLASS64;
  big_endian = buffer[EI_DATA] == ELFDATA2MSB;
  phoff = is64 ? read_u64_endian_bytes(buffer + 32, big_endian)
               : read_u32_endian_bytes(buffer + 28, big_endian);
  phentsize = read_u16_endian_bytes(buffer + (is64 ? 54 : 42), big_endian);
  phnum = read_u16_endian_bytes(buffer + (is64 ? 56 : 44), big_endian);

  if (phoff == 0 || phentsize == 0 || phnum == 0 ||
      phoff + (uint64_t)phentsize * phnum > size) {
    return false;
  }

  linfo_offset = (size_t)phoff + (size_t)phentsize * phnum;
  if (linfo_offset + 12 <= size && memcmp(buffer + linfo_offset + 4, "UPX!", 4) == 0) {
    report->upx_packed = true;
    report->upx_pack_header_known = true;
    report->upx_pack_header_version = buffer[linfo_offset + 10];
    report->upx_pack_header_format = buffer[linfo_offset + 11];
    return true;
  }

  if (linfo_offset + 12 <= size) {
    expected_version = buffer[linfo_offset + 10];
    expected_format = buffer[linfo_offset + 11];
  } else {
    expected_version = 0;
    expected_format = 0;
  }

  trailing = find_last_occurrence_bytes(buffer, size, upx_magic, sizeof(upx_magic));
  if (trailing < 0) {
    return false;
  }

  if (!decode_upx_pack_header_at(buffer, size, (size_t)trailing, false,
                                 &pack_version, &pack_format) &&
      !decode_upx_pack_header_at(buffer, size, (size_t)trailing, true,
                                 &pack_version, &pack_format)) {
    return false;
  }

  if (expected_version != 0 && expected_format != 0 &&
      (pack_version != expected_version || pack_format != expected_format)) {
    return false;
  }

  report->upx_packed = true;
  report->upx_pack_header_known = true;
  report->upx_pack_header_version = pack_version;
  report->upx_pack_header_format = pack_format;
  return true;
}

static bool detect_upx_pe_packing(const bfd_byte *buffer, size_t size,
                                  analysis_report_t *report) {
  size_t pe_offset;
  uint16_t section_count;
  uint16_t optional_size;
  size_t optional_offset;
  size_t section_table_offset;
  uint16_t machine;
  uint8_t expected_format = 0;
  uint32_t raw_offsets[3] = {0};
  unsigned pack_version = 0;
  unsigned pack_format = 0;

  if (size < 0x40 || buffer[0] != 'M' || buffer[1] != 'Z') {
    return false;
  }

  pe_offset = read_u32_le_bytes(buffer + 0x3c);
  if (pe_offset + 24 > size || memcmp(buffer + pe_offset, "PE\0\0", 4) != 0) {
    return false;
  }

  machine = read_u16_le_bytes(buffer + pe_offset + 4);
  if (machine == 0x14c) {
    expected_format = 9;
  } else if (machine == 0x8664) {
    expected_format = 36;
  } else if (machine == 0x1c2 || machine == 0x1c4) {
    expected_format = 21;
  } else {
    return false;
  }

  section_count = read_u16_le_bytes(buffer + pe_offset + 6);
  optional_size = read_u16_le_bytes(buffer + pe_offset + 20);
  optional_offset = pe_offset + 24;
  section_table_offset = optional_offset + optional_size;
  if (section_count < 2 || section_count > 16 ||
      section_table_offset + (size_t)section_count * 40 > size) {
    return false;
  }

  if (memcmp(buffer + section_table_offset, "UPX0", 4) == 0 &&
      memcmp(buffer + section_table_offset + 40, "UPX1", 4) == 0) {
    report->upx_packed = true;
  }

  if (section_count >= 2) {
    raw_offsets[1] = read_u32_le_bytes(buffer + section_table_offset + 40 + 20);
  }
  if (section_count >= 3) {
    raw_offsets[2] = read_u32_le_bytes(buffer + section_table_offset + 80 + 20);
  }

  if (raw_offsets[1] >= 64) {
    size_t start = raw_offsets[1] - 64;
    size_t end = start + 1024;
    if (end > size) {
      end = size;
    }
    for (size_t offset = start; offset + 28 <= end && offset < start + 128; ++offset) {
      if (memcmp(buffer + offset, "UPX!", 4) == 0 &&
          decode_upx_pack_header_at(buffer, size, offset, false, &pack_version,
                                    &pack_format) &&
          pack_format == expected_format) {
        report->upx_packed = true;
        report->upx_pack_header_known = true;
        report->upx_pack_header_version = pack_version;
        report->upx_pack_header_format = pack_format;
        return true;
      }
    }
  }

  if (section_count >= 3) {
    size_t start = raw_offsets[2];
    size_t end = start + 1024;
    if (end > size) {
      end = size;
    }
    for (size_t offset = start; offset + 28 <= end && offset < start + 128; ++offset) {
      if (memcmp(buffer + offset, "UPX!", 4) == 0 &&
          decode_upx_pack_header_at(buffer, size, offset, false, &pack_version,
                                    &pack_format) &&
          pack_format == expected_format) {
        report->upx_packed = true;
        report->upx_pack_header_known = true;
        report->upx_pack_header_version = pack_version;
        report->upx_pack_header_format = pack_format;
        return true;
      }
    }
  }

  return report->upx_packed;
}

static void detect_upx_packing_identity(const bfd_byte *buffer, size_t size,
                                        analysis_report_t *report) {
  bool normalized_changed = false;

  if (detect_upx_embedded_version(buffer, size, report->upx_version_raw,
                                  sizeof(report->upx_version_raw),
                                  report->upx_version, sizeof(report->upx_version),
                                  &normalized_changed)) {
    report->upx_version_known = true;
    report->upx_version_normalized = normalized_changed;
  }

  if (detect_upx_elf_packing(buffer, size, report) ||
      detect_upx_pe_packing(buffer, size, report)) {
    return;
  }

  if (report->upx_version_known) {
    report->upx_packed = true;
  }
}

static void free_string_list(string_list_t *list) {
  if (list == NULL) {
    return;
  }

  for (size_t index = 0; index < list->count; ++index) {
    free(list->items[index]);
  }
  free(list->items);
}

static bool append_string_unique(string_list_t *list, const char *text) {
  char **new_items;
  char *copy;

  if (list == NULL || text == NULL || text[0] == '\0') {
    return true;
  }

  for (size_t index = 0; index < list->count; ++index) {
    if (strcmp(list->items[index], text) == 0) {
      return true;
    }
  }

  if (list->count == list->capacity) {
    size_t new_capacity = list->capacity == 0 ? 4 : list->capacity * 2;

    new_items = realloc(list->items, new_capacity * sizeof(*new_items));
    if (new_items == NULL) {
      return false;
    }

    list->items = new_items;
    list->capacity = new_capacity;
  }

  copy = duplicate_text(text);
  if (copy == NULL) {
    return false;
  }

  list->items[list->count++] = copy;
  return true;
}

static void free_import_libraries(import_library_t *libraries, size_t count) {
  if (libraries == NULL) {
    return;
  }

  for (size_t index = 0; index < count; ++index) {
    free(libraries[index].name);
    free_string_list(&libraries[index].symbols);
  }
  free(libraries);
}

static void free_extracted_strings(extracted_string_t *strings, size_t count) {
  if (strings == NULL) {
    return;
  }

  for (size_t index = 0; index < count; ++index) {
    free(strings[index].value);
  }
  free(strings);
}

static bool append_extracted_string(analysis_report_t *report, size_t offset,
                                    const char *value, const char *encoding) {
  extracted_string_t *new_strings;
  char *copy;
  size_t new_capacity;

  if (report == NULL || value == NULL || value[0] == '\0' || encoding == NULL) {
    return true;
  }

  if (report->string_count == report->string_capacity) {
    new_capacity = report->string_capacity == 0 ? 32 : report->string_capacity * 2;
    new_strings =
        realloc(report->strings, new_capacity * sizeof(*report->strings));
    if (new_strings == NULL) {
      return false;
    }
    report->strings = new_strings;
    report->string_capacity = new_capacity;
  }

  copy = duplicate_text(value);
  if (copy == NULL) {
    return false;
  }

  report->strings[report->string_count].offset = offset;
  report->strings[report->string_count].value = copy;
  report->strings[report->string_count].encoding = encoding;
  ++report->string_count;
  return true;
}

static bool append_pe_resource_entry(analysis_report_t *report,
                                     const pe_resource_entry_t *entry) {
  pe_resource_entry_t *new_entries;
  size_t new_capacity;

  if (report == NULL || entry == NULL) {
    return false;
  }
  if (report->pe_resource_count >= MAX_PE_RESOURCE_ENTRIES) {
    return true;
  }

  if (report->pe_resource_count == report->pe_resource_capacity) {
    new_capacity =
        report->pe_resource_capacity == 0 ? 16 : report->pe_resource_capacity * 2;
    if (new_capacity > MAX_PE_RESOURCE_ENTRIES) {
      new_capacity = MAX_PE_RESOURCE_ENTRIES;
    }
    new_entries =
        realloc(report->pe_resources, new_capacity * sizeof(*new_entries));
    if (new_entries == NULL) {
      return false;
    }
    report->pe_resources = new_entries;
    report->pe_resource_capacity = new_capacity;
  }

  report->pe_resources[report->pe_resource_count++] = *entry;
  report->pe_resources_available = true;
  return true;
}

static bool append_embedded_signature(analysis_report_t *report, size_t offset,
                                      const char *kind) {
  embedded_signature_t *new_hits;
  size_t new_capacity;

  if (report == NULL || kind == NULL) {
    return false;
  }
  if (report->embedded_signature_count >= MAX_EMBEDDED_SIGNATURE_HITS) {
    return true;
  }

  for (size_t index = 0; index < report->embedded_signature_count; ++index) {
    if (report->embedded_signatures[index].offset == offset &&
        strcmp(report->embedded_signatures[index].kind, kind) == 0) {
      return true;
    }
  }

  if (report->embedded_signature_count == report->embedded_signature_capacity) {
    new_capacity = report->embedded_signature_capacity == 0
                       ? 8
                       : report->embedded_signature_capacity * 2;
    if (new_capacity > MAX_EMBEDDED_SIGNATURE_HITS) {
      new_capacity = MAX_EMBEDDED_SIGNATURE_HITS;
    }
    new_hits =
        realloc(report->embedded_signatures, new_capacity * sizeof(*new_hits));
    if (new_hits == NULL) {
      return false;
    }
    report->embedded_signatures = new_hits;
    report->embedded_signature_capacity = new_capacity;
  }

  report->embedded_signatures[report->embedded_signature_count].offset = offset;
  report->embedded_signatures[report->embedded_signature_count].kind = kind;
  ++report->embedded_signature_count;
  return true;
}

static bool append_protector_hint(analysis_report_t *report, const char *name,
                                  const char *kind, const char *confidence,
                                  const char *evidence_format, ...) {
  protector_hint_t *hint;
  char evidence[160];
  va_list args;

  if (report == NULL || name == NULL || kind == NULL || confidence == NULL ||
      evidence_format == NULL) {
    return false;
  }

  va_start(args, evidence_format);
  vsnprintf(evidence, sizeof(evidence), evidence_format, args);
  va_end(args);
  evidence[sizeof(evidence) - 1] = '\0';

  for (size_t index = 0; index < report->protector_hint_count; ++index) {
    hint = &report->protector_hints[index];
    if (strcmp(hint->name, name) == 0 && strcmp(hint->kind, kind) == 0 &&
        strcmp(hint->evidence, evidence) == 0) {
      return true;
    }
  }

  if (report->protector_hint_count >= MAX_PROTECTOR_HINTS) {
    return true;
  }

  hint = &report->protector_hints[report->protector_hint_count++];
  hint->name = name;
  hint->kind = kind;
  hint->confidence = confidence;
  snprintf(hint->evidence, sizeof(hint->evidence), "%s", evidence);
  return true;
}

static import_library_t *find_or_add_import_library(import_library_t **libraries,
                                                    size_t *count,
                                                    size_t *capacity,
                                                    const char *name) {
  import_library_t *new_libraries;

  if (libraries == NULL || count == NULL || capacity == NULL || name == NULL) {
    return NULL;
  }

  for (size_t index = 0; index < *count; ++index) {
    if (strcmp((*libraries)[index].name, name) == 0) {
      return &(*libraries)[index];
    }
  }

  if (*count == *capacity) {
    size_t new_capacity = *capacity == 0 ? 4 : *capacity * 2;

    new_libraries = realloc(*libraries, new_capacity * sizeof(*new_libraries));
    if (new_libraries == NULL) {
      return NULL;
    }

    *libraries = new_libraries;
    *capacity = new_capacity;
  }

  memset(&(*libraries)[*count], 0, sizeof(**libraries));
  (*libraries)[*count].name = duplicate_text(name);
  if ((*libraries)[*count].name == NULL) {
    return NULL;
  }

  return &(*libraries)[(*count)++];
}

static bool is_ascii_string_byte(unsigned char value) {
  return value == '\t' || (value >= 0x20 && value <= 0x7e);
}

static bool is_common_string_separator(unsigned char value) {
  switch (value) {
  case '.':
  case '_':
  case '-':
  case '/':
  case '\\':
  case ':':
    return true;
  default:
    return false;
  }
}

static bool extracted_string_looks_meaningful(const char *text) {
  unsigned int counts[256] = {0};
  size_t length = 0;
  size_t alpha = 0;
  size_t alnum = 0;
  size_t digits = 0;
  size_t uppercase = 0;
  size_t lowercase = 0;
  size_t punctuation = 0;
  size_t common_separators = 0;
  size_t whitespace = 0;
  size_t unique = 0;
  size_t max_run = 0;
  size_t current_run = 0;
  unsigned char previous = '\0';

  if (text == NULL || text[0] == '\0') {
    return false;
  }

  for (const unsigned char *cursor = (const unsigned char *)text; *cursor != '\0';
       ++cursor) {
    unsigned char value = *cursor;

    ++length;
    if (isalpha(value)) {
      ++alpha;
    }
    if (isalnum(value)) {
      ++alnum;
    }
    if (isdigit(value)) {
      ++digits;
    }
    if (isupper(value)) {
      ++uppercase;
    }
    if (islower(value)) {
      ++lowercase;
    }
    if (ispunct(value)) {
      ++punctuation;
    }
    if (is_common_string_separator(value)) {
      ++common_separators;
    }
    if (isspace(value)) {
      ++whitespace;
    }

    if (counts[value]++ == 0) {
      ++unique;
    }

    if (length == 1 || value != previous) {
      current_run = 1;
    } else {
      ++current_run;
    }
    if (current_run > max_run) {
      max_run = current_run;
    }
    previous = value;
  }

  if (length == 0 || whitespace * 2 >= length) {
    return false;
  }

  if (unique <= 2 && length >= 6) {
    return false;
  }

  if (unique <= 3 && length >= 6 && whitespace == 0 && common_separators == 0) {
    return false;
  }

  if (length <= 6 && unique <= 4 && alpha <= 2 && whitespace == 0 &&
      common_separators == 0) {
    return false;
  }

  if (length <= 6 && whitespace != 0 && punctuation != 0 && alpha <= 2 &&
      common_separators == 0) {
    return false;
  }

  if (max_run * 3 >= length * 2 && length >= 6) {
    return false;
  }

  if (length <= 8 && punctuation >= 2 && common_separators == 0) {
    return false;
  }

  if (length <= 8 && punctuation == 1 && common_separators == 0 && digits == 0 &&
      lowercase == 0 && uppercase + punctuation == length &&
      (ispunct((unsigned char)text[0]) ||
       ispunct((unsigned char)text[length - 1]))) {
    return false;
  }

  if (alpha >= 2) {
    return true;
  }

  return alnum >= 4;
}

static bool section_is_string_candidate(const section_report_t *section,
                                        bool explicit_selection) {
  if (section == NULL || !section->has_contents || section->size == 0 ||
      section->is_compressed) {
    return false;
  }

  if (explicit_selection) {
    return true;
  }

  return (section->flags & SEC_CODE) == 0;
}

static bool append_ascii_string(analysis_report_t *report, size_t offset,
                                const bfd_byte *buffer, size_t length,
                                const char *encoding) {
  char *text;

  text = malloc(length + 1);
  if (text == NULL) {
    return false;
  }

  for (size_t index = 0; index < length; ++index) {
    text[index] = (char)buffer[index];
  }
  text[length] = '\0';

  if (!extracted_string_looks_meaningful(text)) {
    free(text);
    return true;
  }

  if (!append_extracted_string(report, offset, text, encoding)) {
    free(text);
    return false;
  }

  free(text);
  return true;
}

static bool collect_strings_from_buffer(const bfd_byte *buffer, size_t size,
                                        size_t base_offset, size_t min_length,
                                        bool scan_utf16le, bool scan_utf16be,
                                        analysis_report_t *report) {
  size_t start = 0;

  while (start < size) {
    size_t cursor = start;

    while (cursor < size && is_ascii_string_byte(buffer[cursor])) {
      ++cursor;
    }
    if (cursor - start >= min_length &&
        !append_ascii_string(report, base_offset + start, buffer + start,
                             cursor - start,
                             "ascii")) {
      return false;
    }
    start = cursor + 1;
  }

  if (scan_utf16le) {
    start = 0;
    while (start + 1 < size) {
      size_t cursor = start;
      size_t count = 0;

      while (cursor + 1 < size && is_ascii_string_byte(buffer[cursor]) &&
             buffer[cursor + 1] == 0) {
        cursor += 2;
        ++count;
      }
      if (count >= min_length) {
        char *text = malloc(count + 1);
        if (text == NULL) {
          return false;
        }
        for (size_t index = 0; index < count; ++index) {
          text[index] = (char)buffer[start + index * 2];
        }
        text[count] = '\0';
        if (!extracted_string_looks_meaningful(text)) {
          free(text);
          start = cursor;
          continue;
        }
        if (!append_extracted_string(report, base_offset + start, text,
                                     "utf16le")) {
          free(text);
          return false;
        }
        free(text);
        start = cursor;
      } else {
        ++start;
      }
    }
  }

  if (scan_utf16be) {
    start = 0;
    while (start + 1 < size) {
      size_t cursor = start;
      size_t count = 0;

      while (cursor + 1 < size && buffer[cursor] == 0 &&
             is_ascii_string_byte(buffer[cursor + 1])) {
        cursor += 2;
        ++count;
      }
      if (count >= min_length) {
        char *text = malloc(count + 1);
        if (text == NULL) {
          return false;
        }
        for (size_t index = 0; index < count; ++index) {
          text[index] = (char)buffer[start + index * 2 + 1];
        }
        text[count] = '\0';
        if (!extracted_string_looks_meaningful(text)) {
          free(text);
          start = cursor;
          continue;
        }
        if (!append_extracted_string(report, base_offset + start, text,
                                     "utf16be")) {
          free(text);
          return false;
        }
        free(text);
        start = cursor;
      } else {
        ++start;
      }
    }
  }

  return true;
}

static bool collect_strings_from_sections(bfd *abfd, const options_t *options,
                                          analysis_report_t *report) {
  bool explicit_selection = options->section_filter_count != 0;
  bool scan_utf16le = bfd_little_endian(abfd);
  bool scan_utf16be = bfd_big_endian(abfd);

  if (!scan_utf16le && !scan_utf16be) {
    scan_utf16le = true;
    scan_utf16be = true;
  }

  for (size_t index = 0; index < report->section_count; ++index) {
    const section_report_t *section = &report->sections[index];
    bfd_byte *contents = NULL;

    if (!section_is_selected(options, section->section) ||
        !section_is_string_candidate(section, explicit_selection)) {
      continue;
    }

    if (!bfd_get_full_section_contents(abfd, section->section, &contents)) {
      fprintf(stderr,
              "binsight: warning: unable to read section '%s' for string "
              "extraction: %s\n",
              section->name, bfd_errmsg(bfd_get_error()));
      continue;
    }

    if (!collect_strings_from_buffer(contents, section->size,
                                     (size_t)section->filepos,
                                     options->min_string_length, scan_utf16le,
                                     scan_utf16be, report)) {
      free(contents);
      return false;
    }

    free(contents);
  }

  return true;
}

static const char *bool_presence(bool value) {
  return value ? "present" : "not seen";
}

static bool pe_timestamp_to_text(uint32_t timestamp, char *buffer, size_t size) {
  time_t seconds;
  struct tm tm_value;

  if (buffer == NULL || size == 0 || timestamp == 0) {
    return false;
  }

  seconds = (time_t)timestamp;
#if defined(_POSIX_THREAD_SAFE_FUNCTIONS)
  if (gmtime_r(&seconds, &tm_value) == NULL) {
    return false;
  }
#else
  {
    struct tm *value = gmtime(&seconds);
    if (value == NULL) {
      return false;
    }
    tm_value = *value;
  }
#endif

  return strftime(buffer, size, "%Y-%m-%d %H:%M:%S UTC", &tm_value) != 0;
}

static void json_escape_text(FILE *stream, const char *text) {
  const unsigned char *cursor =
      (const unsigned char *)(text != NULL ? text : "");

  fputc('"', stream);
  for (; *cursor != '\0'; ++cursor) {
    switch (*cursor) {
      case '\\':
        fputs("\\\\", stream);
        break;
      case '"':
        fputs("\\\"", stream);
        break;
      case '\b':
        fputs("\\b", stream);
        break;
      case '\f':
        fputs("\\f", stream);
        break;
      case '\n':
        fputs("\\n", stream);
        break;
      case '\r':
        fputs("\\r", stream);
        break;
      case '\t':
        fputs("\\t", stream);
        break;
      default:
        if (*cursor < 0x20) {
          fprintf(stream, "\\u%04x", *cursor);
        } else {
          fputc(*cursor, stream);
        }
        break;
    }
  }
  fputc('"', stream);
}

static bool report_has_section_name(const analysis_report_t *report,
                                    const char *name) {
  if (report == NULL || name == NULL) {
    return false;
  }

  for (size_t index = 0; index < report->section_count; ++index) {
    if (strcmp(report->sections[index].name, name) == 0) {
      return true;
    }
  }

  return false;
}

static bool symbol_table_has_prefix(const symbol_table_t *table,
                                    const char *prefix) {
  size_t prefix_length;

  if (table == NULL || table->symbols == NULL || table->count <= 0 ||
      prefix == NULL) {
    return false;
  }

  prefix_length = strlen(prefix);
  for (long index = 0; index < table->count; ++index) {
    const char *name = table->symbols[index] != NULL ? table->symbols[index]->name
                                                     : NULL;
    if (name != NULL && strncmp(name, prefix, prefix_length) == 0) {
      return true;
    }
  }

  return false;
}

static bool symbol_table_has_fragment(const symbol_table_t *table,
                                      const char *fragment) {
  if (table == NULL || table->symbols == NULL || table->count <= 0 ||
      fragment == NULL) {
    return false;
  }

  for (long index = 0; index < table->count; ++index) {
    const char *name = table->symbols[index] != NULL ? table->symbols[index]->name
                                                     : NULL;
    if (name != NULL && ci_contains(name, fragment)) {
      return true;
    }
  }

  return false;
}

static void maybe_set_language_guess(analysis_report_t *report, int *best_score,
                                     int score, const char *language,
                                     const char *reason) {
  if (report == NULL || best_score == NULL || language == NULL || reason == NULL ||
      score <= *best_score) {
    return;
  }

  *best_score = score;
  report->language_known = true;
  set_report_text(report->language, sizeof(report->language), language);
  set_report_text(report->language_reason, sizeof(report->language_reason),
                  reason);
}

static void infer_language_guess(const symbol_table_t *symbols,
                                 analysis_report_t *report) {
  int best_score = 0;

  if (report == NULL) {
    return;
  }

  if (report->pe_clr_runtime) {
    maybe_set_language_guess(report, &best_score, 100, ".NET",
                             "CLR runtime metadata was found in the PE image");
  }

  if (report_has_section_name(report, ".gopclntab") ||
      report_has_section_name(report, ".go.buildinfo") ||
      report_has_section_name(report, ".gosymtab") ||
      symbol_table_has_prefix(symbols, "runtime.") ||
      symbol_table_has_prefix(symbols, "go:") ||
      symbol_table_has_prefix(symbols, "type:")) {
    maybe_set_language_guess(report, &best_score, 95, "Go",
                             "Go runtime metadata or symbol naming was found");
  }

  if (report_has_section_name(report, ".rustc") ||
      symbol_table_has_prefix(symbols, "_RN") ||
      symbol_table_has_fragment(symbols, "rust_eh_personality") ||
      symbol_table_has_fragment(symbols, "core::panicking") ||
      symbol_table_has_fragment(symbols, "alloc::") ||
      symbol_table_has_fragment(symbols, "std::rt::lang_start")) {
    maybe_set_language_guess(report, &best_score, 90, "Rust",
                             "Rust runtime or mangled symbol markers were found");
  }

  if (symbol_table_has_prefix(symbols, "_Z") ||
      symbol_table_has_fragment(symbols, "__gxx_personality_v0") ||
      symbol_table_has_fragment(symbols, "std::") ||
      symbol_table_has_fragment(symbols, "vtable for")) {
    maybe_set_language_guess(report, &best_score, 80, "C++",
                             "C++ ABI or mangled symbol markers were found");
  }

  if (symbol_table_has_fragment(symbols, "NimMain") ||
      symbol_table_has_fragment(symbols, "nimFrame") ||
      symbol_table_has_fragment(symbols, "nimGC_")) {
    maybe_set_language_guess(report, &best_score, 75, "Nim",
                             "Nim runtime markers were found");
  }

  if (symbol_table_has_fragment(symbols, "__zig_probe_stack")) {
    maybe_set_language_guess(report, &best_score, 70, "Zig",
                             "Zig runtime support symbols were found");
  }

  if (symbol_table_has_fragment(symbols, "dmd_personality") ||
      symbol_table_has_fragment(symbols, "object.TypeInfo")) {
    maybe_set_language_guess(report, &best_score, 65, "D",
                             "D runtime or mangled symbol markers were found");
  }

  if (best_score == 0) {
    report->language_known = true;
    set_report_text(report->language, sizeof(report->language), "C or C++");
    set_report_text(report->language_reason, sizeof(report->language_reason),
                    "no stronger language-specific runtime markers were found");
  }
}

static const char *pe_loader_name(uint16_t subsystem) {
  switch (subsystem) {
    case IMAGE_SUBSYSTEM_NATIVE:
      return "native PE loader";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
    case IMAGE_SUBSYSTEM_EFI_ROM:
      return "UEFI PE loader";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
      return "Windows boot loader";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
    default:
      return "Windows PE loader";
  }
}

static const char *pe_subsystem_name(uint16_t subsystem) {
  switch (subsystem) {
    case 0:
      return "Unknown";
    case IMAGE_SUBSYSTEM_NATIVE:
      return "Native";
    case IMAGE_SUBSYSTEM_WINDOWS_GUI:
      return "Windows GUI";
    case IMAGE_SUBSYSTEM_WINDOWS_CUI:
      return "Windows CUI";
    case 5:
      return "OS/2 CUI";
    case 7:
      return "POSIX CUI";
    case 9:
      return "Windows CE";
    case IMAGE_SUBSYSTEM_EFI_APPLICATION:
      return "EFI Application";
    case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
      return "EFI Boot Service Driver";
    case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
      return "EFI Runtime Driver";
    case IMAGE_SUBSYSTEM_EFI_ROM:
      return "EFI ROM";
    case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:
      return "Windows Boot Application";
    default:
      return "Unknown";
  }
}

static bool symbol_table_has_any_fragment(const symbol_table_t *table,
                                          const char *const *fragments,
                                          size_t fragment_count) {
  for (size_t index = 0; index < fragment_count; ++index) {
    if (symbol_table_has_fragment(table, fragments[index])) {
      return true;
    }
  }
  return false;
}

static void collect_compiler_comments(bfd *abfd, analysis_report_t *report) {
  asection *section;
  bfd_byte *contents = NULL;
  size_t size;
  size_t offset = 0;

  if (abfd == NULL || report == NULL) {
    return;
  }

  section = bfd_get_section_by_name(abfd, ".comment");
  if (section == NULL || bfd_section_size(section) == 0) {
    return;
  }

  if (!bfd_get_full_section_contents(abfd, section, &contents)) {
    return;
  }

  size = (size_t)bfd_section_size(section);
  while (offset < size) {
    size_t remaining = size - offset;
    size_t length = strnlen((const char *)(contents + offset), remaining);

    if (length == remaining) {
      break;
    }

    if (length != 0) {
      if (!append_string_unique(&report->compiler_comments,
                                (const char *)(contents + offset))) {
        break;
      }
    }

    offset += length + 1;
  }

  if (report->compiler_comments.count != 0) {
    report->provenance_available = true;
    report->provenance_is_elf = true;
  }

  free(contents);
}

static void collect_elf_provenance_from_sections(bfd *abfd,
                                                 analysis_report_t *report) {
  asection *section;
  bfd_byte *contents = NULL;

  if (abfd == NULL || report == NULL) {
    return;
  }

  section = bfd_get_section_by_name(abfd, ".note.gnu.build-id");
  if (section != NULL && bfd_section_size(section) >= 16 &&
      bfd_get_full_section_contents(abfd, section, &contents)) {
    bool big_endian = bfd_big_endian(abfd);
    size_t size = (size_t)bfd_section_size(section);
    size_t offset = 0;

    while (offset + 12 <= size) {
      uint32_t namesz = read_u32_endian_bytes(contents + offset, big_endian);
      uint32_t descsz = read_u32_endian_bytes(contents + offset + 4, big_endian);
      uint32_t type = read_u32_endian_bytes(contents + offset + 8, big_endian);
      size_t name_offset = offset + 12;
      size_t desc_offset = (name_offset + namesz + 3U) & ~((size_t)3U);
      size_t next = (desc_offset + descsz + 3U) & ~((size_t)3U);

      if (desc_offset > size || next > size) {
        break;
      }

      if (type == 3 && namesz >= 3 && name_offset + namesz <= size &&
          memcmp(contents + name_offset, "GNU", 3) == 0 &&
          descsz * 2 + 1 <= sizeof(report->elf_build_id)) {
        for (uint32_t index = 0; index < descsz; ++index) {
          snprintf(report->elf_build_id + index * 2,
                   sizeof(report->elf_build_id) - index * 2, "%02x",
                   contents[desc_offset + index]);
        }
        report->provenance_available = true;
        report->provenance_is_elf = true;
        break;
      }

      offset = next;
    }

    free(contents);
    contents = NULL;
  }

  section = bfd_get_section_by_name(abfd, ".gnu_debuglink");
  if (section != NULL && bfd_section_size(section) >= 4 &&
      bfd_get_full_section_contents(abfd, section, &contents)) {
    bool big_endian = bfd_big_endian(abfd);
    size_t size = (size_t)bfd_section_size(section);
    size_t name_length = strnlen((const char *)contents, size);

    if (name_length < size) {
      set_report_text(report->elf_debuglink, sizeof(report->elf_debuglink),
                      (const char *)contents);
      report->provenance_available = true;
      report->provenance_is_elf = true;

      {
        size_t crc_offset = (name_length + 1U + 3U) & ~((size_t)3U);
        if (crc_offset + 4 <= size) {
          report->elf_debuglink_crc_known = true;
          report->elf_debuglink_crc32 =
              read_u32_endian_bytes(contents + crc_offset, big_endian);
        }
      }
    }

    free(contents);
    contents = NULL;
  }

  collect_compiler_comments(abfd, report);
}

static void collect_elf_security_context(const bfd_byte *buffer, size_t size,
                                         const symbol_table_t *symbols,
                                         analysis_report_t *report) {
  bool is64;
  bool big_endian;
  uint16_t type;
  uint64_t phoff;
  uint16_t phentsize;
  uint16_t phnum;
  bool has_interp = false;
  bool has_gnu_stack = false;
  bool stack_executable = false;
  bool has_gnu_relro = false;
  bool has_tls = false;
  bool bind_now = false;
  static const char *const fortify_markers[] = {
      "__memcpy_chk", "__memmove_chk", "__sprintf_chk",
      "__snprintf_chk", "__printf_chk", "__fprintf_chk",
  };

  if (size < 64 || report == NULL ||
      (buffer[EI_CLASS] != ELFCLASS32 && buffer[EI_CLASS] != ELFCLASS64) ||
      (buffer[EI_DATA] != ELFDATA2LSB && buffer[EI_DATA] != ELFDATA2MSB)) {
    return;
  }

  is64 = buffer[EI_CLASS] == ELFCLASS64;
  big_endian = buffer[EI_DATA] == ELFDATA2MSB;
  type = read_u16_endian_bytes(buffer + 16, big_endian);
  phoff = is64 ? read_u64_endian_bytes(buffer + 32, big_endian)
               : read_u32_endian_bytes(buffer + 28, big_endian);
  phentsize = read_u16_endian_bytes(buffer + (is64 ? 54 : 42), big_endian);
  phnum = read_u16_endian_bytes(buffer + (is64 ? 56 : 44), big_endian);

  if (phoff != 0 && phentsize != 0 && phnum != 0 &&
      phoff + (uint64_t)phentsize * phnum <= size) {
    for (uint16_t index = 0; index < phnum; ++index) {
      const bfd_byte *ph = buffer + phoff + (uint64_t)phentsize * index;
      uint32_t ph_type = read_u32_endian_bytes(ph, big_endian);
      uint32_t ph_flags = is64 ? read_u32_endian_bytes(ph + 4, big_endian)
                               : read_u32_endian_bytes(ph + 24, big_endian);

      if (ph_type == PT_INTERP) {
        has_interp = true;
      } else if (ph_type == PT_GNU_STACK) {
        has_gnu_stack = true;
        stack_executable = (ph_flags & 1U) != 0;
      } else if (ph_type == PT_GNU_RELRO) {
        has_gnu_relro = true;
      } else if (ph_type == PT_TLS) {
        has_tls = true;
      } else if (ph_type == PT_DYNAMIC) {
        uint64_t dynamic_offset = is64 ? read_u64_endian_bytes(ph + 8, big_endian)
                                       : read_u32_endian_bytes(ph + 4, big_endian);
        uint64_t dynamic_size = is64 ? read_u64_endian_bytes(ph + 32, big_endian)
                                     : read_u32_endian_bytes(ph + 16, big_endian);

        if (dynamic_offset < size && dynamic_size != 0 &&
            dynamic_offset + dynamic_size <= size) {
          for (uint64_t cursor = dynamic_offset;
               cursor + (uint64_t)(is64 ? 16U : 8U) <= dynamic_offset + dynamic_size;
               cursor += (uint64_t)(is64 ? 16U : 8U)) {
            uint64_t tag = is64 ? read_u64_endian_bytes(buffer + cursor, big_endian)
                                : read_u32_endian_bytes(buffer + cursor, big_endian);
            uint64_t value =
                is64 ? read_u64_endian_bytes(buffer + cursor + 8, big_endian)
                     : read_u32_endian_bytes(buffer + cursor + 4, big_endian);

            if (tag == DT_NULL) {
              break;
            }

            if (tag == DT_BIND_NOW ||
                (tag == DT_FLAGS && (value & DF_BIND_NOW) != 0) ||
                (tag == DT_FLAGS_1 && (value & DF_1_NOW) != 0)) {
              bind_now = true;
            }
          }
        }
      }
    }
  }

  report->security_context_available = true;
  report->security_context_is_elf = true;
  report->nx_known = has_gnu_stack;
  report->nx_enabled = has_gnu_stack && !stack_executable;
  snprintf(report->relro, sizeof(report->relro), "%s",
           has_gnu_relro ? (bind_now ? "full" : "partial") : "none");
  report->canary_present =
      symbol_table_has_fragment(symbols, "__stack_chk_fail") ||
      symbol_table_has_fragment(symbols, "__intel_security_cookie");
  report->fortify_present =
      symbol_table_has_any_fragment(symbols, fortify_markers,
                                    sizeof(fortify_markers) /
                                        sizeof(fortify_markers[0]));
  report->tls_present = has_tls || report_has_section_name(report, ".tdata") ||
                        report_has_section_name(report, ".tbss");

  if (type == ET_DYN && has_interp) {
    set_report_text(report->execution_model, sizeof(report->execution_model),
                    "PIE executable");
  } else if (type == ET_DYN) {
    set_report_text(report->execution_model, sizeof(report->execution_model),
                    "shared object");
  } else if (type == ET_EXEC) {
    set_report_text(report->execution_model, sizeof(report->execution_model),
                    "non-PIE executable");
  } else if (type == ET_REL) {
    set_report_text(report->execution_model, sizeof(report->execution_model),
                    "relocatable object");
  } else {
    set_report_text(report->execution_model, sizeof(report->execution_model),
                    "unknown");
  }
}

static void format_pe_guid(const bfd_byte *bytes, char *buffer, size_t size) {
  if (buffer == NULL || size == 0) {
    return;
  }

  snprintf(buffer, size,
           "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
           "%02x%02x%02x%02x%02x%02x",
           bytes[3], bytes[2], bytes[1], bytes[0], bytes[5], bytes[4], bytes[7],
           bytes[6], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
           bytes[13], bytes[14], bytes[15]);
}

static void collect_pe_security_context(const bfd_byte *buffer, size_t size,
                                        analysis_report_t *report) {
  size_t pe_offset;
  const bfd_byte *coff;
  const bfd_byte *optional;
  const bfd_byte *section_table;
  uint16_t optional_magic;
  bool pe32_plus;
  uint16_t section_count;
  uint16_t optional_size;
  uint16_t subsystem;
  uint16_t dll_characteristics;
  uint32_t directory_count;
  uint32_t size_of_headers;
  uint64_t image_base;
  uint32_t tls_rva = 0;
  uint32_t tls_size = 0;

  if (size < 0x40 || buffer[0] != 'M' || buffer[1] != 'Z' || report == NULL) {
    return;
  }

  pe_offset = read_u32_le_bytes(buffer + 0x3c);
  if (pe_offset + 24 > size || memcmp(buffer + pe_offset, "PE\0\0", 4) != 0) {
    return;
  }

  coff = buffer + pe_offset + 4;
  optional = coff + 20;
  section_count = read_u16_le_bytes(coff + 2);
  optional_size = read_u16_le_bytes(coff + 16);
  if ((size_t)(optional - buffer) + optional_size > size || optional_size < 96) {
    return;
  }

  optional_magic = read_u16_le_bytes(optional);
  pe32_plus = optional_magic == 0x20b;
  if (optional_magic != 0x10b && optional_magic != 0x20b) {
    return;
  }

  subsystem = read_u16_le_bytes(optional + 68);
  dll_characteristics = read_u16_le_bytes(optional + 70);
  directory_count = read_u32_le_bytes(optional + (pe32_plus ? 108 : 92));
  if (directory_count > 16) {
    directory_count = 16;
  }

  size_of_headers = read_u32_le_bytes(optional + 60);
  image_base = pe32_plus ? read_u64_le_bytes(optional + 24)
                         : read_u32_le_bytes(optional + 28);
  section_table = optional + optional_size;
  if ((size_t)(section_table - buffer) + (size_t)section_count * 40 > size) {
    return;
  }

  if (directory_count > PE_DIRECTORY_TLS) {
    const bfd_byte *entry =
        optional + (pe32_plus ? 112 : 96) + (size_t)PE_DIRECTORY_TLS * 8;
    tls_rva = read_u32_le_bytes(entry);
    tls_size = read_u32_le_bytes(entry + 4);
  }

  report->security_context_available = true;
  report->security_context_is_pe = true;
  report->pe_subsystem = subsystem;
  set_report_text(report->execution_model, sizeof(report->execution_model),
                  pe_subsystem_name(subsystem));
  report->aslr_known = true;
  report->aslr_enabled =
      (dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0;
  report->nx_known = true;
  report->nx_enabled =
      (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0;
  report->cfg_known = true;
  report->cfg_enabled =
      (dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;
  report->high_entropy_va_known = true;
  report->high_entropy_va_enabled =
      (dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0;
  report->force_integrity_known = true;
  report->force_integrity_enabled =
      (dll_characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0;
  report->no_seh_known = true;
  report->no_seh_enabled =
      (dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0;

  if (tls_rva != 0 && tls_size != 0) {
    size_t tls_offset;

    if (map_pe_rva_to_offset(section_table, section_count, size_of_headers, size,
                             tls_rva, &tls_offset) &&
        tls_offset + (pe32_plus ? 32U : 16U) <= size) {
      uint64_t callbacks = pe32_plus ? read_u64_le_bytes(buffer + tls_offset + 24)
                                     : read_u32_le_bytes(buffer + tls_offset + 12);
      if (callbacks >= image_base) {
        callbacks -= image_base;
      }
      report->pe_tls_callbacks_present = callbacks != 0;
    }
  }
}

static void collect_pe_provenance(const bfd_byte *buffer, size_t size,
                                  analysis_report_t *report) {
  size_t pe_offset;
  const bfd_byte *coff;
  const bfd_byte *optional;
  const bfd_byte *section_table;
  uint16_t optional_magic;
  bool pe32_plus;
  uint16_t section_count;
  uint16_t optional_size;
  uint32_t directory_count;
  uint32_t size_of_headers;
  uint32_t debug_rva = 0;
  uint32_t debug_size = 0;
  uint32_t timestamp;

  if (size < 0x40 || buffer[0] != 'M' || buffer[1] != 'Z' || report == NULL) {
    return;
  }

  pe_offset = read_u32_le_bytes(buffer + 0x3c);
  if (pe_offset + 24 > size || memcmp(buffer + pe_offset, "PE\0\0", 4) != 0) {
    return;
  }

  coff = buffer + pe_offset + 4;
  optional = coff + 20;
  section_count = read_u16_le_bytes(coff + 2);
  optional_size = read_u16_le_bytes(coff + 16);
  timestamp = read_u32_le_bytes(coff + 4);
  if ((size_t)(optional - buffer) + optional_size > size || optional_size < 96) {
    return;
  }

  optional_magic = read_u16_le_bytes(optional);
  pe32_plus = optional_magic == 0x20b;
  if (optional_magic != 0x10b && optional_magic != 0x20b) {
    return;
  }

  directory_count = read_u32_le_bytes(optional + (pe32_plus ? 108 : 92));
  if (directory_count > 16) {
    directory_count = 16;
  }

  size_of_headers = read_u32_le_bytes(optional + 60);
  section_table = optional + optional_size;
  if ((size_t)(section_table - buffer) + (size_t)section_count * 40 > size) {
    return;
  }

  report->pe_timestamp_known = timestamp != 0;
  report->pe_timestamp = timestamp;
  if (timestamp != 0) {
    pe_timestamp_to_text(timestamp, report->pe_timestamp_text,
                         sizeof(report->pe_timestamp_text));
  }

  for (size_t index = 0x40; index + 4 <= pe_offset && index + 4 <= size; ++index) {
    if (memcmp(buffer + index, "Rich", 4) == 0) {
      report->pe_rich_header_present = true;
      break;
    }
  }

  if (directory_count > PE_DIRECTORY_SECURITY) {
    const bfd_byte *entry =
        optional + (pe32_plus ? 112 : 96) + (size_t)PE_DIRECTORY_SECURITY * 8;
    uint32_t file_offset = read_u32_le_bytes(entry);
    uint32_t file_size = read_u32_le_bytes(entry + 4);

    if (file_offset != 0 && file_size != 0 && file_offset < size &&
        (uint64_t)file_offset + file_size <= size) {
      report->pe_authenticode_present = true;
      report->pe_authenticode_offset = file_offset;
      report->pe_authenticode_size = file_size;
    }
  }

  if (directory_count > PE_DIRECTORY_DEBUG) {
    const bfd_byte *entry =
        optional + (pe32_plus ? 112 : 96) + (size_t)PE_DIRECTORY_DEBUG * 8;
    debug_rva = read_u32_le_bytes(entry);
    debug_size = read_u32_le_bytes(entry + 4);
  }

  if (debug_rva != 0 && debug_size >= 28) {
    size_t debug_offset;

    if (map_pe_rva_to_offset(section_table, section_count, size_of_headers, size,
                             debug_rva, &debug_offset)) {
      size_t entry_count = debug_size / 28U;

      for (size_t index = 0; index < entry_count; ++index) {
        const bfd_byte *debug_entry = buffer + debug_offset + index * 28U;
        uint32_t type;
        uint32_t data_size;
        uint32_t data_pointer;

        if ((size_t)(debug_entry - buffer) + 28 > size) {
          break;
        }

        type = read_u32_le_bytes(debug_entry + 12);
        data_size = read_u32_le_bytes(debug_entry + 16);
        data_pointer = read_u32_le_bytes(debug_entry + 24);

        if (type == IMAGE_DEBUG_TYPE_REPRO) {
          report->pe_repro_debug_present = true;
          continue;
        }

        if (type == IMAGE_DEBUG_TYPE_CODEVIEW && data_pointer < size &&
            (uint64_t)data_pointer + data_size <= size && data_size >= 24 &&
            memcmp(buffer + data_pointer, "RSDS", 4) == 0) {
          const bfd_byte *codeview = buffer + data_pointer;
          const char *pdb_path =
              bounded_file_string(buffer, size, data_pointer + 24, data_size - 24);

          report->pe_codeview_present = true;
          format_pe_guid(codeview + 4, report->pe_codeview_guid,
                         sizeof(report->pe_codeview_guid));
          report->pe_codeview_age = read_u32_le_bytes(codeview + 20);
          if (pdb_path != NULL) {
            set_report_text(report->pe_pdb_path, sizeof(report->pe_pdb_path),
                            pdb_path);
          }
        }
      }
    }
  }

  if (report->pe_timestamp_known || report->pe_rich_header_present ||
      report->pe_authenticode_present || report->pe_codeview_present ||
      report->pe_repro_debug_present) {
    report->provenance_available = true;
    report->provenance_is_pe = true;
  }
}

static const char *pe_resource_type_name(uint32_t id) {
  switch (id) {
    case 1:
      return "CURSOR";
    case 2:
      return "BITMAP";
    case 3:
      return "ICON";
    case 4:
      return "MENU";
    case 5:
      return "DIALOG";
    case 6:
      return "STRING";
    case 7:
      return "FONTDIR";
    case 8:
      return "FONT";
    case 9:
      return "ACCELERATOR";
    case 10:
      return "RCDATA";
    case 11:
      return "MESSAGETABLE";
    case 12:
      return "GROUP_CURSOR";
    case 14:
      return "GROUP_ICON";
    case 16:
      return "VERSION";
    case 17:
      return "DLGINCLUDE";
    case 19:
      return "PLUGPLAY";
    case 20:
      return "VXD";
    case 21:
      return "ANICURSOR";
    case 22:
      return "ANIICON";
    case 23:
      return "HTML";
    case 24:
      return "MANIFEST";
    default:
      return NULL;
  }
}

static void format_pe_resource_identifier(char *buffer, size_t size,
                                          const char *prefix, uint32_t value) {
  if (buffer == NULL || size == 0) {
    return;
  }

  snprintf(buffer, size, "%s#%u", prefix, value);
}

static bool read_pe_resource_name_string(const bfd_byte *buffer, size_t size,
                                         size_t resource_base_offset,
                                         uint32_t name_offset,
                                         char *out, size_t out_size) {
  size_t absolute_offset = resource_base_offset + (size_t)name_offset;
  size_t length;
  size_t used = 0;

  if (out == NULL || out_size == 0 || absolute_offset + 2 > size) {
    return false;
  }

  length = read_u16_le_bytes(buffer + absolute_offset);
  absolute_offset += 2;
  if (absolute_offset + length * 2 > size) {
    return false;
  }

  for (size_t index = 0; index < length && used + 1 < out_size; ++index) {
    uint16_t code_unit = read_u16_le_bytes(buffer + absolute_offset + index * 2);

    out[used++] = (code_unit >= 0x20 && code_unit <= 0x7e)
                      ? (char)code_unit
                      : '?';
  }
  out[used] = '\0';
  return used != 0;
}

static bool pe_resource_directory_bounds(const bfd_byte *section_table,
                                         uint16_t section_count,
                                         uint32_t resource_rva,
                                         size_t size, size_t *section_end_out) {
  for (uint16_t index = 0; index < section_count; ++index) {
    const bfd_byte *section = section_table + (size_t)index * 40U;
    uint32_t virtual_size = read_u32_le_bytes(section + 8);
    uint32_t virtual_address = read_u32_le_bytes(section + 12);
    uint32_t raw_size = read_u32_le_bytes(section + 16);
    uint32_t raw_pointer = read_u32_le_bytes(section + 20);
    uint32_t span = max_u32(virtual_size, raw_size);
    size_t section_end;

    if (span == 0 || resource_rva < virtual_address ||
        resource_rva >= virtual_address + span) {
      continue;
    }
    if (raw_pointer >= size) {
      return false;
    }

    section_end = (size_t)raw_pointer + raw_size;
    if (section_end > size) {
      section_end = size;
    }
    *section_end_out = section_end;
    return true;
  }

  return false;
}

static bool collect_pe_resource_directory_entries(
    const bfd_byte *buffer, size_t size, const bfd_byte *section_table,
    uint16_t section_count, uint32_t size_of_headers, size_t resource_base_offset,
    size_t resource_section_end, uint32_t directory_relative_offset,
    unsigned depth, const char *type_label, const char *name_label,
    const char *language_label, analysis_report_t *report) {
  size_t directory_offset = resource_base_offset + (size_t)directory_relative_offset;
  uint16_t named_count;
  uint16_t id_count;
  size_t total_entries;

  if (depth > 4 || directory_offset + 16 > resource_section_end ||
      directory_offset + 16 > size) {
    return true;
  }

  named_count = read_u16_le_bytes(buffer + directory_offset + 12);
  id_count = read_u16_le_bytes(buffer + directory_offset + 14);
  total_entries = (size_t)named_count + id_count;
  if (directory_offset + 16 + total_entries * 8 > resource_section_end ||
      directory_offset + 16 + total_entries * 8 > size) {
    return true;
  }

  for (size_t index = 0; index < total_entries; ++index) {
    const bfd_byte *entry = buffer + directory_offset + 16 + index * 8;
    uint32_t name_or_id = read_u32_le_bytes(entry);
    uint32_t data_or_subdir = read_u32_le_bytes(entry + 4);
    char current_type[32];
    char current_name[96];
    char current_language[32];

    snprintf(current_type, sizeof(current_type), "%s",
             type_label != NULL ? type_label : "");
    snprintf(current_name, sizeof(current_name), "%s",
             name_label != NULL ? name_label : "");
    snprintf(current_language, sizeof(current_language), "%s",
             language_label != NULL ? language_label : "");

    if (depth == 0) {
      if ((name_or_id & UINT32_C(0x80000000)) != 0) {
        if (!read_pe_resource_name_string(
                buffer, size, resource_base_offset, name_or_id & 0x7fffffffU,
                current_type, sizeof(current_type))) {
          snprintf(current_type, sizeof(current_type), "TYPE_NAME");
        }
      } else {
        const char *known_type = pe_resource_type_name(name_or_id);

        if (known_type != NULL) {
          snprintf(current_type, sizeof(current_type), "%s", known_type);
        } else {
          format_pe_resource_identifier(current_type, sizeof(current_type),
                                        "TYPE", name_or_id);
        }
      }
    } else if (depth == 1) {
      if ((name_or_id & UINT32_C(0x80000000)) != 0) {
        if (!read_pe_resource_name_string(
                buffer, size, resource_base_offset, name_or_id & 0x7fffffffU,
                current_name, sizeof(current_name))) {
          snprintf(current_name, sizeof(current_name), "NAME");
        }
      } else {
        format_pe_resource_identifier(current_name, sizeof(current_name), "ID",
                                      name_or_id);
      }
    } else if (depth == 2) {
      snprintf(current_language, sizeof(current_language), "0x%04x",
               (unsigned)(name_or_id & 0xffffU));
    }

    if ((data_or_subdir & UINT32_C(0x80000000)) != 0) {
      if (!collect_pe_resource_directory_entries(
              buffer, size, section_table, section_count, size_of_headers,
              resource_base_offset, resource_section_end,
              data_or_subdir & 0x7fffffffU, depth + 1, current_type,
              current_name, current_language, report)) {
        return false;
      }
      continue;
    }

    if (depth >= 2) {
      size_t data_entry_offset =
          resource_base_offset + (size_t)(data_or_subdir & 0x7fffffffU);
      pe_resource_entry_t resource_entry;
      uint32_t data_rva;

      if (data_entry_offset + 16 > resource_section_end ||
          data_entry_offset + 16 > size) {
        continue;
      }

      memset(&resource_entry, 0, sizeof(resource_entry));
      data_rva = read_u32_le_bytes(buffer + data_entry_offset);
      resource_entry.data_rva = data_rva;
      resource_entry.data_size = read_u32_le_bytes(buffer + data_entry_offset + 4);
      resource_entry.codepage =
          read_u32_le_bytes(buffer + data_entry_offset + 8);
      snprintf(resource_entry.type, sizeof(resource_entry.type), "%s",
               current_type[0] != '\0' ? current_type : "TYPE");
      snprintf(resource_entry.name, sizeof(resource_entry.name), "%s",
               current_name[0] != '\0' ? current_name : "ID");
      snprintf(resource_entry.language, sizeof(resource_entry.language), "%s",
               current_language[0] != '\0' ? current_language : "0x0000");

      if (map_pe_rva_to_offset(section_table, section_count, size_of_headers, size,
                               data_rva, &resource_entry.data_offset)) {
        resource_entry.data_offset_known = true;
      }

      if (!append_pe_resource_entry(report, &resource_entry)) {
        return false;
      }
    }
  }

  return true;
}

static bool collect_pe_resources(const bfd_byte *buffer, size_t size,
                                 analysis_report_t *report) {
  size_t pe_offset;
  const bfd_byte *coff;
  const bfd_byte *optional;
  const bfd_byte *section_table;
  uint16_t optional_magic;
  bool pe32_plus;
  uint16_t section_count;
  uint16_t optional_size;
  uint32_t directory_count;
  uint32_t size_of_headers;
  uint32_t resource_rva = 0;
  uint32_t resource_size = 0;
  size_t resource_base_offset;
  size_t resource_section_end;

  if (size < 0x40 || buffer[0] != 'M' || buffer[1] != 'Z' || report == NULL) {
    return true;
  }

  pe_offset = read_u32_le_bytes(buffer + 0x3c);
  if (pe_offset + 24 > size || memcmp(buffer + pe_offset, "PE\0\0", 4) != 0) {
    return true;
  }

  coff = buffer + pe_offset + 4;
  optional = coff + 20;
  section_count = read_u16_le_bytes(coff + 2);
  optional_size = read_u16_le_bytes(coff + 16);
  if ((size_t)(optional - buffer) + optional_size > size || optional_size < 96) {
    return true;
  }

  optional_magic = read_u16_le_bytes(optional);
  pe32_plus = optional_magic == 0x20b;
  if (optional_magic != 0x10b && optional_magic != 0x20b) {
    return true;
  }

  directory_count = read_u32_le_bytes(optional + (pe32_plus ? 108 : 92));
  if (directory_count > 16) {
    directory_count = 16;
  }

  size_of_headers = read_u32_le_bytes(optional + 60);
  section_table = optional + optional_size;
  if ((size_t)(section_table - buffer) + (size_t)section_count * 40 > size) {
    return true;
  }

  if (directory_count > PE_DIRECTORY_RESOURCE) {
    const bfd_byte *entry =
        optional + (pe32_plus ? 112 : 96) + (size_t)PE_DIRECTORY_RESOURCE * 8U;

    resource_rva = read_u32_le_bytes(entry);
    resource_size = read_u32_le_bytes(entry + 4);
  }

  if (resource_rva == 0 || resource_size < 16) {
    return true;
  }

  if (!map_pe_rva_to_offset(section_table, section_count, size_of_headers, size,
                            resource_rva, &resource_base_offset) ||
      !pe_resource_directory_bounds(section_table, section_count, resource_rva,
                                    size, &resource_section_end)) {
    return true;
  }

  report->pe_resources_available = true;
  return collect_pe_resource_directory_entries(
      buffer, size, section_table, section_count, size_of_headers,
      resource_base_offset, resource_section_end, 0, 0, NULL, NULL, NULL,
      report);
}

static void collect_overlay_analysis(const bfd_byte *buffer, size_t size,
                                     analysis_report_t *report) {
  static const struct {
    const char *kind;
    const bfd_byte magic[8];
    size_t magic_size;
  } signature_rules[] = {
      {"PE executable", {'M', 'Z'}, 2},
      {"ELF executable", {0x7f, 'E', 'L', 'F'}, 4},
      {"ZIP archive", {'P', 'K', 0x03, 0x04}, 4},
      {"ZIP end of central directory", {'P', 'K', 0x05, 0x06}, 4},
      {"GZip stream", {0x1f, 0x8b, 0x08}, 3},
      {"7-Zip archive", {'7', 'z', 0xbc, 0xaf, 0x27, 0x1c}, 6},
      {"RAR archive", {'R', 'a', 'r', '!', 0x1a, 0x07}, 6},
      {"CAB archive", {'M', 'S', 'C', 'F'}, 4},
      {"PNG image", {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}, 8},
      {"PDF document", {'%', 'P', 'D', 'F', '-'}, 5},
  };
  size_t max_end = 0;
  bool have_reference = false;

  if (buffer == NULL || report == NULL) {
    return;
  }

  for (size_t index = 0; index < report->section_count; ++index) {
    const section_report_t *section = &report->sections[index];
    size_t section_size;
    uintmax_t end;

    if (!section->has_contents || section->filepos < 0) {
      continue;
    }

    section_size = section->rawsize != 0 ? (size_t)section->rawsize
                 : section->compressed_size != 0
                     ? (size_t)section->compressed_size
                     : (size_t)section->size;
    end = (uintmax_t)section->filepos + section_size;
    if (end > size) {
      end = size;
    }
    if ((size_t)end > max_end) {
      max_end = (size_t)end;
    }
    have_reference = true;
  }

  if (!have_reference) {
    return;
  }

  report->overlay_analysis_available = true;
  report->overlay_offset = max_end < size ? max_end : size;
  report->overlay_size = size > report->overlay_offset ? size - report->overlay_offset
                                                       : 0;
  if (report->overlay_size == 0) {
    return;
  }

  report->overlay_hashes_available = true;
  report->overlay_entropy = shannon_entropy(buffer + report->overlay_offset,
                                            (bfd_size_type)report->overlay_size);
  report->overlay_crc32_value = crc32_bytes(buffer + report->overlay_offset,
                                            (bfd_size_type)report->overlay_size);

  for (size_t rule_index = 0;
       rule_index < sizeof(signature_rules) / sizeof(signature_rules[0]);
       ++rule_index) {
    const size_t start = report->overlay_offset;
    const size_t limit =
        size >= signature_rules[rule_index].magic_size
            ? size - signature_rules[rule_index].magic_size
            : 0;

    for (size_t offset = start;
         offset <= limit &&
         report->embedded_signature_count < MAX_EMBEDDED_SIGNATURE_HITS;
         ++offset) {
      if (memcmp(buffer + offset, signature_rules[rule_index].magic,
                 signature_rules[rule_index].magic_size) == 0 &&
          !append_embedded_signature(report, offset,
                                     signature_rules[rule_index].kind)) {
        return;
      }
    }
  }
}

static bool find_marker_bytes(const bfd_byte *buffer, size_t size,
                              const char *needle, size_t *offset_out) {
  size_t needle_size;

  if (buffer == NULL || needle == NULL) {
    return false;
  }

  needle_size = strlen(needle);
  if (needle_size == 0 || needle_size > size) {
    return false;
  }

  for (size_t offset = 0; offset + needle_size <= size; ++offset) {
    if (memcmp(buffer + offset, needle, needle_size) == 0) {
      if (offset_out != NULL) {
        *offset_out = offset;
      }
      return true;
    }
  }

  return false;
}

static void collect_protector_hints(const bfd_byte *buffer, size_t size,
                                    analysis_report_t *report) {
  if (report == NULL) {
    return;
  }

  if (report->upx_packed) {
    if (report->upx_pack_header_known) {
      append_protector_hint(report, "UPX", "packer", "high",
                            "validated UPX pack header v%u fmt%u",
                            report->upx_pack_header_version,
                            report->upx_pack_header_format);
    } else {
      append_protector_hint(report, "UPX", "packer", "medium",
                            "UPX marker or embedded version was detected");
    }
  }

  for (size_t index = 0; index < report->section_count; ++index) {
    const section_report_t *section = &report->sections[index];

    for (size_t rule_index = 0;
         rule_index < sizeof(k_protector_section_rules) /
                          sizeof(k_protector_section_rules[0]);
         ++rule_index) {
      const protector_rule_t *rule = &k_protector_section_rules[rule_index];

      if (report->upx_packed && strcmp(rule->name, "UPX") == 0) {
        continue;
      }
      if (ci_contains(section->name, rule->needle)) {
        append_protector_hint(report, rule->name, rule->kind, rule->confidence,
                              "section name '%s' matched '%s'", section->name,
                              rule->needle);
      }
    }
  }

  for (size_t rule_index = 0;
       rule_index < sizeof(k_protector_marker_rules) /
                        sizeof(k_protector_marker_rules[0]);
       ++rule_index) {
    const protector_rule_t *rule = &k_protector_marker_rules[rule_index];
    size_t offset = 0;

    if (report->upx_packed && strcmp(rule->name, "UPX") == 0) {
      continue;
    }
    if (find_marker_bytes(buffer, size, rule->needle, &offset)) {
      append_protector_hint(report, rule->name, rule->kind, rule->confidence,
                            "marker '%s' at file offset 0x%zx", rule->needle,
                            offset);
    }
  }

  if (report->entry_section != NULL && report->entry_section->high_entropy) {
    append_protector_hint(report, "generic packed/encrypted code", "heuristic",
                          "medium",
                          "entry point section '%s' has high entropy %.2f",
                          report->entry_section->name,
                          report->entry_section->entropy);
  }

  if (report->highest_entropy_section != NULL &&
      report->highest_entropy_section->entropy >= 7.60 &&
      report->highest_entropy_section->size >= 4096) {
    append_protector_hint(report, "generic packed/encrypted payload",
                          "heuristic", "low",
                          "section '%s' entropy is %.2f over %" PRIuMAX
                          " bytes",
                          report->highest_entropy_section->name,
                          report->highest_entropy_section->entropy,
                          (uintmax_t)report->highest_entropy_section->size);
  }

  if (report->overlay_analysis_available && report->overlay_size >= 4096 &&
      report->overlay_hashes_available && report->overlay_entropy >= 7.20) {
    append_protector_hint(report, "high-entropy overlay", "heuristic", "low",
                          "overlay entropy is %.2f over %zu bytes",
                          report->overlay_entropy, report->overlay_size);
  }

  if (report->dependency_summary_is_pe && report->pe_import_count <= 1 &&
      report->highest_entropy_section != NULL &&
      report->highest_entropy_section->entropy >= 7.20) {
    append_protector_hint(report, "sparse imports with high entropy",
                          "heuristic", "low",
                          "PE has %zu import libraries and high section entropy %.2f",
                          report->pe_import_count,
                          report->highest_entropy_section->entropy);
  }
}

static uint32_t max_u32(uint32_t left, uint32_t right) {
  return left > right ? left : right;
}

static const char *bounded_file_string(const bfd_byte *buffer, size_t size,
                                       size_t offset, size_t max_length) {
  const void *terminator;

  if (buffer == NULL || offset >= size || max_length == 0 ||
      offset + max_length > size) {
    return NULL;
  }

  terminator = memchr(buffer + offset, '\0', max_length);
  if (terminator == NULL) {
    return NULL;
  }

  return (const char *)(buffer + offset);
}

static bool map_elf_vaddr_to_offset(const bfd_byte *buffer, size_t size,
                                    bool is64, bool big_endian, uint64_t phoff,
                                    uint16_t phentsize, uint16_t phnum,
                                    uint64_t vaddr, size_t *offset_out) {
  if (phoff == 0 || phentsize == 0 || phnum == 0 ||
      phoff + (uint64_t)phentsize * phnum > size) {
    return false;
  }

  for (uint16_t index = 0; index < phnum; ++index) {
    const bfd_byte *ph = buffer + phoff + (uint64_t)phentsize * index;
    uint32_t type = read_u32_endian_bytes(ph, big_endian);
    uint64_t segment_offset;
    uint64_t segment_vaddr;
    uint64_t segment_filesz;
    uint64_t segment_memsz;
    uint64_t delta;

    if (type != PT_LOAD) {
      continue;
    }

    if (is64) {
      segment_offset = read_u64_endian_bytes(ph + 8, big_endian);
      segment_vaddr = read_u64_endian_bytes(ph + 16, big_endian);
      segment_filesz = read_u64_endian_bytes(ph + 32, big_endian);
      segment_memsz = read_u64_endian_bytes(ph + 40, big_endian);
    } else {
      segment_offset = read_u32_endian_bytes(ph + 4, big_endian);
      segment_vaddr = read_u32_endian_bytes(ph + 8, big_endian);
      segment_filesz = read_u32_endian_bytes(ph + 16, big_endian);
      segment_memsz = read_u32_endian_bytes(ph + 20, big_endian);
    }

    if (vaddr < segment_vaddr || vaddr >= segment_vaddr + segment_memsz) {
      continue;
    }

    delta = vaddr - segment_vaddr;
    if (delta >= segment_filesz || segment_offset + delta >= size) {
      return false;
    }

    *offset_out = (size_t)(segment_offset + delta);
    return true;
  }

  return false;
}

static bool collect_elf_dependencies(const bfd_byte *buffer, size_t size,
                                     analysis_report_t *report) {
  bool is64;
  bool big_endian;
  uint64_t phoff;
  uint16_t phentsize;
  uint16_t phnum;
  uint64_t dynamic_offset = 0;
  uint64_t dynamic_size = 0;
  uint64_t strtab_vaddr = 0;
  uint64_t strtab_size = 0;
  uint64_t soname_offset = UINT64_MAX;
  uint64_t rpath_offset = UINT64_MAX;
  uint64_t runpath_offset = UINT64_MAX;
  uint64_t *needed_offsets = NULL;
  size_t needed_count = 0;
  size_t needed_capacity = 0;
  size_t strtab_offset = 0;
  bool success = true;

  if (size < 64 || buffer[0] != 0x7f || buffer[1] != 'E' || buffer[2] != 'L' ||
      buffer[3] != 'F' || buffer[EI_VERSION] != 1 ||
      (buffer[EI_CLASS] != ELFCLASS32 && buffer[EI_CLASS] != ELFCLASS64) ||
      (buffer[EI_DATA] != ELFDATA2LSB && buffer[EI_DATA] != ELFDATA2MSB)) {
    return true;
  }

  is64 = buffer[EI_CLASS] == ELFCLASS64;
  big_endian = buffer[EI_DATA] == ELFDATA2MSB;
  phoff = is64 ? read_u64_endian_bytes(buffer + 32, big_endian)
               : read_u32_endian_bytes(buffer + 28, big_endian);
  phentsize = read_u16_endian_bytes(buffer + (is64 ? 54 : 42), big_endian);
  phnum = read_u16_endian_bytes(buffer + (is64 ? 56 : 44), big_endian);

  if (phoff == 0 || phentsize == 0 || phnum == 0 ||
      phoff + (uint64_t)phentsize * phnum > size) {
    return true;
  }

  for (uint16_t index = 0; index < phnum; ++index) {
    const bfd_byte *ph = buffer + phoff + (uint64_t)phentsize * index;
    uint32_t type = read_u32_endian_bytes(ph, big_endian);

    if (type != PT_DYNAMIC) {
      continue;
    }

    if (is64) {
      dynamic_offset = read_u64_endian_bytes(ph + 8, big_endian);
      dynamic_size = read_u64_endian_bytes(ph + 32, big_endian);
    } else {
      dynamic_offset = read_u32_endian_bytes(ph + 4, big_endian);
      dynamic_size = read_u32_endian_bytes(ph + 16, big_endian);
    }
    break;
  }

  if (dynamic_size == 0 || dynamic_offset >= size ||
      dynamic_offset + dynamic_size > size) {
    free(needed_offsets);
    return true;
  }

  for (uint64_t cursor = dynamic_offset;
       cursor + (is64 ? 16U : 8U) <= dynamic_offset + dynamic_size;
       cursor += (uint64_t)(is64 ? 16U : 8U)) {
    uint64_t tag = is64 ? read_u64_endian_bytes(buffer + cursor, big_endian)
                        : read_u32_endian_bytes(buffer + cursor, big_endian);
    uint64_t value =
        is64 ? read_u64_endian_bytes(buffer + cursor + 8, big_endian)
             : read_u32_endian_bytes(buffer + cursor + 4, big_endian);

    if (tag == DT_NULL) {
      break;
    }

    switch (tag) {
      case DT_STRTAB:
        strtab_vaddr = value;
        break;
      case DT_STRSZ:
        strtab_size = value;
        break;
      case DT_SONAME:
        soname_offset = value;
        break;
      case DT_RPATH:
        rpath_offset = value;
        break;
      case DT_RUNPATH:
        runpath_offset = value;
        break;
      case DT_NEEDED:
        if (needed_count == needed_capacity) {
          size_t new_capacity = needed_capacity == 0 ? 4 : needed_capacity * 2;
          uint64_t *new_offsets =
              realloc(needed_offsets, new_capacity * sizeof(*new_offsets));
          if (new_offsets == NULL) {
            success = false;
            goto done;
          }
          needed_offsets = new_offsets;
          needed_capacity = new_capacity;
        }
        needed_offsets[needed_count++] = value;
        break;
      default:
        break;
    }
  }

  if (strtab_vaddr == 0 || strtab_size == 0 ||
      !map_elf_vaddr_to_offset(buffer, size, is64, big_endian, phoff, phentsize,
                               phnum, strtab_vaddr, &strtab_offset) ||
      strtab_offset + strtab_size > size) {
    goto done;
  }

  for (size_t index = 0; index < needed_count; ++index) {
    const char *name;

    if (needed_offsets[index] >= strtab_size) {
      continue;
    }

    name = bounded_file_string(buffer, size,
                               strtab_offset + (size_t)needed_offsets[index],
                               (size_t)(strtab_size - needed_offsets[index]));
    if (name != NULL &&
        !append_string_unique(&report->elf_needed_libraries, name)) {
      success = false;
      goto done;
    }
  }

  if (soname_offset < strtab_size) {
    const char *value = bounded_file_string(
        buffer, size, strtab_offset + (size_t)soname_offset,
        (size_t)(strtab_size - soname_offset));
    if (value != NULL) {
      set_report_text(report->elf_soname, sizeof(report->elf_soname), value);
    }
  }

  if (rpath_offset < strtab_size) {
    const char *value = bounded_file_string(
        buffer, size, strtab_offset + (size_t)rpath_offset,
        (size_t)(strtab_size - rpath_offset));
    if (value != NULL) {
      set_report_text(report->elf_rpath, sizeof(report->elf_rpath), value);
    }
  }

  if (runpath_offset < strtab_size) {
    const char *value = bounded_file_string(
        buffer, size, strtab_offset + (size_t)runpath_offset,
        (size_t)(strtab_size - runpath_offset));
    if (value != NULL) {
      set_report_text(report->elf_runpath, sizeof(report->elf_runpath), value);
    }
  }

  if (report->elf_needed_libraries.count != 0 || report->elf_soname[0] != '\0' ||
      report->elf_rpath[0] != '\0' || report->elf_runpath[0] != '\0') {
    report->dependency_summary_available = true;
    report->dependency_summary_is_elf = true;
  }

done:
  free(needed_offsets);
  return success;
}

static bool map_pe_rva_to_offset(const bfd_byte *section_table,
                                 uint16_t section_count, uint32_t size_of_headers,
                                 size_t size, uint32_t rva, size_t *offset_out) {
  if (rva < size_of_headers && rva < size) {
    *offset_out = (size_t)rva;
    return true;
  }

  for (uint16_t index = 0; index < section_count; ++index) {
    const bfd_byte *section = section_table + (size_t)index * 40;
    uint32_t virtual_size = read_u32_le_bytes(section + 8);
    uint32_t virtual_address = read_u32_le_bytes(section + 12);
    uint32_t raw_size = read_u32_le_bytes(section + 16);
    uint32_t raw_pointer = read_u32_le_bytes(section + 20);
    uint32_t span = max_u32(virtual_size, raw_size);
    uint32_t delta;

    if (span == 0 || rva < virtual_address || rva >= virtual_address + span) {
      continue;
    }

    delta = rva - virtual_address;
    if ((size_t)raw_pointer + delta >= size) {
      return false;
    }

    *offset_out = (size_t)raw_pointer + delta;
    return true;
  }

  return false;
}

static uint32_t normalize_pe_pointer_to_rva(uint64_t value, uint32_t attributes,
                                            uint64_t image_base) {
  if (attributes == 1) {
    return (uint32_t)value;
  }
  if (value >= image_base) {
    return (uint32_t)(value - image_base);
  }
  return 0;
}

static bool append_import_symbol(import_library_t *library, const char *symbol) {
  if (library == NULL) {
    return false;
  }
  return append_string_unique(&library->symbols, symbol);
}

static bool collect_pe_import_directory(
    const bfd_byte *buffer, size_t size, const bfd_byte *section_table,
    uint16_t section_count, uint32_t size_of_headers, bool pe32_plus,
    uint64_t image_base, uint32_t directory_rva, uint32_t directory_size,
    bool delay_imports, import_library_t **libraries, size_t *library_count,
    size_t *library_capacity) {
  size_t directory_offset;
  size_t max_descriptors;

  if (directory_rva == 0 || directory_size < 20 ||
      !map_pe_rva_to_offset(section_table, section_count, size_of_headers, size,
                            directory_rva, &directory_offset) ||
      directory_offset >= size) {
    return true;
  }

  max_descriptors = directory_size / (delay_imports ? 32U : 20U);
  if (max_descriptors == 0) {
    return true;
  }

  for (size_t index = 0; index < max_descriptors; ++index) {
    const bfd_byte *descriptor =
        buffer + directory_offset + index * (delay_imports ? 32U : 20U);
    uint32_t dll_name_rva;
    uint32_t thunk_rva;
    import_library_t *library;
    size_t dll_name_offset;
    const char *dll_name;

    if ((size_t)(descriptor - buffer) + (delay_imports ? 32U : 20U) > size) {
      break;
    }

    if (delay_imports) {
      uint32_t attributes = read_u32_le_bytes(descriptor);
      dll_name_rva = normalize_pe_pointer_to_rva(read_u32_le_bytes(descriptor + 4),
                                                 attributes, image_base);
      thunk_rva = normalize_pe_pointer_to_rva(read_u32_le_bytes(descriptor + 16),
                                              attributes, image_base);
      if (thunk_rva == 0) {
        thunk_rva = normalize_pe_pointer_to_rva(read_u32_le_bytes(descriptor + 12),
                                                attributes, image_base);
      }
      if (attributes == 0 && dll_name_rva == 0 && thunk_rva == 0) {
        dll_name_rva = (uint32_t)read_u64_le_bytes(descriptor + 4);
        thunk_rva = (uint32_t)read_u64_le_bytes(descriptor + 16);
      }
    } else {
      dll_name_rva = read_u32_le_bytes(descriptor + 12);
      thunk_rva = read_u32_le_bytes(descriptor);
      if (thunk_rva == 0) {
        thunk_rva = read_u32_le_bytes(descriptor + 16);
      }
    }

    if (dll_name_rva == 0 && thunk_rva == 0) {
      break;
    }

    if (!map_pe_rva_to_offset(section_table, section_count, size_of_headers, size,
                              dll_name_rva, &dll_name_offset)) {
      continue;
    }

    dll_name = bounded_file_string(buffer, size, dll_name_offset,
                                   size - dll_name_offset);
    if (dll_name == NULL) {
      continue;
    }

    library = find_or_add_import_library(libraries, library_count, library_capacity,
                                         dll_name);
    if (library == NULL) {
      return false;
    }

    if (thunk_rva != 0) {
      size_t thunk_offset;

      if (!map_pe_rva_to_offset(section_table, section_count, size_of_headers, size,
                                thunk_rva, &thunk_offset)) {
        continue;
      }

      for (;;) {
        uint64_t thunk_value;
        bool ordinal;

        if (pe32_plus) {
          if (thunk_offset + 8 > size) {
            break;
          }
          thunk_value = read_u64_le_bytes(buffer + thunk_offset);
          thunk_offset += 8;
          ordinal = (thunk_value & UINT64_C(0x8000000000000000)) != 0;
        } else {
          if (thunk_offset + 4 > size) {
            break;
          }
          thunk_value = read_u32_le_bytes(buffer + thunk_offset);
          thunk_offset += 4;
          ordinal = (thunk_value & UINT32_C(0x80000000)) != 0;
        }

        if (thunk_value == 0) {
          break;
        }

        if (ordinal) {
          char ordinal_name[32];
          unsigned int ordinal_value =
              (unsigned int)(thunk_value & (pe32_plus ? 0xffffU : 0xffffU));
          snprintf(ordinal_name, sizeof(ordinal_name), "ordinal#%u",
                   ordinal_value);
          if (!append_import_symbol(library, ordinal_name)) {
            return false;
          }
        } else {
          uint32_t name_rva = (uint32_t)thunk_value;
          size_t name_offset;
          const char *symbol_name;

          if (!map_pe_rva_to_offset(section_table, section_count, size_of_headers,
                                    size, name_rva, &name_offset) ||
              name_offset + 2 >= size) {
            continue;
          }

          symbol_name =
              bounded_file_string(buffer, size, name_offset + 2, size - name_offset - 2);
          if (symbol_name != NULL && !append_import_symbol(library, symbol_name)) {
            return false;
          }
        }
      }
    }
  }

  return true;
}

static bool collect_pe_dependencies(const bfd_byte *buffer, size_t size,
                                    analysis_report_t *report) {
  size_t pe_offset;
  const bfd_byte *coff;
  const bfd_byte *optional;
  const bfd_byte *section_table;
  uint16_t optional_magic;
  bool pe32_plus;
  uint16_t section_count;
  uint16_t optional_size;
  uint32_t size_of_headers;
  uint64_t image_base;
  uint32_t directory_count;
  uint32_t import_rva = 0;
  uint32_t import_size = 0;
  uint32_t delay_import_rva = 0;
  uint32_t delay_import_size = 0;
  uint32_t export_rva = 0;
  uint32_t export_size = 0;

  if (size < 0x40 || buffer[0] != 'M' || buffer[1] != 'Z') {
    return true;
  }

  pe_offset = read_u32_le_bytes(buffer + 0x3c);
  if (pe_offset + 24 > size || memcmp(buffer + pe_offset, "PE\0\0", 4) != 0) {
    return true;
  }

  coff = buffer + pe_offset + 4;
  optional = coff + 20;
  section_count = read_u16_le_bytes(coff + 2);
  optional_size = read_u16_le_bytes(coff + 16);
  if ((size_t)(optional - buffer) + optional_size > size || optional_size < 96) {
    return true;
  }

  optional_magic = read_u16_le_bytes(optional);
  pe32_plus = optional_magic == 0x20b;
  if (optional_magic != 0x10b && optional_magic != 0x20b) {
    return true;
  }

  size_of_headers = read_u32_le_bytes(optional + 60);
  image_base = pe32_plus ? read_u64_le_bytes(optional + 24)
                         : read_u32_le_bytes(optional + 28);
  directory_count = read_u32_le_bytes(optional + (pe32_plus ? 108 : 92));
  if (directory_count > 16) {
    directory_count = 16;
  }

  section_table = optional + optional_size;
  if ((size_t)(section_table - buffer) + (size_t)section_count * 40 > size) {
    return true;
  }

  if (directory_count > PE_DIRECTORY_IMPORT) {
    const bfd_byte *entry =
        optional + (pe32_plus ? 112 : 96) + (size_t)PE_DIRECTORY_IMPORT * 8;
    import_rva = read_u32_le_bytes(entry);
    import_size = read_u32_le_bytes(entry + 4);
  }

  if (directory_count > PE_DIRECTORY_DELAY_IMPORT) {
    const bfd_byte *entry =
        optional + (pe32_plus ? 112 : 96) + (size_t)PE_DIRECTORY_DELAY_IMPORT * 8;
    delay_import_rva = read_u32_le_bytes(entry);
    delay_import_size = read_u32_le_bytes(entry + 4);
  }

  if (directory_count > PE_DIRECTORY_EXPORT) {
    const bfd_byte *entry =
        optional + (pe32_plus ? 112 : 96) + (size_t)PE_DIRECTORY_EXPORT * 8;
    export_rva = read_u32_le_bytes(entry);
    export_size = read_u32_le_bytes(entry + 4);
  }

  if (!collect_pe_import_directory(
          buffer, size, section_table, section_count, size_of_headers, pe32_plus,
          image_base, import_rva, import_size, false, &report->pe_imports,
          &report->pe_import_count, &report->pe_import_capacity)) {
    return false;
  }

  if (!collect_pe_import_directory(
          buffer, size, section_table, section_count, size_of_headers, pe32_plus,
          image_base, delay_import_rva, delay_import_size, true,
          &report->pe_delay_imports, &report->pe_delay_import_count,
          &report->pe_delay_import_capacity)) {
    return false;
  }

  if (export_rva != 0 && export_size >= 40) {
    size_t export_offset;

    if (map_pe_rva_to_offset(section_table, section_count, size_of_headers, size,
                             export_rva, &export_offset) &&
        export_offset + 40 <= size) {
      report->pe_export_count = read_u32_le_bytes(buffer + export_offset + 20);
    }
  }

  if (report->pe_import_count != 0 || report->pe_delay_import_count != 0 ||
      report->pe_export_count != 0) {
    report->dependency_summary_available = true;
    report->dependency_summary_is_pe = true;
  }

  return true;
}

static void analyze_elf_file_identity(const bfd_byte *buffer, size_t size,
                                      analysis_report_t *report) {
  bool is64;
  bool big_endian;
  uint16_t type;
  uint64_t phoff;
  uint16_t phentsize;
  uint16_t phnum;
  bool has_interp = false;
  bool has_dynamic = false;

  if (size < 64 || buffer[EI_VERSION] != 1 ||
      (buffer[EI_CLASS] != ELFCLASS32 && buffer[EI_CLASS] != ELFCLASS64) ||
      (buffer[EI_DATA] != ELFDATA2LSB && buffer[EI_DATA] != ELFDATA2MSB)) {
    return;
  }

  is64 = buffer[EI_CLASS] == ELFCLASS64;
  big_endian = buffer[EI_DATA] == ELFDATA2MSB;
  type = read_u16_endian_bytes(buffer + 16, big_endian);
  phoff = is64 ? read_u64_endian_bytes(buffer + 32, big_endian)
               : read_u32_endian_bytes(buffer + 28, big_endian);
  phentsize = read_u16_endian_bytes(buffer + (is64 ? 54 : 42), big_endian);
  phnum = read_u16_endian_bytes(buffer + (is64 ? 56 : 44), big_endian);

  report->linking_known = true;
  report->loader_known = true;

  if (phoff != 0 && phentsize != 0 && phnum != 0 &&
      phoff + (uint64_t)phentsize * phnum <= size) {
    for (uint16_t index = 0; index < phnum; ++index) {
      const bfd_byte *ph = buffer + phoff + (uint64_t)phentsize * index;
      uint32_t ph_type = read_u32_endian_bytes(ph, big_endian);

      if (ph_type == PT_DYNAMIC) {
        has_dynamic = true;
      } else if (ph_type == PT_INTERP) {
        uint64_t offset = is64 ? read_u64_endian_bytes(ph + 8, big_endian)
                               : read_u32_endian_bytes(ph + 4, big_endian);
        uint64_t file_size = is64 ? read_u64_endian_bytes(ph + 32, big_endian)
                                  : read_u32_endian_bytes(ph + 16, big_endian);
        const void *terminator;

        if (offset < size && file_size != 0 && offset + file_size <= size) {
          size_t max_length = (size_t)file_size;
          terminator = memchr(buffer + offset, '\0', max_length);
          if (terminator != NULL) {
            snprintf(report->loader, sizeof(report->loader), "%s",
                     (const char *)(buffer + offset));
          } else {
            snprintf(report->loader, sizeof(report->loader), "%.*s",
                     (int)max_length, (const char *)(buffer + offset));
          }
          has_interp = true;
        }
      }
    }
  }

  if (has_interp) {
    set_report_text(report->linking, sizeof(report->linking), "dynamic");
  } else if (has_dynamic) {
    set_report_text(report->linking, sizeof(report->linking),
                    type == ET_DYN ? "shared object / dynamic"
                                   : "dynamic (no PT_INTERP path found)");
    set_report_text(report->loader, sizeof(report->loader),
                    type == ET_DYN ? "none embedded (shared object)"
                                   : "none embedded");
  } else {
    set_report_text(report->linking, sizeof(report->linking), "static");
    set_report_text(report->loader, sizeof(report->loader),
                    "none (statically linked)");
  }
}

static void analyze_pe_file_identity(const bfd_byte *buffer, size_t size,
                                     analysis_report_t *report) {
  size_t pe_offset;
  const bfd_byte *coff;
  const bfd_byte *optional;
  uint16_t optional_magic;
  bool pe32_plus;
  uint16_t subsystem;
  uint32_t directory_count;
  bool import_directory_present = false;

  if (size < 0x40 || buffer[0] != 'M' || buffer[1] != 'Z') {
    return;
  }

  pe_offset = read_u32_le_bytes(buffer + 0x3c);
  if (pe_offset + 24 > size || memcmp(buffer + pe_offset, "PE\0\0", 4) != 0) {
    return;
  }

  coff = buffer + pe_offset + 4;
  optional = coff + 20;
  if ((size_t)(optional - buffer) + 96 > size) {
    return;
  }

  optional_magic = read_u16_le_bytes(optional);
  pe32_plus = optional_magic == 0x20b;
  if (optional_magic != 0x10b && optional_magic != 0x20b) {
    return;
  }

  subsystem = read_u16_le_bytes(optional + 68);
  directory_count = read_u32_le_bytes(optional + (pe32_plus ? 108 : 92));
  if (directory_count > 16) {
    directory_count = 16;
  }

  if (directory_count > PE_DIRECTORY_IMPORT) {
    const bfd_byte *entry =
        optional + (pe32_plus ? 112 : 96) + (size_t)PE_DIRECTORY_IMPORT * 8;
    if ((size_t)(entry - buffer) + 8 <= size) {
      import_directory_present =
          read_u32_le_bytes(entry) != 0 && read_u32_le_bytes(entry + 4) != 0;
    }
  }

  if (directory_count > PE_DIRECTORY_CLR) {
    const bfd_byte *entry =
        optional + (pe32_plus ? 112 : 96) + (size_t)PE_DIRECTORY_CLR * 8;
    if ((size_t)(entry - buffer) + 8 <= size) {
      report->pe_clr_runtime =
          read_u32_le_bytes(entry) != 0 && read_u32_le_bytes(entry + 4) != 0;
    }
  }

  report->linking_known = true;
  report->loader_known = true;
  set_report_text(report->loader, sizeof(report->loader),
                  pe_loader_name(subsystem));
  set_report_text(report->linking, sizeof(report->linking),
                  import_directory_present ? "dynamic imports present"
                                           : "no import table seen");
}

static bool enrich_analysis_report(bfd *abfd, const options_t *options,
                                   const symbol_table_t *symbols,
                                   analysis_report_t *report) {
  bfd_byte *buffer = NULL;
  size_t size = 0;
  uint8_t md5[16];
  uint8_t sha256[32];

  if (!read_file_bytes(options->path, &buffer, &size)) {
    return false;
  }

  report->file_crc32_value = crc32_bytes(buffer, (bfd_size_type)size);
  binsight_md5(buffer, size, md5);
  binsight_sha256(buffer, size, sha256);
  binsight_digest_hex(md5, sizeof(md5), report->file_md5, sizeof(report->file_md5));
  binsight_digest_hex(sha256, sizeof(sha256), report->file_sha256,
                      sizeof(report->file_sha256));
  report->file_hashes_available = true;
  detect_upx_packing_identity(buffer, size, report);

  if (size >= 4 && buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' &&
      buffer[3] == 'F') {
    analyze_elf_file_identity(buffer, size, report);
    if (!collect_elf_dependencies(buffer, size, report)) {
      free(buffer);
      return false;
    }
    collect_elf_security_context(buffer, size, symbols, report);
    collect_elf_provenance_from_sections(abfd, report);
  } else if (size >= 2 && buffer[0] == 'M' && buffer[1] == 'Z') {
    analyze_pe_file_identity(buffer, size, report);
    if (!collect_pe_dependencies(buffer, size, report)) {
      free(buffer);
      return false;
    }
    collect_pe_security_context(buffer, size, report);
    collect_pe_provenance(buffer, size, report);
    if (!collect_pe_resources(buffer, size, report)) {
      free(buffer);
      return false;
    }
  }

  collect_overlay_analysis(buffer, size, report);
  collect_protector_hints(buffer, size, report);
  infer_language_guess(symbols, report);
  free(buffer);
  return true;
}

static bool is_pe_target(const bfd *abfd) {
  const char *target = bfd_get_target(abfd);

  return target != NULL &&
         (strncmp(target, "pei-", 4) == 0 || strncmp(target, "pe-", 3) == 0);
}

static bfd_size_type section_on_disk_size(const section_report_t *report) {
  if (report->rawsize != 0) {
    return report->rawsize;
  }
  if (report->compressed_size != 0) {
    return report->compressed_size;
  }
  return report->size;
}

static double shannon_entropy(const bfd_byte *contents, bfd_size_type size) {
  double entropy = 0.0;
  size_t counts[256] = {0};

  if (size == 0) {
    return 0.0;
  }

  for (bfd_size_type index = 0; index < size; ++index) {
    ++counts[contents[index]];
  }

  for (size_t index = 0; index < 256; ++index) {
    if (counts[index] == 0) {
      continue;
    }

    double probability = (double)counts[index] / (double)size;
    entropy -= probability * log2(probability);
  }

  return entropy;
}

static uint32_t crc32_bytes(const bfd_byte *contents, bfd_size_type size) {
  uLong value = crc32(0L, Z_NULL, 0);
  bfd_size_type offset = 0;

  while (offset < size) {
    uInt chunk =
        (uInt)((size - offset) > (bfd_size_type)UINT_MAX ? UINT_MAX : (size - offset));
    value = crc32(value, contents + offset, chunk);
    offset += chunk;
  }

  return (uint32_t)value;
}

static void free_options(options_t *options) {
  for (size_t index = 0; index < options->search_query_count; ++index) {
    free(options->search_queries[index].text);
    free(options->search_queries[index].bytes);
  }
  free(options->search_queries);
  for (size_t index = 0; index < options->patch_count; ++index) {
    free(options->patches[index].bytes);
  }
  free(options->patches);
  free(options->section_filters);
}

static bool parse_size_option_value(const char *text, const char *option_name,
                                    size_t minimum, size_t maximum,
                                    size_t *value_out) {
  char *end = NULL;
  uintmax_t value;

  /* base 0 keeps the CLI flexible: callers can pass plain decimal lengths or
     hexdump-style offsets such as 0x200 through the same validator. */
  errno = 0;
  value = strtoumax(text, &end, 0);
  if (text[0] == '\0' || end == NULL || *end != '\0' || errno != 0 ||
      value < minimum || value > maximum || value > SIZE_MAX) {
    if (minimum == maximum) {
      fprintf(stderr, "binsight: %s expects the value %zu\n", option_name,
              minimum);
    } else {
      fprintf(stderr,
              "binsight: %s expects an integer between %zu and %zu\n",
              option_name, minimum, maximum);
    }
    return false;
  }

  *value_out = (size_t)value;
  return true;
}

static bool add_section_filter(options_t *options, const char *name) {
  const char **new_filters;

  if (options->section_filter_count == options->section_filter_capacity) {
    size_t new_capacity =
        options->section_filter_capacity == 0 ? 4 : options->section_filter_capacity * 2;

    new_filters =
        realloc(options->section_filters, new_capacity * sizeof(*new_filters));
    if (new_filters == NULL) {
      fprintf(stderr, "out of memory while storing section filters\n");
      return false;
    }

    options->section_filters = new_filters;
    options->section_filter_capacity = new_capacity;
  }

  options->section_filters[options->section_filter_count++] = name;
  return true;
}

static bool add_search_query(options_t *options, search_query_kind_t kind,
                             const char *value) {
  search_query_t query;
  search_query_t *new_queries;

  memset(&query, 0, sizeof(query));
  if (value == NULL || value[0] == '\0') {
    fprintf(stderr, "binsight: search queries must not be empty\n");
    return false;
  }

  query.kind = kind;
  if (kind == SEARCH_QUERY_HEX) {
    size_t byte_count = 0;

    if (!parse_patch_bytes(value, &query.bytes, &byte_count)) {
      return false;
    }
    query.byte_count = byte_count;
  } else {
    query.text = duplicate_text(value);
    if (query.text == NULL) {
      fprintf(stderr, "out of memory while storing search query\n");
      return false;
    }
  }

  if (options->search_query_count == options->search_query_capacity) {
    size_t new_capacity =
        options->search_query_capacity == 0 ? 4
                                            : options->search_query_capacity * 2;

    new_queries =
        realloc(options->search_queries, new_capacity * sizeof(*new_queries));
    if (new_queries == NULL) {
      fprintf(stderr, "out of memory while storing search queries\n");
      free(query.text);
      free(query.bytes);
      return false;
    }

    options->search_queries = new_queries;
    options->search_query_capacity = new_capacity;
  }

  options->search_queries[options->search_query_count++] = query;
  return true;
}

static int hex_digit_value(char ch) {
  if (ch >= '0' && ch <= '9') {
    return ch - '0';
  }
  if (ch >= 'a' && ch <= 'f') {
    return ch - 'a' + 10;
  }
  if (ch >= 'A' && ch <= 'F') {
    return ch - 'A' + 10;
  }
  return -1;
}

static bool parse_patch_bytes(const char *text, bfd_byte **bytes_out,
                              size_t *length_out) {
  const char *digits = text;
  size_t digit_count;
  bfd_byte *bytes;

  /* Accept both 9090 and 0x9090 so callers can mirror the offset syntax. */
  if (digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
    digits += 2;
  }

  digit_count = strlen(digits);
  if (digit_count == 0 || (digit_count % 2) != 0) {
    fprintf(stderr,
            "binsight: patch bytes must be a non-empty even-length hex string\n");
    return false;
  }

  bytes = malloc(digit_count / 2);
  if (bytes == NULL) {
    fprintf(stderr, "out of memory while parsing patch bytes\n");
    return false;
  }

  for (size_t index = 0; index < digit_count; index += 2) {
    int high = hex_digit_value(digits[index]);
    int low = hex_digit_value(digits[index + 1]);

    if (high < 0 || low < 0) {
      fprintf(stderr,
              "binsight: patch bytes must contain only hexadecimal digits\n");
      free(bytes);
      return false;
    }

    bytes[index / 2] = (bfd_byte)((high << 4) | low);
  }

  *bytes_out = bytes;
  *length_out = digit_count / 2;
  return true;
}

static bool add_byte_patch(options_t *options, const char *spec) {
  const char *separator = strchr(spec, ':');
  char offset_text[64];
  byte_patch_t patch;
  byte_patch_t *new_patches;
  size_t offset_length;

  memset(&patch, 0, sizeof(patch));
  if (separator == NULL || separator == spec || separator[1] == '\0') {
    fprintf(stderr,
            "binsight: --patch expects OFFSET:HEXBYTES, for example 0x3c:9090\n");
    return false;
  }

  offset_length = (size_t)(separator - spec);
  if (offset_length >= sizeof(offset_text)) {
    fprintf(stderr, "binsight: patch offset is too long\n");
    return false;
  }

  memcpy(offset_text, spec, offset_length);
  offset_text[offset_length] = '\0';
  if (!parse_size_option_value(offset_text, "--patch offset", 0, SIZE_MAX,
                               &patch.offset)) {
    return false;
  }
  if (!parse_patch_bytes(separator + 1, &patch.bytes, &patch.length)) {
    return false;
  }

  /* Preserve the original CLI order so the final patch summary matches the
     user's input exactly. */
  if (options->patch_count == options->patch_capacity) {
    size_t new_capacity =
        options->patch_capacity == 0 ? 4 : options->patch_capacity * 2;

    new_patches =
        realloc(options->patches, new_capacity * sizeof(*new_patches));
    if (new_patches == NULL) {
      fprintf(stderr, "out of memory while storing patch operations\n");
      free(patch.bytes);
      return false;
    }

    options->patches = new_patches;
    options->patch_capacity = new_capacity;
  }

  options->patches[options->patch_count++] = patch;
  return true;
}

static bool output_includes_any(const options_t *options, unsigned int views) {
  return (options->output_views & views) != 0U;
}

static bool output_uses_only_raw_views(const options_t *options) {
  const unsigned int raw_views = OUTPUT_VIEW_HEX | OUTPUT_VIEW_SEARCH;

  return options->output_views != 0 &&
         (options->output_views & (unsigned int)~raw_views) == 0U;
}

static void clear_output_views(options_t *options, unsigned int views) {
  options->output_views &= (unsigned int)~views;
}

static void select_output_views(options_t *options, unsigned int views) {
  if (!options->explicit_view_selection) {
    options->output_views = 0;
    options->explicit_view_selection = true;
  }

  options->output_views |= views;
}

static const inspect_command_t *find_inspect_command(const char *name) {
  for (size_t index = 0;
       index < sizeof(k_inspect_commands) / sizeof(k_inspect_commands[0]);
       ++index) {
    if (strcmp(name, k_inspect_commands[index].name) == 0) {
      return &k_inspect_commands[index];
    }
  }

  return NULL;
}

static parse_result_t parse_options(int argc, char **argv, options_t *options) {
  const inspect_command_t *command = NULL;
  int parse_index = 1;
  int option;
  static const struct option long_options[] = {
      {"all-sections", no_argument, NULL, 'a'},
      {"min-string-len", required_argument, NULL, 'm'},
      {"section", required_argument, NULL, 's'},
      {"no-disasm", no_argument, NULL, 'n'},
      {"summary", no_argument, NULL, 1003},
      {"overview", no_argument, NULL, 1003},
      {"imports", no_argument, NULL, 1004},
      {"headers", no_argument, NULL, 1005},
      {"triage", no_argument, NULL, 1006},
      {"sections", no_argument, NULL, 1007},
      {"disasm", no_argument, NULL, 1008},
      {"strings", no_argument, NULL, 1009},
      {"security", no_argument, NULL, 1010},
      {"provenance", no_argument, NULL, 1011},
      {"json", no_argument, NULL, 1012},
      {"ndjson", no_argument, NULL, 1013},
      {"hex", no_argument, NULL, 1014},
      {"hex-start", required_argument, NULL, 1015},
      {"hex-length", required_argument, NULL, 1016},
      {"hex-width", required_argument, NULL, 1017},
      {"patch", required_argument, NULL, 1018},
      {"patch-out", required_argument, NULL, 1019},
      {"resources", no_argument, NULL, 1020},
      {"overlay", no_argument, NULL, 1021},
      {"search", no_argument, NULL, 1022},
      {"find-ascii", required_argument, NULL, 1023},
      {"find-utf16", required_argument, NULL, 1024},
      {"find-hex", required_argument, NULL, 1025},
      {"max-search-hits", required_argument, NULL, 1026},
      {"repair-upx", required_argument, NULL, 1002},
      {"repair-upx-elf", required_argument, NULL, 1000},
      {"repair-and-unpack-upx", required_argument, NULL, 1001},
      {"help", no_argument, NULL, 'h'},
      {0, 0, 0, 0},
  };

  memset(options, 0, sizeof(*options));
  options->output_views = OUTPUT_VIEW_DEFAULT;
  options->min_string_length = 4;
  options->hex_bytes_per_line = DEFAULT_HEX_BYTES_PER_LINE;
  options->search_hit_limit = DEFAULT_SEARCH_HIT_LIMIT;

  /* Subcommands are optional; if argv[1] names one, consume it before normal
     getopt parsing so the rest of the flags work the same either way. */
  if (argc >= 3 && argv[1][0] != '-') {
    command = find_inspect_command(argv[1]);
    if (command != NULL) {
      options->output_views = command->views;
      options->explicit_view_selection = true;
      parse_index = 2;
    }
  }

  optind = parse_index;

  while ((option = getopt_long(argc, argv, "am:s:nh", long_options, NULL)) !=
         -1) {
    switch (option) {
      case 'a':
        options->disassemble_all_contents = true;
        break;
      case 'm': {
        char *end = NULL;
        unsigned long value = strtoul(optarg, &end, 10);

        if (optarg[0] == '\0' || end == NULL || *end != '\0' || value == 0 ||
            value > 4096) {
          fprintf(stderr,
                  "binsight: --min-string-len expects an integer between 1 and 4096\n");
          return PARSE_ERROR;
        }
        options->min_string_length = (size_t)value;
        break;
      }
      case 's':
        if (!add_section_filter(options, optarg)) {
          return PARSE_ERROR;
        }
        break;
      case 'n':
        clear_output_views(options, OUTPUT_VIEW_DISASSEMBLY);
        break;
      case 1003:
        select_output_views(options, OUTPUT_VIEW_OVERVIEW);
        break;
      case 1004:
        select_output_views(options, OUTPUT_VIEW_DEPENDENCIES);
        break;
      case 1005:
        select_output_views(options, OUTPUT_VIEW_HEADERS);
        break;
      case 1006:
        select_output_views(options, OUTPUT_VIEW_TRIAGE);
        break;
      case 1007:
        select_output_views(options, OUTPUT_VIEW_SECTIONS);
        break;
      case 1008:
        select_output_views(options, OUTPUT_VIEW_DISASSEMBLY);
        break;
      case 1009:
        select_output_views(options, OUTPUT_VIEW_STRINGS);
        break;
      case 1010:
        select_output_views(options, OUTPUT_VIEW_SECURITY);
        break;
      case 1011:
        select_output_views(options, OUTPUT_VIEW_PROVENANCE);
        break;
      case 1012:
        options->json_output = true;
        break;
      case 1013:
        options->ndjson_output = true;
        break;
      case 1014:
        select_output_views(options, OUTPUT_VIEW_HEX);
        break;
      case 1015:
        if (!parse_size_option_value(optarg, "--hex-start", 0, SIZE_MAX,
                                     &options->hex_start)) {
          return PARSE_ERROR;
        }
        options->hex_start_set = true;
        break;
      case 1016:
        if (!parse_size_option_value(optarg, "--hex-length", 1, SIZE_MAX,
                                     &options->hex_length)) {
          return PARSE_ERROR;
        }
        options->hex_length_set = true;
        break;
      case 1017:
        if (!parse_size_option_value(optarg, "--hex-width",
                                     MIN_HEX_BYTES_PER_LINE,
                                     MAX_HEX_BYTES_PER_LINE,
                                     &options->hex_bytes_per_line)) {
          return PARSE_ERROR;
        }
        break;
      case 1018:
        if (!add_byte_patch(options, optarg)) {
          return PARSE_ERROR;
        }
        break;
      case 1019:
        options->patch_output_path = optarg;
        break;
      case 1020:
        select_output_views(options, OUTPUT_VIEW_RESOURCES);
        break;
      case 1021:
        select_output_views(options, OUTPUT_VIEW_OVERLAY);
        break;
      case 1022:
        select_output_views(options, OUTPUT_VIEW_SEARCH);
        break;
      case 1023:
        if (!add_search_query(options, SEARCH_QUERY_ASCII, optarg)) {
          return PARSE_ERROR;
        }
        select_output_views(options, OUTPUT_VIEW_SEARCH);
        break;
      case 1024:
        if (!add_search_query(options, SEARCH_QUERY_UTF16, optarg)) {
          return PARSE_ERROR;
        }
        select_output_views(options, OUTPUT_VIEW_SEARCH);
        break;
      case 1025:
        if (!add_search_query(options, SEARCH_QUERY_HEX, optarg)) {
          return PARSE_ERROR;
        }
        select_output_views(options, OUTPUT_VIEW_SEARCH);
        break;
      case 1026:
        if (!parse_size_option_value(optarg, "--max-search-hits", 1,
                                     MAX_SEARCH_HIT_LIMIT,
                                     &options->search_hit_limit)) {
          return PARSE_ERROR;
        }
        break;
      case 1002:
      case 1000:
        options->repair_upx = true;
        options->output_path = optarg;
        break;
      case 1001:
        options->repair_and_unpack_upx = true;
        options->output_path = optarg;
        break;
      case 'h':
        print_usage(stdout, argv[0]);
        return PARSE_HELP;
      default:
        print_usage(stderr, argv[0]);
        return PARSE_ERROR;
    }
  }

  if (options->repair_upx && options->repair_and_unpack_upx) {
    fprintf(stderr,
            "binsight: choose either --repair-upx or "
            "--repair-and-unpack-upx, not both\n");
    return PARSE_ERROR;
  }

  if (options->patch_count != 0 &&
      (options->repair_upx || options->repair_and_unpack_upx)) {
    fprintf(stderr,
            "binsight: byte patch mode cannot be combined with UPX repair "
            "mode\n");
    return PARSE_ERROR;
  }

  if (options->json_output && options->ndjson_output) {
    fprintf(stderr, "binsight: choose either --json or --ndjson, not both\n");
    return PARSE_ERROR;
  }

  if (optind != argc - 1) {
    print_usage(stderr, argv[0]);
    return PARSE_ERROR;
  }

  options->path = argv[optind];
  if ((options->repair_upx || options->repair_and_unpack_upx) &&
      options->section_filter_count != 0) {
    fprintf(stderr,
            "binsight: section filters are only valid in inspection mode\n");
    return PARSE_ERROR;
  }

  if ((options->repair_upx || options->repair_and_unpack_upx) &&
      options->explicit_view_selection) {
    fprintf(stderr,
            "binsight: focused inspection views are only valid in inspection "
            "mode\n");
    return PARSE_ERROR;
  }

  if (options->patch_count == 0 && options->patch_output_path != NULL) {
    fprintf(stderr,
            "binsight: --patch-out requires at least one --patch operation\n");
    return PARSE_ERROR;
  }

  if (options->patch_count != 0) {
    if (options->patch_output_path == NULL) {
      fprintf(stderr,
              "binsight: byte patch mode requires --patch-out to name the "
              "edited copy\n");
      return PARSE_ERROR;
    }

    /* Keep patching as a narrow write-only mode instead of mixing it with
       inspection flags; that avoids ambiguous "inspect and edit" behavior. */
    if (options->section_filter_count != 0 || options->json_output ||
        options->ndjson_output || options->disassemble_all_contents ||
        options->explicit_view_selection || options->min_string_length != 4 ||
        options->hex_start_set || options->hex_length_set ||
        options->hex_bytes_per_line != DEFAULT_HEX_BYTES_PER_LINE ||
        options->search_query_count != 0 ||
        options->search_hit_limit != DEFAULT_SEARCH_HIT_LIMIT ||
        options->output_views != OUTPUT_VIEW_DEFAULT) {
      fprintf(stderr,
              "binsight: byte patch mode does not accept inspection-view "
              "options\n");
      return PARSE_ERROR;
    }
  }

  if (!(options->repair_upx || options->repair_and_unpack_upx) &&
      options->section_filter_count != 0 &&
      !output_includes_any(options,
                           OUTPUT_VIEW_SECTIONS | OUTPUT_VIEW_DISASSEMBLY |
                               OUTPUT_VIEW_STRINGS)) {
    fprintf(stderr,
            "binsight: section filters require section headers, strings, or "
            "disassembly "
            "output\n");
    return PARSE_ERROR;
  }

  if (!(options->repair_upx || options->repair_and_unpack_upx) &&
      options->disassemble_all_contents &&
      !output_includes_any(options, OUTPUT_VIEW_DISASSEMBLY)) {
    fprintf(stderr,
            "binsight: --all-sections requires disassembly output\n");
    return PARSE_ERROR;
  }

  if (!(options->repair_upx || options->repair_and_unpack_upx) &&
      options->patch_count == 0 &&
      (options->hex_start_set || options->hex_length_set ||
       options->hex_bytes_per_line != DEFAULT_HEX_BYTES_PER_LINE) &&
      !output_includes_any(options, OUTPUT_VIEW_HEX)) {
    fprintf(stderr,
            "binsight: --hex-start/--hex-length/--hex-width require hex "
            "output\n");
    return PARSE_ERROR;
  }

  if (!(options->repair_upx || options->repair_and_unpack_upx) &&
      output_includes_any(options, OUTPUT_VIEW_SEARCH) &&
      options->search_query_count == 0) {
    fprintf(stderr,
            "binsight: search output requires at least one --find-ascii, "
            "--find-utf16, or --find-hex query\n");
    return PARSE_ERROR;
  }

  if (!(options->repair_upx || options->repair_and_unpack_upx) &&
      options->search_query_count == 0 &&
      options->search_hit_limit != DEFAULT_SEARCH_HIT_LIMIT) {
    fprintf(stderr,
            "binsight: --max-search-hits requires active search queries\n");
    return PARSE_ERROR;
  }

  if (!(options->repair_upx || options->repair_and_unpack_upx) &&
      options->output_views == 0) {
    fprintf(stderr, "binsight: no inspection output views were selected\n");
    return PARSE_ERROR;
  }

  if (!(options->repair_upx || options->repair_and_unpack_upx) &&
      (options->json_output || options->ndjson_output) &&
      output_includes_any(options, OUTPUT_VIEW_HEADERS | OUTPUT_VIEW_DISASSEMBLY |
                                       OUTPUT_VIEW_HEX | OUTPUT_VIEW_SEARCH)) {
    fprintf(stderr,
            "binsight: --json/--ndjson currently support overview, imports, triage, sections, strings, security, provenance, resources, and overlay views; headers, disassembly, hex, and search remain text-only\n");
    return PARSE_ERROR;
  }

  return PARSE_OK;
}

static bool section_is_selected(const options_t *options,
                                const asection *section) {
  const char *name = bfd_section_name(section);

  if (options->section_filter_count == 0) {
    return true;
  }

  for (size_t index = 0; index < options->section_filter_count; ++index) {
    if (strcmp(name, options->section_filters[index]) == 0) {
      return true;
    }
  }

  return false;
}

static bool section_is_disassemblable(const options_t *options,
                                      const asection *section) {
  flagword flags = bfd_section_flags(section);

  if (!section_is_selected(options, section)) {
    return false;
  }

  if ((flags & SEC_HAS_CONTENTS) == 0 || bfd_section_size(section) == 0) {
    return false;
  }

  if (options->disassemble_all_contents || options->section_filter_count > 0) {
    return true;
  }

  return (flags & SEC_CODE) != 0;
}

static void print_bfd_error(const char *path, const char *action) {
  fprintf(stderr, "%s: %s failed for '%s': %s\n", "binsight", action, path,
          bfd_errmsg(bfd_get_error()));
}

static bool load_symbols(bfd *abfd, symbol_table_t *table) {
  long upper_bound;

  memset(table, 0, sizeof(*table));

  upper_bound = bfd_get_symtab_upper_bound(abfd);
  if (upper_bound > 0) {
    table->symbols = malloc((size_t)upper_bound);
    if (table->symbols == NULL) {
      fprintf(stderr, "out of memory while loading symbols\n");
      return false;
    }

    table->count = bfd_canonicalize_symtab(abfd, table->symbols);
    if (table->count < 0) {
      print_bfd_error(bfd_get_filename(abfd), "symbol table load");
      free(table->symbols);
      table->symbols = NULL;
      table->count = 0;
      return false;
    }

    if (table->count > 0) {
      return true;
    }

    free(table->symbols);
    table->symbols = NULL;
  } else if (upper_bound < 0) {
    print_bfd_error(bfd_get_filename(abfd), "symbol table query");
    return false;
  }

  upper_bound = bfd_get_dynamic_symtab_upper_bound(abfd);
  if (upper_bound <= 0) {
    return true;
  }

  table->symbols = malloc((size_t)upper_bound);
  if (table->symbols == NULL) {
    fprintf(stderr, "out of memory while loading dynamic symbols\n");
    return false;
  }

  table->count = bfd_canonicalize_dynamic_symtab(abfd, table->symbols);
  if (table->count < 0) {
    print_bfd_error(bfd_get_filename(abfd), "dynamic symbol table load");
    free(table->symbols);
    table->symbols = NULL;
    table->count = 0;
    return false;
  }

  table->dynamic = table->count > 0;
  return true;
}

static void free_symbols(symbol_table_t *table) {
  free(table->symbols);
}

static void free_analysis_report(analysis_report_t *report) {
  free_string_list(&report->elf_needed_libraries);
  free_string_list(&report->compiler_comments);
  free_import_libraries(report->pe_imports, report->pe_import_count);
  free_import_libraries(report->pe_delay_imports, report->pe_delay_import_count);
  free(report->pe_resources);
  free_extracted_strings(report->strings, report->string_count);
  free(report->embedded_signatures);
  free(report->sections);
}

static int compare_symbols_by_address(const void *left, const void *right) {
  const asymbol *left_symbol = *(const asymbol *const *)left;
  const asymbol *right_symbol = *(const asymbol *const *)right;
  bfd_vma left_value = bfd_asymbol_value(left_symbol);
  bfd_vma right_value = bfd_asymbol_value(right_symbol);

  if (left_value < right_value) {
    return -1;
  }
  if (left_value > right_value) {
    return 1;
  }
  return strcmp(bfd_asymbol_name(left_symbol), bfd_asymbol_name(right_symbol));
}

static bool symbol_is_displayable(const asymbol *symbol,
                                  const asection *section) {
  flagword flags;

  if (symbol == NULL || section == NULL || symbol->section != section) {
    return false;
  }

  if (symbol->name == NULL || symbol->name[0] == '\0') {
    return false;
  }

  flags = symbol->flags;
  if ((flags & (BSF_FILE | BSF_SECTION_SYM | BSF_DEBUGGING)) != 0) {
    return false;
  }

  return true;
}

static bool symbol_is_useful_for_analysis(const asymbol *symbol) {
  if (symbol == NULL || symbol->name == NULL || symbol->name[0] == '\0') {
    return false;
  }

  return (symbol->flags & (BSF_FILE | BSF_SECTION_SYM | BSF_DEBUGGING)) == 0;
}

static bool symbol_looks_imported(const asymbol *symbol) {
  const char *name;

  if (symbol == NULL || symbol->name == NULL) {
    return false;
  }

  name = symbol->name;
  return bfd_is_und_section(symbol->section) || strncmp(name, "__imp_", 6) == 0 ||
         strncmp(name, "imp_", 4) == 0;
}

static void maybe_add_symbol_clue(analysis_report_t *report, const char *name,
                                  const char *reason, bool undefined) {
  if (name == NULL || reason == NULL) {
    return;
  }

  for (size_t index = 0; index < report->symbol_clue_count; ++index) {
    if (strcmp(report->symbol_clues[index].name, name) == 0) {
      return;
    }
  }

  if (report->symbol_clue_count >= MAX_SYMBOL_CLUES) {
    return;
  }

  report->symbol_clues[report->symbol_clue_count].name = name;
  report->symbol_clues[report->symbol_clue_count].reason = reason;
  report->symbol_clues[report->symbol_clue_count].undefined = undefined;
  ++report->symbol_clue_count;
}

static void analyze_symbols(const symbol_table_t *table,
                            analysis_report_t *report) {
  if (table == NULL || table->symbols == NULL || table->count <= 0) {
    return;
  }

  for (long index = 0; index < table->count; ++index) {
    asymbol *symbol = table->symbols[index];
    const char *reason;
    bool undefined;
    bool external;

    if (!symbol_is_useful_for_analysis(symbol)) {
      continue;
    }

    undefined = bfd_is_und_section(symbol->section);
    external = undefined || (symbol->flags & (BSF_GLOBAL | BSF_WEAK)) != 0;

    if (undefined) {
      ++report->undefined_symbol_count;
    }
    if (external) {
      ++report->external_symbol_count;
    }

    reason =
        symbol_looks_imported(symbol)
            ? match_suspicious_rule(
                  symbol->name, k_suspicious_symbol_rules,
                  sizeof(k_suspicious_symbol_rules) /
                      sizeof(k_suspicious_symbol_rules[0]))
            : NULL;
    if (reason != NULL) {
      maybe_add_symbol_clue(report, symbol->name, reason, undefined);
    }
  }
}

static bool collect_section_symbols(const symbol_table_t *table,
                                    const asection *section,
                                    section_symbol_table_t *section_symbols) {
  size_t count = 0;

  memset(section_symbols, 0, sizeof(*section_symbols));

  if (table == NULL || table->symbols == NULL || table->count <= 0) {
    return true;
  }

  section_symbols->items =
      calloc((size_t)table->count, sizeof(*section_symbols->items));
  if (section_symbols->items == NULL) {
    fprintf(stderr, "out of memory while collecting section symbols\n");
    return false;
  }

  for (long index = 0; index < table->count; ++index) {
    if (!symbol_is_displayable(table->symbols[index], section)) {
      continue;
    }
    section_symbols->items[count++] = table->symbols[index];
  }

  section_symbols->count = count;
  qsort(section_symbols->items, section_symbols->count,
        sizeof(*section_symbols->items), compare_symbols_by_address);
  return true;
}

static void free_section_symbols(section_symbol_table_t *section_symbols) {
  free(section_symbols->items);
}

static void print_file_overview(bfd *abfd, const char *path,
                                const symbol_table_t *symbols,
                                const analysis_report_t *report) {
  const bfd_arch_info_type *arch_info = bfd_get_arch_info(abfd);
  char file_flags[256];
  unsigned int width = address_width_for_bfd(abfd);

  printf("Binary: %s\n", path);
  printf("Target: %s\n", bfd_get_target(abfd));
  printf("Flavour: %s\n", bfd_flavour_name(bfd_get_flavour(abfd)));
  printf("Architecture: %s\n",
         arch_info != NULL ? arch_info->printable_name : "unknown");
  printf("Address bits: %u\n", bfd_arch_bits_per_address(abfd));
  printf("Byte bits: %u\n", bfd_arch_bits_per_byte(abfd));
  printf("Endianness: %s\n",
         bfd_big_endian(abfd)
             ? "big"
             : (bfd_little_endian(abfd) ? "little" : "unknown"));
  printf("Entry point: ");
  print_hex(stdout, width, (uintmax_t)bfd_get_start_address(abfd));
  printf("\n");
  printf("File size: %" PRIuMAX " bytes\n", report->file_size);
  printf("Section count: %u\n", bfd_count_sections(abfd));
  printf("File flags: %s\n",
         format_flags(bfd_get_file_flags(abfd), k_file_flags,
                      sizeof(k_file_flags) / sizeof(k_file_flags[0]),
                      file_flags, sizeof(file_flags)));
  if (symbols->count > 0) {
    printf("Symbols loaded: %ld (%s)\n", symbols->count,
           symbols->dynamic ? "dynamic" : "regular");
  } else {
    printf("Symbols loaded: none\n");
  }
  if (report->linking_known) {
    printf("Linking: %s\n", report->linking);
  } else {
    printf("Linking: unknown\n");
  }
  if (report->loader_known) {
    printf("Loader: %s\n", report->loader);
  } else {
    printf("Loader: unknown\n");
  }
  if (report->language_known) {
    printf("Language guess: %s", report->language);
    if (report->language_reason[0] != '\0') {
      printf(" (%s)", report->language_reason);
    }
    printf("\n");
  } else {
    printf("Language guess: unknown\n");
  }
  if (report->upx_packed) {
    printf("UPX: packed");
    if (report->upx_version_known) {
      printf(" (embedded id %s", report->upx_version_raw);
      if (report->upx_version_normalized) {
        printf(", normalized %s", report->upx_version);
      }
      printf(")");
    } else {
      printf(" (exact release unavailable)");
    }
    if (report->upx_pack_header_known) {
      printf("  Pack header: v%u fmt%u", report->upx_pack_header_version,
             report->upx_pack_header_format);
    }
    printf("\n");
  } else {
    printf("UPX: not detected\n");
  }
  if (report->protector_hint_count != 0) {
    printf("Packer/protector hints:\n");
    for (size_t index = 0; index < report->protector_hint_count; ++index) {
      const protector_hint_t *hint = &report->protector_hints[index];

      printf("  - %s [%s, %s confidence]: %s\n", hint->name, hint->kind,
             hint->confidence, hint->evidence);
    }
  } else {
    printf("Packer/protector hints: none matched\n");
  }
  if (report->file_hashes_available) {
    printf("File hashes:\n");
    printf("  CRC32: %08" PRIx32 "\n", report->file_crc32_value);
    printf("  MD5: %s\n", report->file_md5);
    printf("  SHA256: %s\n", report->file_sha256);
  }
}

static void print_string_preview(const string_list_t *list, size_t limit) {
  size_t preview_count;

  if (list == NULL || list->count == 0) {
    printf("none");
    return;
  }

  preview_count = list->count < limit ? list->count : limit;
  for (size_t index = 0; index < preview_count; ++index) {
    if (index != 0) {
      printf(", ");
    }
    printf("%s", list->items[index]);
  }

  if (list->count > preview_count) {
    printf(" (+%zu more)", list->count - preview_count);
  }
}

static void print_dependency_summary(const analysis_report_t *report) {
  printf("Dependency Summary:\n");

  if (report->dependency_summary_is_elf) {
    printf("  Needed shared libraries:\n");
    if (report->elf_needed_libraries.count == 0) {
      printf("    - none found\n");
    } else {
      for (size_t index = 0; index < report->elf_needed_libraries.count; ++index) {
        printf("    - %s\n", report->elf_needed_libraries.items[index]);
      }
    }

    if (report->elf_soname[0] != '\0') {
      printf("  SONAME: %s\n", report->elf_soname);
    }
    if (report->elf_rpath[0] != '\0') {
      printf("  RPATH: %s\n", report->elf_rpath);
    }
    if (report->elf_runpath[0] != '\0') {
      printf("  RUNPATH: %s\n", report->elf_runpath);
    }
    return;
  }

  if (report->dependency_summary_is_pe) {
    printf("  Imports:\n");
    if (report->pe_import_count == 0) {
      printf("    - none found\n");
    } else {
      for (size_t index = 0; index < report->pe_import_count; ++index) {
        const import_library_t *library = &report->pe_imports[index];

        printf("    - %s (%zu): ", library->name, library->symbols.count);
        print_string_preview(&library->symbols, 6);
        printf("\n");
      }
    }

    printf("  Delay imports:\n");
    if (report->pe_delay_import_count == 0) {
      printf("    - none found\n");
    } else {
      for (size_t index = 0; index < report->pe_delay_import_count; ++index) {
        const import_library_t *library = &report->pe_delay_imports[index];

        printf("    - %s (%zu): ", library->name, library->symbols.count);
        print_string_preview(&library->symbols, 6);
        printf("\n");
      }
    }

    printf("  Exported functions: %zu\n", report->pe_export_count);
    return;
  }

  printf("  No explicit dependency metadata was found.\n");
}

static void print_security_context(const analysis_report_t *report) {
  printf("Security Context:\n");

  if (report->security_context_is_elf) {
    printf("  Execution model: %s\n",
           report->execution_model[0] != '\0' ? report->execution_model
                                              : "unknown");
    if (report->nx_known) {
      printf("  NX stack: %s\n", report->nx_enabled ? "enabled" : "disabled");
    } else {
      printf("  NX stack: unknown (no PT_GNU_STACK header)\n");
    }
    printf("  RELRO: %s\n", report->relro[0] != '\0' ? report->relro : "unknown");
    printf("  Stack canary: %s\n", bool_presence(report->canary_present));
    printf("  Fortify imports: %s\n", bool_presence(report->fortify_present));
    printf("  TLS: %s\n", bool_presence(report->tls_present));
    return;
  }

  if (report->security_context_is_pe) {
    printf("  Subsystem: %s\n", pe_subsystem_name(report->pe_subsystem));
    printf("  ASLR: %s\n", report->aslr_enabled ? "enabled" : "disabled");
    printf("  DEP / NX: %s\n", report->nx_enabled ? "enabled" : "disabled");
    printf("  CFG: %s\n", report->cfg_enabled ? "enabled" : "disabled");
    printf("  High-entropy VA: %s\n",
           report->high_entropy_va_enabled ? "enabled" : "disabled");
    printf("  Force Integrity: %s\n",
           report->force_integrity_enabled ? "enabled" : "disabled");
    printf("  No SEH: %s\n", report->no_seh_enabled ? "enabled" : "disabled");
    printf("  TLS callbacks: %s\n", bool_presence(report->pe_tls_callbacks_present));
    printf("  CLR runtime: %s\n", bool_presence(report->pe_clr_runtime));
    return;
  }

  printf("  No format-specific hardening data was found.\n");
}

static void print_provenance_report(const analysis_report_t *report) {
  printf("Provenance:\n");

  if (report->provenance_is_elf) {
    if (report->elf_build_id[0] != '\0') {
      printf("  Build ID: %s\n", report->elf_build_id);
    }
    if (report->elf_debuglink[0] != '\0') {
      printf("  Debug link: %s", report->elf_debuglink);
      if (report->elf_debuglink_crc_known) {
        printf(" (CRC32 %08" PRIx32 ")", report->elf_debuglink_crc32);
      }
      printf("\n");
    }
    if (report->compiler_comments.count != 0) {
      printf("  Compiler comments:\n");
      for (size_t index = 0; index < report->compiler_comments.count; ++index) {
        printf("    - %s\n", report->compiler_comments.items[index]);
      }
    }
    if (report->elf_build_id[0] == '\0' && report->elf_debuglink[0] == '\0' &&
        report->compiler_comments.count == 0) {
      printf("  No explicit ELF provenance hints were found.\n");
    }
    return;
  }

  if (report->provenance_is_pe) {
    if (report->pe_timestamp_known) {
      printf("  COFF timestamp: 0x%08" PRIx32, report->pe_timestamp);
      if (report->pe_timestamp_text[0] != '\0') {
        printf(" (%s)", report->pe_timestamp_text);
      }
      printf("\n");
    }
    printf("  Rich header: %s\n", bool_presence(report->pe_rich_header_present));
    if (report->pe_authenticode_present) {
      printf("  Authenticode certificate table: present at 0x%08" PRIx32
             " (%" PRIu32 " bytes, not verified)\n",
             report->pe_authenticode_offset, report->pe_authenticode_size);
    } else {
      printf("  Authenticode certificate table: not seen\n");
    }
    if (report->pe_codeview_present) {
      printf("  CodeView GUID: %s\n", report->pe_codeview_guid);
      printf("  PDB age: %" PRIu32 "\n", report->pe_codeview_age);
      if (report->pe_pdb_path[0] != '\0') {
        printf("  PDB path: %s\n", report->pe_pdb_path);
      }
    }
    printf("  Repro build marker: %s\n",
           bool_presence(report->pe_repro_debug_present));
    return;
  }

  printf("  No provenance metadata was found.\n");
}

static void print_pe_resource_report(const analysis_report_t *report) {
  printf("PE Resources:\n");

  if (!report->pe_resources_available) {
    printf("  No PE resource directory was found.\n");
    return;
  }

  printf("  Leaf resources: %zu\n", report->pe_resource_count);
  if (report->pe_resource_count == 0) {
    printf("  Resource directory exists, but no leaf entries were parsed.\n");
    return;
  }

  for (size_t index = 0; index < report->pe_resource_count; ++index) {
    const pe_resource_entry_t *entry = &report->pe_resources[index];

    printf("  [%02zu] %-12s %-18s lang=%-8s size=%" PRIu32,
           index + 1, entry->type, entry->name, entry->language,
           entry->data_size);
    if (entry->data_offset_known) {
      printf(" offset=0x%08zx", entry->data_offset);
    }
    printf(" rva=0x%08" PRIx32 " codepage=%" PRIu32 "\n",
           entry->data_rva, entry->codepage);
  }
}

static void print_overlay_report(const analysis_report_t *report) {
  printf("Overlay Analysis:\n");

  if (!report->overlay_analysis_available) {
    printf("  Overlay analysis unavailable for this file.\n");
    return;
  }

  printf("  Overlay offset: 0x%08zx\n", report->overlay_offset);
  printf("  Overlay size: %zu bytes\n", report->overlay_size);
  if (report->overlay_size == 0) {
    printf("  No overlay bytes were detected after the last on-disk section.\n");
    return;
  }

  if (report->overlay_hashes_available) {
    printf("  Overlay entropy: %.2f bits/byte\n", report->overlay_entropy);
    printf("  Overlay CRC32: %08" PRIx32 "\n", report->overlay_crc32_value);
  }

  if (report->embedded_signature_count == 0) {
    printf("  Embedded payload hints: none matched the current signature set\n");
    return;
  }

  printf("  Embedded payload hints:\n");
  for (size_t index = 0; index < report->embedded_signature_count; ++index) {
    printf("    - 0x%08zx %s\n", report->embedded_signatures[index].offset,
           report->embedded_signatures[index].kind);
  }
}

static size_t collect_pattern_hits(const bfd_byte *buffer, size_t size,
                                   const bfd_byte *pattern,
                                   size_t pattern_size, size_t *hits,
                                   size_t hit_limit) {
  size_t total = 0;

  if (pattern_size == 0 || pattern_size > size) {
    return 0;
  }

  for (size_t offset = 0; offset + pattern_size <= size; ++offset) {
    if (memcmp(buffer + offset, pattern, pattern_size) != 0) {
      continue;
    }
    if (total < hit_limit) {
      hits[total] = offset;
    }
    ++total;
  }

  return total;
}

static bool pattern_matches_at(const bfd_byte *buffer, size_t size,
                               size_t offset, const bfd_byte *pattern,
                               size_t pattern_size) {
  return pattern_size != 0 && offset <= size &&
         pattern_size <= size - offset &&
         memcmp(buffer + offset, pattern, pattern_size) == 0;
}

static size_t collect_utf16_hits(const bfd_byte *buffer, size_t size,
                                 const bfd_byte *pattern, size_t pattern_size,
                                 const bfd_byte *opposite_pattern,
                                 bool little_endian, size_t *hits,
                                 size_t hit_limit) {
  size_t total = 0;

  if (pattern_size == 0 || pattern_size > size) {
    return 0;
  }

  for (size_t offset = 0; offset + pattern_size <= size; ++offset) {
    bool shifted_opposite;

    if (memcmp(buffer + offset, pattern, pattern_size) != 0) {
      continue;
    }

    /* ASCII-range UTF-16 text can produce one-byte-shift mirror matches in the
       opposite endianness. Prefer the even-aligned match and suppress the odd
       mirror so both endian reports do not count the same bytes. */
    shifted_opposite =
        (offset % 2U) == 1U &&
        (little_endian
             ? pattern_matches_at(buffer, size, offset - 1, opposite_pattern,
                                  pattern_size)
             : pattern_matches_at(buffer, size, offset + 1, opposite_pattern,
                                  pattern_size));
    if (shifted_opposite) {
      continue;
    }

    if (total < hit_limit) {
      hits[total] = offset;
    }
    ++total;
  }

  return total;
}

static bool encode_utf16_literal(const char *text, bfd_byte **le_out,
                                 bfd_byte **be_out, size_t *size_out) {
  size_t length = strlen(text);
  bfd_byte *le_bytes;
  bfd_byte *be_bytes;

  if (length == 0) {
    return false;
  }

  le_bytes = malloc(length * 2);
  be_bytes = malloc(length * 2);
  if (le_bytes == NULL || be_bytes == NULL) {
    free(le_bytes);
    free(be_bytes);
    return false;
  }

  for (size_t index = 0; index < length; ++index) {
    unsigned char ch = (unsigned char)text[index];

    le_bytes[index * 2] = ch;
    le_bytes[index * 2 + 1] = 0;
    be_bytes[index * 2] = 0;
    be_bytes[index * 2 + 1] = ch;
  }

  *le_out = le_bytes;
  *be_out = be_bytes;
  *size_out = length * 2;
  return true;
}

static void print_search_hits(const char *label, unsigned int width,
                              const size_t *hits, size_t shown,
                              size_t total_count) {
  printf("    %s: %zu match%s\n", label, total_count,
         total_count == 1 ? "" : "es");
  for (size_t index = 0; index < shown; ++index) {
    printf("      - ");
    print_hex(stdout, width, (uintmax_t)hits[index]);
    printf("\n");
  }
  if (total_count > shown) {
    printf("      - ... %zu more not shown\n", total_count - shown);
  }
}

static bool print_search_results_for_path(const options_t *options) {
  bfd_byte *buffer = NULL;
  size_t size = 0;
  size_t *hits = NULL;
  unsigned int width;
  bool success = false;

  if (!read_file_bytes(options->path, &buffer, &size)) {
    fprintf(stderr, "binsight: unable to read '%s' for search\n", options->path);
    return false;
  }

  hits = calloc(options->search_hit_limit, sizeof(*hits));
  if (hits == NULL) {
    fprintf(stderr, "out of memory while collecting search hits\n");
    free(buffer);
    return false;
  }

  width = hex_width_for_value(size == 0 ? 0 : (uintmax_t)(size - 1));
  printf("Search Results:\n");
  printf("  File size: %zu bytes\n", size);
  printf("  Max hits per query: %zu\n", options->search_hit_limit);

  for (size_t query_index = 0; query_index < options->search_query_count;
       ++query_index) {
    const search_query_t *query = &options->search_queries[query_index];

    if (query->kind == SEARCH_QUERY_ASCII) {
      size_t pattern_size = strlen(query->text);
      size_t total = collect_pattern_hits(
          buffer, size, (const bfd_byte *)query->text, pattern_size, hits,
          options->search_hit_limit);
      size_t shown = total < options->search_hit_limit ? total
                                                       : options->search_hit_limit;

      printf("  Query %zu: ASCII \"%s\"\n", query_index + 1, query->text);
      print_search_hits("exact", width, hits, shown, total);
    } else if (query->kind == SEARCH_QUERY_HEX) {
      size_t total = collect_pattern_hits(buffer, size, query->bytes,
                                          query->byte_count, hits,
                                          options->search_hit_limit);
      size_t shown = total < options->search_hit_limit ? total
                                                       : options->search_hit_limit;

      printf("  Query %zu: HEX ", query_index + 1);
      print_byte_sequence(stdout, query->bytes, query->byte_count);
      printf("\n");
      print_search_hits("exact", width, hits, shown, total);
    } else if (query->kind == SEARCH_QUERY_UTF16) {
      bfd_byte *le_bytes = NULL;
      bfd_byte *be_bytes = NULL;
      size_t pattern_size = 0;
      size_t total_le;
      size_t shown_le;
      size_t total_be;
      size_t shown_be;

      if (!encode_utf16_literal(query->text, &le_bytes, &be_bytes, &pattern_size)) {
        fprintf(stderr, "out of memory while encoding UTF-16 search query\n");
        goto done;
      }

      printf("  Query %zu: UTF-16 \"%s\"\n", query_index + 1, query->text);
      total_le = collect_utf16_hits(buffer, size, le_bytes, pattern_size,
                                    be_bytes, true, hits,
                                    options->search_hit_limit);
      shown_le = total_le < options->search_hit_limit ? total_le
                                                      : options->search_hit_limit;
      print_search_hits("UTF-16LE", width, hits, shown_le, total_le);

      total_be = collect_utf16_hits(buffer, size, be_bytes, pattern_size,
                                    le_bytes, false, hits,
                                    options->search_hit_limit);
      shown_be = total_be < options->search_hit_limit ? total_be
                                                      : options->search_hit_limit;
      print_search_hits("UTF-16BE", width, hits, shown_be, total_be);

      free(le_bytes);
      free(be_bytes);
    }
  }

  success = true;

done:
  free(hits);
  free(buffer);
  return success;
}

static void print_extracted_strings(const analysis_report_t *report) {
  printf("Extracted Strings:\n");

  if (report->string_count == 0) {
    printf("  No strings matched the current extraction rules.\n");
    return;
  }

  printf("  Total strings: %zu\n", report->string_count);
  for (size_t index = 0; index < report->string_count; ++index) {
    printf("  [0x%08zx] %-7s %s\n", report->strings[index].offset,
           report->strings[index].encoding, report->strings[index].value);
  }
}

static void print_byte_sequence(FILE *stream, const bfd_byte *bytes,
                                size_t count) {
  for (size_t index = 0; index < count; ++index) {
    if (index != 0) {
      fputc(' ', stream);
    }
    fprintf(stream, "%02x", bytes[index]);
  }
}

static void print_hex_ascii_column(const bfd_byte *bytes, size_t count,
                                   size_t width) {
  size_t index;

  for (index = 0; index < count; ++index) {
    unsigned char value = bytes[index];

    /* Match the usual hexdump convention: printable bytes survive, the rest
       collapse to '.' so the ASCII gutter stays aligned and readable. */
    putchar(isprint(value) ? value : '.');
  }
  for (; index < width; ++index) {
    putchar(' ');
  }
}

static bool print_hex_view_for_path(const options_t *options) {
  bfd_byte *buffer = NULL;
  size_t size = 0;
  size_t start = options->hex_start_set ? options->hex_start : 0;
  size_t max_length = options->hex_length_set ? options->hex_length
                                              : DEFAULT_HEX_VIEW_LENGTH;
  size_t length;
  unsigned int width;
  size_t midpoint = options->hex_bytes_per_line / 2;

  if (!read_file_bytes(options->path, &buffer, &size)) {
    fprintf(stderr, "binsight: unable to read '%s' for hex view\n",
            options->path);
    return false;
  }

  /* The hex view intentionally bypasses libbfd so it still works on damaged
     or partially repaired files that are useful to inspect byte-for-byte. */
  if (start > size) {
    fprintf(stderr,
            "binsight: --hex-start points beyond the end of the file\n");
    free(buffer);
    return false;
  }

  length = max_length;
  if (length > size - start) {
    length = size - start;
  }

  width = hex_width_for_value(size == 0 ? 0 : (uintmax_t)(size - 1));
  printf("Hex View:\n");
  printf("  File size: %zu bytes\n", size);
  if (length == 0) {
    if (size == 0) {
      printf("  No bytes are available.\n");
    } else {
      printf("  Start offset ");
      print_hex(stdout, width, (uintmax_t)start);
      printf(" is at the end of the file.\n");
    }
    free(buffer);
    return true;
  }

  printf("  Showing bytes ");
  print_hex(stdout, width, (uintmax_t)start);
  printf(" - ");
  print_hex(stdout, width, (uintmax_t)(start + length - 1));
  printf(" (%zu byte%s", length, length == 1 ? "" : "s");
  if (start + length < size) {
    printf(", %zu omitted", size - (start + length));
  }
  printf(")\n");

  for (size_t row_offset = 0; row_offset < length;
       row_offset += options->hex_bytes_per_line) {
    size_t row_count = options->hex_bytes_per_line;
    size_t absolute_offset = start + row_offset;

    if (row_count > length - row_offset) {
      row_count = length - row_offset;
    }

    printf("  ");
    print_hex(stdout, width, (uintmax_t)absolute_offset);
    printf(": ");
    for (size_t index = 0; index < options->hex_bytes_per_line; ++index) {
      if (index < row_count) {
        printf("%02x ", buffer[absolute_offset + index]);
      } else {
        printf("   ");
      }
      /* Split each row into two visual groups, the same way most hex editors
         and hexdump tools break 16-byte rows into 8+8. */
      if (midpoint != 0 && index + 1 == midpoint) {
        putchar(' ');
      }
    }
    printf(" |");
    print_hex_ascii_column(buffer + absolute_offset, row_count,
                           options->hex_bytes_per_line);
    printf("|\n");
  }

  if (start + length < size) {
    if (!options->hex_length_set) {
      printf("  ... truncated to %d bytes by default; use --hex-length to show "
             "more\n",
             DEFAULT_HEX_VIEW_LENGTH);
    } else {
      printf("  ... %zu additional byte%s not shown\n",
             size - (start + length),
             (size - (start + length)) == 1 ? "" : "s");
    }
  }

  free(buffer);
  return true;
}

static bool patches_overlap(const byte_patch_t *left, const byte_patch_t *right) {
  size_t left_end = left->offset + left->length;
  size_t right_end = right->offset + right->length;

  /* Treat patches as half-open ranges [start, end): touching edges are fine,
     but any shared byte means the request is ambiguous and must be rejected. */
  return left->offset < right_end && right->offset < left_end;
}

static bool apply_byte_patches(const options_t *options) {
  bfd_byte *buffer = NULL;
  size_t size = 0;
  size_t total_bytes = 0;
  unsigned int width;
  char error_buffer[256];

  if (!read_file_bytes(options->path, &buffer, &size)) {
    fprintf(stderr, "binsight: unable to read '%s' for patching\n",
            options->path);
    return false;
  }

  for (size_t index = 0; index < options->patch_count; ++index) {
    const byte_patch_t *patch = &options->patches[index];

    if (patch->offset > size || patch->length > size - patch->offset) {
      fprintf(stderr,
              "binsight: patch at offset 0x%zx extends past the end of the "
              "file\n",
              patch->offset);
      free(buffer);
      return false;
    }
  }

  for (size_t left = 0; left < options->patch_count; ++left) {
    for (size_t right = left + 1; right < options->patch_count; ++right) {
      /* Reject overlapping ranges so repeated --patch flags cannot silently
         override one another based on argument order. */
      if (patches_overlap(&options->patches[left], &options->patches[right])) {
        fprintf(stderr,
                "binsight: patch ranges at 0x%zx and 0x%zx overlap\n",
                options->patches[left].offset, options->patches[right].offset);
        free(buffer);
        return false;
      }
    }
  }

  for (size_t index = 0; index < options->patch_count; ++index) {
    const byte_patch_t *patch = &options->patches[index];

    memcpy(buffer + patch->offset, patch->bytes, patch->length);
    total_bytes += patch->length;
  }

  /* Patch mode always writes a separate output file; the input stays untouched
     so analysts can compare original and edited samples side by side. */
  memset(error_buffer, 0, sizeof(error_buffer));
  if (!write_file_bytes(options->patch_output_path, buffer, size, error_buffer,
                        sizeof(error_buffer))) {
    fprintf(stderr, "binsight: %s\n", error_buffer);
    free(buffer);
    return false;
  }

  width = hex_width_for_value(size == 0 ? 0 : (uintmax_t)(size - 1));
  printf("Patched file written:\n");
  printf("  Input: %s\n", options->path);
  printf("  Output: %s\n", options->patch_output_path);
  printf("  Applied patches: %zu\n", options->patch_count);
  printf("  Total bytes changed: %zu\n", total_bytes);
  for (size_t index = 0; index < options->patch_count; ++index) {
    const byte_patch_t *patch = &options->patches[index];

    printf("  ");
    print_hex(stdout, width, (uintmax_t)patch->offset);
    printf(" (%zu byte%s): ", patch->length, patch->length == 1 ? "" : "s");
    print_byte_sequence(stdout, patch->bytes, patch->length);
    printf("\n");
  }

  free(buffer);
  return true;
}

static void json_begin_field(FILE *stream, bool *first, const char *name) {
  if (!*first) {
    fputc(',', stream);
  }
  *first = false;
  json_escape_text(stream, name);
  fputc(':', stream);
}

static void json_string_field(FILE *stream, bool *first, const char *name,
                              const char *value) {
  json_begin_field(stream, first, name);
  json_escape_text(stream, value != NULL ? value : "");
}

static void json_bool_field(FILE *stream, bool *first, const char *name,
                            bool value) {
  json_begin_field(stream, first, name);
  fputs(value ? "true" : "false", stream);
}

static void json_u64_field(FILE *stream, bool *first, const char *name,
                           uint64_t value) {
  json_begin_field(stream, first, name);
  fprintf(stream, "%" PRIu64, value);
}

static void json_i64_field(FILE *stream, bool *first, const char *name,
                           int64_t value) {
  json_begin_field(stream, first, name);
  fprintf(stream, "%" PRId64, value);
}

static void json_double_field(FILE *stream, bool *first, const char *name,
                              double value) {
  json_begin_field(stream, first, name);
  fprintf(stream, "%.6f", value);
}

static void print_json_string_array(FILE *stream, const string_list_t *list) {
  fputc('[', stream);
  if (list != NULL) {
    for (size_t index = 0; index < list->count; ++index) {
      if (index != 0) {
        fputc(',', stream);
      }
      json_escape_text(stream, list->items[index]);
    }
  }
  fputc(']', stream);
}

static void print_json_import_library(FILE *stream,
                                      const import_library_t *library) {
  bool first = true;

  fputc('{', stream);
  json_string_field(stream, &first, "library", library->name);
  json_u64_field(stream, &first, "symbol_count", library->symbols.count);
  json_begin_field(stream, &first, "symbols");
  print_json_string_array(stream, &library->symbols);
  fputc('}', stream);
}

static void print_json_section(FILE *stream, const section_report_t *section) {
  bool first = true;

  fputc('{', stream);
  json_u64_field(stream, &first, "index", section->index);
  json_string_field(stream, &first, "name", section->name);
  json_u64_field(stream, &first, "vma", section->vma);
  json_u64_field(stream, &first, "lma", section->lma);
  json_i64_field(stream, &first, "file_offset", section->filepos);
  json_u64_field(stream, &first, "size", section->size);
  json_u64_field(stream, &first, "raw_size", section->rawsize);
  json_u64_field(stream, &first, "compressed_size", section->compressed_size);
  json_u64_field(stream, &first, "entry_size", section->entsize);
  json_u64_field(stream, &first, "alignment_power", section->alignment_power);
  json_u64_field(stream, &first, "alignment_value",
                 alignment_value(section->alignment_power));
  json_u64_field(stream, &first, "relocations", section->reloc_count);
  json_u64_field(stream, &first, "line_numbers", section->lineno_count);
  json_bool_field(stream, &first, "alloc", (section->flags & SEC_ALLOC) != 0);
  json_bool_field(stream, &first, "load", (section->flags & SEC_LOAD) != 0);
  json_bool_field(stream, &first, "readonly",
                  (section->flags & SEC_READONLY) != 0);
  json_bool_field(stream, &first, "code", (section->flags & SEC_CODE) != 0);
  json_bool_field(stream, &first, "data", (section->flags & SEC_DATA) != 0);
  json_bool_field(stream, &first, "has_contents", section->has_contents);
  json_bool_field(stream, &first, "compressed", section->is_compressed);
  json_bool_field(stream, &first, "entry_point", section->contains_entry);
  json_bool_field(stream, &first, "suspicious_name", section->suspicious_name);
  json_bool_field(stream, &first, "writable_executable",
                  section->writable_and_executable);
  json_bool_field(stream, &first, "high_entropy", section->high_entropy);
  if (section->content_loaded) {
    json_double_field(stream, &first, "entropy", section->entropy);
    json_u64_field(stream, &first, "crc32", section->crc32_value);
  }
  if (section->suspicious_name_reason != NULL) {
    json_string_field(stream, &first, "suspicious_name_reason",
                      section->suspicious_name_reason);
  }
  fputc('}', stream);
}

static void print_json_protector_hints(FILE *stream,
                                       const analysis_report_t *report) {
  fputc('[', stream);
  for (size_t index = 0; index < report->protector_hint_count; ++index) {
    const protector_hint_t *hint = &report->protector_hints[index];
    bool first = true;

    if (index != 0) {
      fputc(',', stream);
    }
    fputc('{', stream);
    json_string_field(stream, &first, "name", hint->name);
    json_string_field(stream, &first, "kind", hint->kind);
    json_string_field(stream, &first, "confidence", hint->confidence);
    json_string_field(stream, &first, "evidence", hint->evidence);
    fputc('}', stream);
  }
  fputc(']', stream);
}

static void print_json_overview(FILE *stream, bfd *abfd, const char *path,
                                const symbol_table_t *symbols,
                                const analysis_report_t *report) {
  const bfd_arch_info_type *arch_info = bfd_get_arch_info(abfd);
  char file_flags[256];
  bool first = true;

  fputc('{', stream);
  json_string_field(stream, &first, "binary", path);
  json_string_field(stream, &first, "target", bfd_get_target(abfd));
  json_string_field(stream, &first, "flavour",
                    bfd_flavour_name(bfd_get_flavour(abfd)));
  json_string_field(stream, &first, "architecture",
                    arch_info != NULL ? arch_info->printable_name : "unknown");
  json_u64_field(stream, &first, "address_bits", bfd_arch_bits_per_address(abfd));
  json_u64_field(stream, &first, "byte_bits", bfd_arch_bits_per_byte(abfd));
  json_string_field(stream, &first, "endianness",
                    bfd_big_endian(abfd)
                        ? "big"
                        : (bfd_little_endian(abfd) ? "little" : "unknown"));
  json_u64_field(stream, &first, "entry_point", bfd_get_start_address(abfd));
  json_u64_field(stream, &first, "file_size", report->file_size);
  json_u64_field(stream, &first, "section_count", bfd_count_sections(abfd));
  json_string_field(stream, &first, "file_flags",
                    format_flags(bfd_get_file_flags(abfd), k_file_flags,
                                 sizeof(k_file_flags) / sizeof(k_file_flags[0]),
                                 file_flags, sizeof(file_flags)));
  json_u64_field(stream, &first, "symbols_loaded", symbols->count > 0
                                                  ? (uint64_t)symbols->count
                                                  : 0);
  json_string_field(stream, &first, "symbols_kind",
                    symbols->count > 0 ? (symbols->dynamic ? "dynamic" : "regular")
                                       : "none");
  json_string_field(stream, &first, "linking",
                    report->linking_known ? report->linking : "unknown");
  json_string_field(stream, &first, "loader",
                    report->loader_known ? report->loader : "unknown");
  json_string_field(stream, &first, "language_guess",
                    report->language_known ? report->language : "unknown");
  if (report->language_reason[0] != '\0') {
    json_string_field(stream, &first, "language_reason",
                      report->language_reason);
  }
  json_begin_field(stream, &first, "upx");
  fputc('{', stream);
  {
    bool upx_first = true;
    json_bool_field(stream, &upx_first, "packed", report->upx_packed);
    if (report->upx_version_known) {
      json_string_field(stream, &upx_first, "embedded_id",
                        report->upx_version_raw);
      json_string_field(stream, &upx_first, "version", report->upx_version);
      json_bool_field(stream, &upx_first, "version_normalized",
                      report->upx_version_normalized);
    }
    if (report->upx_pack_header_known) {
      json_u64_field(stream, &upx_first, "pack_header_version",
                     report->upx_pack_header_version);
      json_u64_field(stream, &upx_first, "pack_header_format",
                     report->upx_pack_header_format);
    }
  }
  fputc('}', stream);
  json_begin_field(stream, &first, "packer_protector_hints");
  print_json_protector_hints(stream, report);
  if (report->file_hashes_available) {
    json_begin_field(stream, &first, "hashes");
    fputc('{', stream);
    {
      bool hash_first = true;
      char crc32_text[9];

      snprintf(crc32_text, sizeof(crc32_text), "%08" PRIx32,
               report->file_crc32_value);
      json_string_field(stream, &hash_first, "crc32", crc32_text);
      json_string_field(stream, &hash_first, "md5", report->file_md5);
      json_string_field(stream, &hash_first, "sha256", report->file_sha256);
    }
    fputc('}', stream);
  }
  fputc('}', stream);
}

static void print_json_dependencies(FILE *stream, const analysis_report_t *report) {
  bool first = true;

  fputc('{', stream);
  if (report->dependency_summary_is_elf) {
    json_string_field(stream, &first, "format", "elf");
    json_begin_field(stream, &first, "needed_libraries");
    print_json_string_array(stream, &report->elf_needed_libraries);
    if (report->elf_soname[0] != '\0') {
      json_string_field(stream, &first, "soname", report->elf_soname);
    }
    if (report->elf_rpath[0] != '\0') {
      json_string_field(stream, &first, "rpath", report->elf_rpath);
    }
    if (report->elf_runpath[0] != '\0') {
      json_string_field(stream, &first, "runpath", report->elf_runpath);
    }
  } else if (report->dependency_summary_is_pe) {
    json_string_field(stream, &first, "format", "pe");
    json_begin_field(stream, &first, "imports");
    fputc('[', stream);
    for (size_t index = 0; index < report->pe_import_count; ++index) {
      if (index != 0) {
        fputc(',', stream);
      }
      print_json_import_library(stream, &report->pe_imports[index]);
    }
    fputc(']', stream);
    json_begin_field(stream, &first, "delay_imports");
    fputc('[', stream);
    for (size_t index = 0; index < report->pe_delay_import_count; ++index) {
      if (index != 0) {
        fputc(',', stream);
      }
      print_json_import_library(stream, &report->pe_delay_imports[index]);
    }
    fputc(']', stream);
    json_u64_field(stream, &first, "export_count", report->pe_export_count);
  } else {
    json_string_field(stream, &first, "format", "none");
    json_bool_field(stream, &first, "found", false);
  }
  fputc('}', stream);
}

static void print_json_triage(FILE *stream, const analysis_report_t *report) {
  bool first = true;
  bool findings_first = true;

  fputc('{', stream);
  if (report->entry_section != NULL) {
    json_string_field(stream, &first, "entry_point_section",
                      report->entry_section->name);
    json_bool_field(stream, &first, "entry_point_in_code",
                    (report->entry_section->flags & SEC_CODE) != 0);
    json_bool_field(stream, &first, "entry_point_in_writable_code",
                    (report->entry_section->flags & SEC_CODE) != 0 &&
                        (report->entry_section->flags & SEC_READONLY) == 0);
  }
  if (report->highest_entropy_section != NULL) {
    json_begin_field(stream, &first, "highest_entropy_section");
    fputc('{', stream);
    {
      bool entropy_first = true;
      json_string_field(stream, &entropy_first, "name",
                        report->highest_entropy_section->name);
      json_double_field(stream, &entropy_first, "entropy",
                        report->highest_entropy_section->entropy);
    }
    fputc('}', stream);
  }
  if (report->trailing_bytes_valid) {
    json_u64_field(stream, &first, "trailing_bytes_after_sections",
                   report->trailing_bytes_after_sections);
  }
  json_u64_field(stream, &first, "external_symbol_count",
                 report->external_symbol_count);
  json_u64_field(stream, &first, "undefined_symbol_count",
                 report->undefined_symbol_count);
  json_begin_field(stream, &first, "suspicious_api_clues");
  fputc('[', stream);
  for (size_t index = 0; index < report->symbol_clue_count; ++index) {
    if (index != 0) {
      fputc(',', stream);
    }
    fputc('{', stream);
    {
      bool clue_first = true;
      json_string_field(stream, &clue_first, "name",
                        report->symbol_clues[index].name);
      json_string_field(stream, &clue_first, "reason",
                        report->symbol_clues[index].reason);
      json_bool_field(stream, &clue_first, "undefined",
                      report->symbol_clues[index].undefined);
    }
    fputc('}', stream);
  }
  fputc(']', stream);
  json_begin_field(stream, &first, "packer_protector_hints");
  print_json_protector_hints(stream, report);
  json_begin_field(stream, &first, "section_findings");
  fputc('[', stream);
  if (report->entry_section != NULL &&
      (report->entry_section->flags & SEC_CODE) == 0) {
    json_escape_text(stream, "entry point lands in non-code section");
    findings_first = false;
  } else if (report->entry_section != NULL &&
             (report->entry_section->flags & SEC_READONLY) == 0) {
    json_escape_text(stream, "entry point lands in writable code section");
    findings_first = false;
  }
  for (size_t index = 0; index < report->section_count; ++index) {
    const section_report_t *section = &report->sections[index];
    char finding[256];

    if (section->writable_and_executable) {
      if (!findings_first) {
        fputc(',', stream);
      }
      snprintf(finding, sizeof(finding), "%s is writable and executable",
               section->name);
      json_escape_text(stream, finding);
      findings_first = false;
    }
    if (section->high_entropy) {
      if (!findings_first) {
        fputc(',', stream);
      }
      snprintf(finding, sizeof(finding), "%s has high entropy", section->name);
      json_escape_text(stream, finding);
      findings_first = false;
    }
    if (section->suspicious_name) {
      if (!findings_first) {
        fputc(',', stream);
      }
      snprintf(finding, sizeof(finding), "%s matched %s", section->name,
               section->suspicious_name_reason);
      json_escape_text(stream, finding);
      findings_first = false;
    }
  }
  fputc(']', stream);
  fputc('}', stream);
}

static void print_json_security(FILE *stream, const analysis_report_t *report) {
  bool first = true;

  fputc('{', stream);
  if (report->security_context_is_elf) {
    json_string_field(stream, &first, "format", "elf");
    json_string_field(stream, &first, "execution_model", report->execution_model);
    json_bool_field(stream, &first, "nx_known", report->nx_known);
    json_bool_field(stream, &first, "nx_enabled", report->nx_enabled);
    json_string_field(stream, &first, "relro", report->relro);
    json_bool_field(stream, &first, "stack_canary_present",
                    report->canary_present);
    json_bool_field(stream, &first, "fortify_present", report->fortify_present);
    json_bool_field(stream, &first, "tls_present", report->tls_present);
  } else if (report->security_context_is_pe) {
    json_string_field(stream, &first, "format", "pe");
    json_string_field(stream, &first, "subsystem",
                      pe_subsystem_name(report->pe_subsystem));
    json_bool_field(stream, &first, "aslr_enabled", report->aslr_enabled);
    json_bool_field(stream, &first, "nx_enabled", report->nx_enabled);
    json_bool_field(stream, &first, "cfg_enabled", report->cfg_enabled);
    json_bool_field(stream, &first, "high_entropy_va_enabled",
                    report->high_entropy_va_enabled);
    json_bool_field(stream, &first, "force_integrity_enabled",
                    report->force_integrity_enabled);
    json_bool_field(stream, &first, "no_seh_enabled", report->no_seh_enabled);
    json_bool_field(stream, &first, "tls_callbacks_present",
                    report->pe_tls_callbacks_present);
    json_bool_field(stream, &first, "clr_runtime_present", report->pe_clr_runtime);
  } else {
    json_bool_field(stream, &first, "found", false);
  }
  fputc('}', stream);
}

static void print_json_provenance(FILE *stream, const analysis_report_t *report) {
  bool first = true;

  fputc('{', stream);
  if (report->provenance_is_elf) {
    json_string_field(stream, &first, "format", "elf");
    if (report->elf_build_id[0] != '\0') {
      json_string_field(stream, &first, "build_id", report->elf_build_id);
    }
    if (report->elf_debuglink[0] != '\0') {
      json_string_field(stream, &first, "debuglink", report->elf_debuglink);
    }
    if (report->elf_debuglink_crc_known) {
      json_u64_field(stream, &first, "debuglink_crc32",
                     report->elf_debuglink_crc32);
    }
    json_begin_field(stream, &first, "compiler_comments");
    print_json_string_array(stream, &report->compiler_comments);
  } else if (report->provenance_is_pe) {
    json_string_field(stream, &first, "format", "pe");
    if (report->pe_timestamp_known) {
      json_u64_field(stream, &first, "timestamp", report->pe_timestamp);
      if (report->pe_timestamp_text[0] != '\0') {
        json_string_field(stream, &first, "timestamp_text",
                          report->pe_timestamp_text);
      }
    }
    json_bool_field(stream, &first, "rich_header_present",
                    report->pe_rich_header_present);
    json_bool_field(stream, &first, "authenticode_present",
                    report->pe_authenticode_present);
    if (report->pe_authenticode_present) {
      json_u64_field(stream, &first, "authenticode_offset",
                     report->pe_authenticode_offset);
      json_u64_field(stream, &first, "authenticode_size",
                     report->pe_authenticode_size);
    }
    json_bool_field(stream, &first, "codeview_present",
                    report->pe_codeview_present);
    if (report->pe_codeview_present) {
      json_string_field(stream, &first, "codeview_guid",
                        report->pe_codeview_guid);
      json_u64_field(stream, &first, "codeview_age", report->pe_codeview_age);
      if (report->pe_pdb_path[0] != '\0') {
        json_string_field(stream, &first, "pdb_path", report->pe_pdb_path);
      }
    }
    json_bool_field(stream, &first, "repro_debug_present",
                    report->pe_repro_debug_present);
  } else {
    json_bool_field(stream, &first, "found", false);
  }
  fputc('}', stream);
}

static void print_json_resources(FILE *stream, const analysis_report_t *report) {
  bool first = true;

  fputc('{', stream);
  json_bool_field(stream, &first, "found", report->pe_resources_available);
  if (report->pe_resources_available) {
    json_string_field(stream, &first, "format", "pe");
    json_u64_field(stream, &first, "count", report->pe_resource_count);
    json_begin_field(stream, &first, "entries");
    fputc('[', stream);
    for (size_t index = 0; index < report->pe_resource_count; ++index) {
      if (index != 0) {
        fputc(',', stream);
      }
      fputc('{', stream);
      {
        bool entry_first = true;
        json_string_field(stream, &entry_first, "type",
                          report->pe_resources[index].type);
        json_string_field(stream, &entry_first, "name",
                          report->pe_resources[index].name);
        json_string_field(stream, &entry_first, "language",
                          report->pe_resources[index].language);
        json_u64_field(stream, &entry_first, "data_rva",
                       report->pe_resources[index].data_rva);
        json_u64_field(stream, &entry_first, "size",
                       report->pe_resources[index].data_size);
        json_u64_field(stream, &entry_first, "codepage",
                       report->pe_resources[index].codepage);
        json_bool_field(stream, &entry_first, "data_offset_known",
                        report->pe_resources[index].data_offset_known);
        if (report->pe_resources[index].data_offset_known) {
          json_u64_field(stream, &entry_first, "data_offset",
                         report->pe_resources[index].data_offset);
        }
      }
      fputc('}', stream);
    }
    fputc(']', stream);
  }
  fputc('}', stream);
}

static void print_json_overlay(FILE *stream, const analysis_report_t *report) {
  bool first = true;

  fputc('{', stream);
  json_bool_field(stream, &first, "found", report->overlay_analysis_available);
  if (report->overlay_analysis_available) {
    json_u64_field(stream, &first, "offset", report->overlay_offset);
    json_u64_field(stream, &first, "size", report->overlay_size);
    json_bool_field(stream, &first, "hashes_available",
                    report->overlay_hashes_available);
    if (report->overlay_hashes_available) {
      json_double_field(stream, &first, "entropy", report->overlay_entropy);
      json_u64_field(stream, &first, "crc32", report->overlay_crc32_value);
    }
    json_begin_field(stream, &first, "embedded_signatures");
    fputc('[', stream);
    for (size_t index = 0; index < report->embedded_signature_count; ++index) {
      if (index != 0) {
        fputc(',', stream);
      }
      fputc('{', stream);
      {
        bool sig_first = true;
        json_u64_field(stream, &sig_first, "offset",
                       report->embedded_signatures[index].offset);
        json_string_field(stream, &sig_first, "kind",
                          report->embedded_signatures[index].kind);
      }
      fputc('}', stream);
    }
    fputc(']', stream);
  }
  fputc('}', stream);
}

static void print_json_report(bfd *abfd, const options_t *options,
                              const symbol_table_t *symbols,
                              const analysis_report_t *report) {
  bool first = true;

  printf("{");
  if (output_includes_any(options, OUTPUT_VIEW_OVERVIEW)) {
    json_begin_field(stdout, &first, "overview");
    print_json_overview(stdout, abfd, options->path, symbols, report);
  }
  if (output_includes_any(options, OUTPUT_VIEW_DEPENDENCIES)) {
    json_begin_field(stdout, &first, "dependencies");
    print_json_dependencies(stdout, report);
  }
  if (output_includes_any(options, OUTPUT_VIEW_TRIAGE)) {
    json_begin_field(stdout, &first, "triage");
    print_json_triage(stdout, report);
  }
  if (output_includes_any(options, OUTPUT_VIEW_SECTIONS)) {
    bool array_first = true;
    json_begin_field(stdout, &first, "sections");
    fputc('[', stdout);
    for (size_t index = 0; index < report->section_count; ++index) {
      if (!section_is_selected(options, report->sections[index].section)) {
        continue;
      }
      if (!array_first) {
        fputc(',', stdout);
      }
      array_first = false;
      print_json_section(stdout, &report->sections[index]);
    }
    fputc(']', stdout);
  }
  if (output_includes_any(options, OUTPUT_VIEW_STRINGS)) {
    json_begin_field(stdout, &first, "strings");
    fputc('[', stdout);
    for (size_t index = 0; index < report->string_count; ++index) {
      if (index != 0) {
        fputc(',', stdout);
      }
      fputc('{', stdout);
      {
        bool string_first = true;
        json_u64_field(stdout, &string_first, "offset", report->strings[index].offset);
        json_string_field(stdout, &string_first, "encoding",
                          report->strings[index].encoding);
        json_string_field(stdout, &string_first, "value",
                          report->strings[index].value);
      }
      fputc('}', stdout);
    }
    fputc(']', stdout);
  }
  if (output_includes_any(options, OUTPUT_VIEW_SECURITY)) {
    json_begin_field(stdout, &first, "security");
    print_json_security(stdout, report);
  }
  if (output_includes_any(options, OUTPUT_VIEW_PROVENANCE)) {
    json_begin_field(stdout, &first, "provenance");
    print_json_provenance(stdout, report);
  }
  if (output_includes_any(options, OUTPUT_VIEW_RESOURCES)) {
    json_begin_field(stdout, &first, "resources");
    print_json_resources(stdout, report);
  }
  if (output_includes_any(options, OUTPUT_VIEW_OVERLAY)) {
    json_begin_field(stdout, &first, "overlay");
    print_json_overlay(stdout, report);
  }
  printf("}\n");
}

static void print_ndjson_record_header(const char *path, const char *type) {
  printf("{\"binary\":");
  json_escape_text(stdout, path);
  printf(",\"type\":");
  json_escape_text(stdout, type);
  printf(",\"data\":");
}

static void print_ndjson_report(bfd *abfd, const options_t *options,
                                const symbol_table_t *symbols,
                                const analysis_report_t *report) {
  if (output_includes_any(options, OUTPUT_VIEW_OVERVIEW)) {
    print_ndjson_record_header(options->path, "overview");
    print_json_overview(stdout, abfd, options->path, symbols, report);
    printf("}\n");
  }
  if (output_includes_any(options, OUTPUT_VIEW_DEPENDENCIES)) {
    print_ndjson_record_header(options->path, "dependencies");
    print_json_dependencies(stdout, report);
    printf("}\n");
  }
  if (output_includes_any(options, OUTPUT_VIEW_TRIAGE)) {
    print_ndjson_record_header(options->path, "triage");
    print_json_triage(stdout, report);
    printf("}\n");
  }
  if (output_includes_any(options, OUTPUT_VIEW_SECURITY)) {
    print_ndjson_record_header(options->path, "security");
    print_json_security(stdout, report);
    printf("}\n");
  }
  if (output_includes_any(options, OUTPUT_VIEW_PROVENANCE)) {
    print_ndjson_record_header(options->path, "provenance");
    print_json_provenance(stdout, report);
    printf("}\n");
  }
  if (output_includes_any(options, OUTPUT_VIEW_RESOURCES)) {
    print_ndjson_record_header(options->path, "resources");
    print_json_resources(stdout, report);
    printf("}\n");
  }
  if (output_includes_any(options, OUTPUT_VIEW_OVERLAY)) {
    print_ndjson_record_header(options->path, "overlay");
    print_json_overlay(stdout, report);
    printf("}\n");
  }
  if (output_includes_any(options, OUTPUT_VIEW_SECTIONS)) {
    for (size_t index = 0; index < report->section_count; ++index) {
      if (!section_is_selected(options, report->sections[index].section)) {
        continue;
      }
      print_ndjson_record_header(options->path, "section");
      print_json_section(stdout, &report->sections[index]);
      printf("}\n");
    }
  }
  if (output_includes_any(options, OUTPUT_VIEW_STRINGS)) {
    for (size_t index = 0; index < report->string_count; ++index) {
      printf("{\"binary\":");
      json_escape_text(stdout, options->path);
      printf(",\"type\":\"string\",\"data\":{");
      {
        bool first = true;
        json_u64_field(stdout, &first, "offset", report->strings[index].offset);
        json_string_field(stdout, &first, "encoding",
                          report->strings[index].encoding);
        json_string_field(stdout, &first, "value", report->strings[index].value);
      }
      printf("}}\n");
    }
  }
}

static bool analyze_section_contents(bfd *abfd, section_report_t *report) {
  bfd_byte *contents = NULL;

  if (!report->has_contents || report->size == 0) {
    return true;
  }

  if (!bfd_get_full_section_contents(abfd, report->section, &contents)) {
    fprintf(stderr,
            "binsight: warning: unable to read section '%s' for entropy/hash "
            "analysis: %s\n",
            report->name, bfd_errmsg(bfd_get_error()));
    return true;
  }

  report->entropy = shannon_entropy(contents, report->size);
  report->crc32_value = crc32_bytes(contents, report->size);
  report->content_loaded = true;
  report->high_entropy = report->size >= 512 && report->entropy >= 7.20;
  free(contents);
  return true;
}

static bool build_analysis_report(bfd *abfd, const options_t *options,
                                  const symbol_table_t *symbols,
                                  analysis_report_t *report) {
  bfd_vma entry_point = bfd_get_start_address(abfd);
  uintmax_t max_mapped_end = 0;
  size_t cursor = 0;

  memset(report, 0, sizeof(*report));
  report->section_count = bfd_count_sections(abfd);

  if (!file_size_from_path(options->path, &report->file_size)) {
    report->file_size = (uintmax_t)bfd_get_file_size(abfd);
  }

  report->sections =
      calloc(report->section_count, sizeof(*report->sections));
  if (report->sections == NULL) {
    fprintf(stderr, "out of memory while building analysis report\n");
    return false;
  }

  for (asection *section = abfd->sections; section != NULL;
       section = section->next, ++cursor) {
    section_report_t *current = &report->sections[cursor];

    current->section = section;
    current->name = bfd_section_name(section);
    current->index = section->index;
    current->flags = bfd_section_flags(section);
    current->vma = bfd_section_vma(section);
    current->lma = bfd_section_lma(section);
    current->size = bfd_section_size(section);
    current->rawsize = section->rawsize;
    current->compressed_size = section->compressed_size;
    current->filepos = section->filepos;
    current->reloc_count = section->reloc_count;
    current->lineno_count = section->lineno_count;
    current->entsize = section->entsize;
    current->alignment_power = bfd_section_alignment(section);
    current->has_contents = (current->flags & SEC_HAS_CONTENTS) != 0;
    current->is_compressed = bfd_is_section_compressed(abfd, section);
    current->suspicious_name_reason = match_suspicious_rule(
        current->name, k_suspicious_section_name_rules,
        sizeof(k_suspicious_section_name_rules) /
            sizeof(k_suspicious_section_name_rules[0]));
    current->suspicious_name = current->suspicious_name_reason != NULL;
    current->writable_and_executable =
        (current->flags & SEC_CODE) != 0 &&
        (current->flags & SEC_READONLY) == 0 &&
        current->has_contents;
    current->contains_entry =
        current->size > 0 && entry_point >= current->vma &&
        entry_point < current->vma + current->size;

    if (section_is_selected(options, section)) {
      ++report->matched_sections;
    }

    if (current->contains_entry) {
      report->entry_section = current;
    }

    if (!analyze_section_contents(abfd, current)) {
      return false;
    }

    if (current->content_loaded &&
        (report->highest_entropy_section == NULL ||
         current->entropy > report->highest_entropy_section->entropy)) {
      report->highest_entropy_section = current;
    }

    if (current->writable_and_executable || current->high_entropy ||
        current->suspicious_name) {
      ++report->suspicious_section_count;
    }

    if (is_pe_target(abfd) && current->has_contents) {
      uintmax_t end = (uintmax_t)current->filepos + section_on_disk_size(current);
      if (end > max_mapped_end) {
        max_mapped_end = end;
      }
    }
  }

  if (is_pe_target(abfd)) {
    report->trailing_bytes_valid = true;
    if (report->file_size > max_mapped_end) {
      report->trailing_bytes_after_sections = report->file_size - max_mapped_end;
    }
  }

  analyze_symbols(symbols, report);
  if (output_includes_any(options, OUTPUT_VIEW_STRINGS) &&
      !collect_strings_from_sections(abfd, options, report)) {
    return false;
  }
  if (!enrich_analysis_report(abfd, options, symbols, report)) {
    infer_language_guess(symbols, report);
  }
  return true;
}

static void print_triage_report(const analysis_report_t *report) {
  bool printed_finding = false;

  printf("Malware Triage:\n");

  if (report->entry_section != NULL) {
    printf("  Entry point section: %s", report->entry_section->name);
    if ((report->entry_section->flags & SEC_CODE) == 0) {
      printf(" [entry point is not in a code section]");
    } else if ((report->entry_section->flags & SEC_READONLY) == 0) {
      printf(" [entry point is in a writable code section]");
    }
    printf("\n");
  } else {
    printf("  Entry point section: unknown\n");
  }

  if (report->highest_entropy_section != NULL) {
    printf("  Highest entropy section: %s (%.2f bits/byte)\n",
           report->highest_entropy_section->name,
           report->highest_entropy_section->entropy);
  } else {
    printf("  Highest entropy section: unavailable\n");
  }

  if (report->trailing_bytes_valid) {
    printf("  Trailing bytes after last mapped section: %" PRIuMAX,
           report->trailing_bytes_after_sections);
    if (report->trailing_bytes_after_sections != 0) {
      printf(" (may be PE certificate data or appended payload)");
    }
    printf("\n");
  }

  printf("  External/undefined symbols: %zu / %zu\n",
         report->external_symbol_count, report->undefined_symbol_count);

  if (report->symbol_clue_count != 0) {
    printf("  Suspicious API/function clues:\n");
    for (size_t index = 0; index < report->symbol_clue_count; ++index) {
      printf("    - %s (%s%s)\n", report->symbol_clues[index].name,
             report->symbol_clues[index].reason,
             report->symbol_clues[index].undefined ? ", unresolved/external"
                                                   : "");
    }
  } else {
    printf("  Suspicious API/function clues: none matched\n");
  }

  if (report->protector_hint_count != 0) {
    printf("  Packer/protector hints:\n");
    for (size_t index = 0; index < report->protector_hint_count; ++index) {
      const protector_hint_t *hint = &report->protector_hints[index];

      printf("    - %s (%s, %s confidence): %s\n", hint->name, hint->kind,
             hint->confidence, hint->evidence);
    }
  } else {
    printf("  Packer/protector hints: none matched\n");
  }

  printf("  Section findings:\n");
  if (report->entry_section != NULL &&
      (report->entry_section->flags & SEC_CODE) == 0) {
    printf("    - entry point lands in non-code section %s\n",
           report->entry_section->name);
    printed_finding = true;
  } else if (report->entry_section != NULL &&
             (report->entry_section->flags & SEC_READONLY) == 0) {
    printf("    - entry point lands in writable code section %s\n",
           report->entry_section->name);
    printed_finding = true;
  }

  for (size_t index = 0; index < report->section_count; ++index) {
    const section_report_t *section = &report->sections[index];

    if (section->writable_and_executable) {
      printf("    - %s is writable and executable\n", section->name);
      printed_finding = true;
    }
    if (section->high_entropy) {
      printf("    - %s has high entropy (%.2f bits/byte)\n", section->name,
             section->entropy);
      printed_finding = true;
    }
    if (section->suspicious_name) {
      printf("    - %s name matched %s\n", section->name,
             section->suspicious_name_reason);
      printed_finding = true;
    }
  }

  if (!printed_finding) {
    printf("    - no high-signal section anomalies detected\n");
  }
}

static void print_sections(bfd *abfd, const options_t *options,
                           const analysis_report_t *report) {
  unsigned int width = address_width_for_bfd(abfd);

  printf("Section Headers:\n");

  for (size_t index = 0; index < report->section_count; ++index) {
    const section_report_t *section = &report->sections[index];
    char section_flags[512];

    if (!section_is_selected(options, section->section)) {
      continue;
    }

    printf("[%02u] %s\n", section->index, section->name);

    printf("  VMA: ");
    print_hex(stdout, width, (uintmax_t)section->vma);
    printf("  LMA: ");
    print_hex(stdout, width, (uintmax_t)section->lma);
    printf("\n");

    printf("  File offset: ");
    print_hex(stdout, width, (uintmax_t)section->filepos);
    printf("  Size: ");
    print_hex(stdout, width, (uintmax_t)section->size);
    printf("  Raw size: ");
    print_hex(stdout, width, (uintmax_t)section->rawsize);
    printf("\n");

    printf("  Compressed size: ");
    print_hex(stdout, width, (uintmax_t)section->compressed_size);
    printf("  Entry size: ");
    print_hex(stdout, width, (uintmax_t)section->entsize);
    printf("  Align: 2^%u", section->alignment_power);
    if (section->alignment_power < sizeof(uintmax_t) * CHAR_BIT) {
      printf(" (%" PRIuMAX ")", alignment_value(section->alignment_power));
    }
    printf("\n");

    printf("  Relocations: %u  Line numbers: %u\n", section->reloc_count,
           section->lineno_count);
    printf("  Attributes: %s, %s, %s, %s, %s, %s, compressed=%s\n",
           section_attribute((section->flags & SEC_ALLOC) != 0, "alloc",
                             "no-alloc"),
           section_attribute((section->flags & SEC_LOAD) != 0, "load",
                             "no-load"),
           section_attribute((section->flags & SEC_READONLY) != 0, "readonly",
                             "writable"),
           section_attribute((section->flags & SEC_CODE) != 0, "code",
                             "non-code"),
           section_attribute((section->flags & SEC_DATA) != 0, "data",
                             "non-data"),
           section_attribute((section->flags & SEC_HAS_CONTENTS) != 0,
                             "contents", "no-contents"),
           yes_no(section->is_compressed));
    if (section->content_loaded) {
      printf("  Entropy: %.2f bits/byte  CRC32: %08" PRIx32
             "  Entry point: %s\n",
             section->entropy, section->crc32_value,
             yes_no(section->contains_entry));
    } else {
      printf("  Entropy: unavailable  CRC32: unavailable  Entry point: %s\n",
             yes_no(section->contains_entry));
    }
    printf("  Flags: %s\n",
           format_flags(section->flags, k_section_flags,
                        sizeof(k_section_flags) / sizeof(k_section_flags[0]),
                        section_flags, sizeof(section_flags)));
  }
}

static void print_disassembly_context_if_available(bfd *abfd,
                                                   const symbol_table_t *table,
                                                   asection *section,
                                                   bfd_vma offset,
                                                   const char **last_file,
                                                   const char **last_function,
                                                   unsigned int *last_line) {
  const char *file = NULL;
  const char *function = NULL;
  unsigned int line = 0;

  if (table == NULL || table->symbols == NULL || table->count <= 0) {
    return;
  }

  if (!bfd_find_nearest_line(abfd, section, table->symbols, offset, &file,
                             &function, &line)) {
    return;
  }

  if (file == NULL && function == NULL && line == 0) {
    return;
  }

  if (*last_file == file && *last_function == function && *last_line == line) {
    return;
  }

  printf("    ; ");
  if (function != NULL) {
    printf("%s", function);
    if (file != NULL) {
      printf(" ");
    }
  }
  if (file != NULL) {
    printf("%s", file);
    if (line != 0) {
      printf(":%u", line);
    }
  }
  printf("\n");

  *last_file = file;
  *last_function = function;
  *last_line = line;
}

static void print_instruction_bytes(const bfd_byte *bytes, size_t count) {
  size_t index;

  for (index = 0; index < count; ++index) {
    printf("%02x ", bytes[index]);
  }
  for (; index < 8; ++index) {
    printf("   ");
  }
}

static void memory_error_handler(int status, bfd_vma memaddr,
                                 struct disassemble_info *info) {
  info->fprintf_func(info->stream, "<memory error at 0x%" PRIxMAX ": %s>",
                     (uintmax_t)memaddr,
                     status != 0 ? strerror(status) : "unknown");
}

static bool remaining_bytes_are_zero(const bfd_byte *contents,
                                     bfd_size_type size,
                                     bfd_size_type offset) {
  for (bfd_size_type index = offset; index < size; ++index) {
    if (contents[index] != 0) {
      return false;
    }
  }
  return true;
}

static bool disassemble_section(bfd *abfd, asection *section,
                                const symbol_table_t *symbols) {
  bfd_byte *contents = NULL;
  bfd_size_type size = bfd_section_size(section);
  unsigned int width = address_width_for_bfd(abfd);
  section_symbol_table_t section_symbols;
  disassemble_info info;
  disassembler_ftype decoder;
  const char *last_file = NULL;
  const char *last_function = NULL;
  unsigned int last_line = 0;
  size_t symbol_cursor = 0;

  if (!bfd_get_full_section_contents(abfd, section, &contents)) {
    print_bfd_error(bfd_get_filename(abfd), "section read");
    return false;
  }

  if (!collect_section_symbols(symbols, section, &section_symbols)) {
    free(contents);
    return false;
  }

  INIT_DISASSEMBLE_INFO(info, stdout, fprintf, styled_fprintf);
  info.flavour = bfd_get_flavour(abfd);
  info.arch = bfd_get_arch(abfd);
  info.mach = bfd_get_mach(abfd);
  info.endian = bfd_big_endian(abfd) ? BFD_ENDIAN_BIG : BFD_ENDIAN_LITTLE;
  info.endian_code = info.endian;
  info.section = section;
  info.symtab = symbols != NULL ? symbols->symbols : NULL;
  info.symtab_size =
      (symbols != NULL && symbols->count > 0 && symbols->count < INT_MAX)
          ? (int)symbols->count
          : 0;
  info.read_memory_func = buffer_read_memory;
  info.memory_error_func = memory_error_handler;
  info.print_address_func = generic_print_address;
  info.symbol_at_address_func = generic_symbol_at_address;
  info.symbol_is_valid = generic_symbol_is_valid;
  info.buffer = contents;
  info.buffer_vma = bfd_section_vma(section);
  info.buffer_length = size;
  info.display_endian = info.endian;
  info.octets_per_byte = bfd_octets_per_byte(abfd, section);
  info.skip_zeroes = 16;
  info.skip_zeroes_at_end = 8;
  disassemble_init_for_target(&info);

  decoder = disassembler(info.arch, info.endian == BFD_ENDIAN_BIG, info.mach,
                         abfd);
  if (decoder == NULL) {
    fprintf(stderr,
            "binsight: no disassembler available for architecture '%s'\n",
            bfd_printable_arch_mach(info.arch, info.mach));
    disassemble_free_target(&info);
    free_section_symbols(&section_symbols);
    free(contents);
    return false;
  }

  printf("Disassembly of section %s:\n", bfd_section_name(section));

  for (bfd_vma address = bfd_section_vma(section),
               end = bfd_section_vma(section) + size;
       address < end;) {
    bfd_size_type offset = (bfd_size_type)(address - bfd_section_vma(section));
    size_t exact_start;
    size_t exact_end;
    FILE *stream = NULL;
    char *disassembly_text = NULL;
    size_t disassembly_length = 0;
    int instruction_size;
    const char *fallback_text = NULL;
    char fallback_buffer[64];

    if (offset >= size) {
      break;
    }

    if (size - offset >= info.skip_zeroes &&
        remaining_bytes_are_zero(contents, size, offset)) {
      printf("  ... skipped %" PRIuMAX " trailing zero bytes ...\n",
             (uintmax_t)(size - offset));
      break;
    }

    while (symbol_cursor < section_symbols.count &&
           bfd_asymbol_value(section_symbols.items[symbol_cursor]) < address) {
      ++symbol_cursor;
    }

    exact_start = symbol_cursor;
    while (symbol_cursor < section_symbols.count &&
           bfd_asymbol_value(section_symbols.items[symbol_cursor]) == address) {
      printf("\n%s:\n", bfd_asymbol_name(section_symbols.items[symbol_cursor]));
      ++symbol_cursor;
    }
    exact_end = symbol_cursor;

    info.symbols =
        exact_start < exact_end ? &section_symbols.items[exact_start] : NULL;
    info.num_symbols =
        exact_start < exact_end ? (int)(exact_end - exact_start) : 0;

    print_disassembly_context_if_available(abfd, symbols, section, offset,
                                           &last_file, &last_function,
                                           &last_line);

    stream = open_memstream(&disassembly_text, &disassembly_length);
    if (stream == NULL) {
      perror("open_memstream");
      disassemble_free_target(&info);
      free_section_symbols(&section_symbols);
      free(contents);
      return false;
    }

    disassemble_set_printf(&info, stream, (fprintf_ftype)fprintf,
                           styled_fprintf);
    instruction_size = decoder(address, &info);
    fflush(stream);
    fclose(stream);

    if (instruction_size <= 0) {
      snprintf(fallback_buffer, sizeof(fallback_buffer), ".byte 0x%02x",
               contents[offset]);
      fallback_text = fallback_buffer;
      instruction_size = 1;
    }

    if (offset + (bfd_size_type)instruction_size > size) {
      instruction_size = (int)(size - offset);
    }

    printf("  ");
    print_hex(stdout, width, (uintmax_t)address);
    printf(": ");
    print_instruction_bytes(contents + offset, (size_t)instruction_size);
    printf("%s\n", fallback_text != NULL ? fallback_text : disassembly_text);

    free(disassembly_text);
    address += (bfd_vma)instruction_size;
  }

  disassemble_free_target(&info);
  free_section_symbols(&section_symbols);
  free(contents);
  return true;
}

static bool inspect_binary(const options_t *options) {
  bfd *abfd = NULL;
  symbol_table_t symbols;
  analysis_report_t report;
  char **matching = NULL;
  bool printed_disassembly = false;
  bool printed_output = false;
  bool success = false;

  memset(&symbols, 0, sizeof(symbols));
  memset(&report, 0, sizeof(report));
  bfd_set_error_program_name("binsight");

  abfd = bfd_openr(options->path, NULL);
  if (abfd == NULL) {
    print_bfd_error(options->path, "open");
    goto done;
  }

  if (!bfd_check_format_matches(abfd, bfd_object, &matching)) {
    if (bfd_get_error() == bfd_error_file_ambiguously_recognized &&
        matching != NULL) {
      fprintf(stderr, "binsight: ambiguous target for '%s'. Matches:\n",
              options->path);
      for (char **candidate = matching; *candidate != NULL; ++candidate) {
        fprintf(stderr, "  %s\n", *candidate);
      }
    } else {
      print_bfd_error(options->path, "format check");
    }
    goto done;
  }

  if (!load_symbols(abfd, &symbols)) {
    goto done;
  }

  if (!build_analysis_report(abfd, options, &symbols, &report)) {
    goto done;
  }

  if (options->section_filter_count != 0 && report.matched_sections == 0) {
    fprintf(stderr, "binsight: no sections matched the current filters\n");
    goto done;
  }

  if (options->json_output) {
    print_json_report(abfd, options, &symbols, &report);
    success = true;
    goto done;
  }

  if (options->ndjson_output) {
    print_ndjson_report(abfd, options, &symbols, &report);
    success = true;
    goto done;
  }

  if (output_includes_any(options, OUTPUT_VIEW_OVERVIEW)) {
    print_file_overview(abfd, options->path, &symbols, &report);
    printed_output = true;
  }

  if (output_includes_any(options, OUTPUT_VIEW_DEPENDENCIES)) {
    if (printed_output) {
      printf("\n");
    }
    print_dependency_summary(&report);
    printed_output = true;
  }

  if (output_includes_any(options, OUTPUT_VIEW_HEADERS)) {
    char native_error[256];

    if (printed_output) {
      printf("\n");
    }
    memset(native_error, 0, sizeof(native_error));
    if (!print_native_header_details(options->path, native_error,
                                     sizeof(native_error))) {
      fprintf(stderr, "binsight: warning: native header details unavailable: %s\n",
              native_error);
    } else {
      printed_output = true;
    }
  }

  if (output_includes_any(options, OUTPUT_VIEW_TRIAGE)) {
    if (printed_output) {
      printf("\n");
    }
    print_triage_report(&report);
    printed_output = true;
  }

  if (output_includes_any(options, OUTPUT_VIEW_SECURITY)) {
    if (printed_output) {
      printf("\n");
    }
    print_security_context(&report);
    printed_output = true;
  }

  if (output_includes_any(options, OUTPUT_VIEW_PROVENANCE)) {
    if (printed_output) {
      printf("\n");
    }
    print_provenance_report(&report);
    printed_output = true;
  }

  if (output_includes_any(options, OUTPUT_VIEW_RESOURCES)) {
    if (printed_output) {
      printf("\n");
    }
    print_pe_resource_report(&report);
    printed_output = true;
  }

  if (output_includes_any(options, OUTPUT_VIEW_OVERLAY)) {
    if (printed_output) {
      printf("\n");
    }
    print_overlay_report(&report);
    printed_output = true;
  }

  if (output_includes_any(options, OUTPUT_VIEW_SECTIONS)) {
    if (printed_output) {
      printf("\n");
    }
    print_sections(abfd, options, &report);
    printed_output = true;
  }

  if (output_includes_any(options, OUTPUT_VIEW_STRINGS)) {
    if (printed_output) {
      printf("\n");
    }
    print_extracted_strings(&report);
    printed_output = true;
  }

  if (output_includes_any(options, OUTPUT_VIEW_SEARCH)) {
    if (printed_output) {
      printf("\n");
    }
    if (!print_search_results_for_path(options)) {
      goto done;
    }
    printed_output = true;
  }

  if (output_includes_any(options, OUTPUT_VIEW_HEX)) {
    if (printed_output) {
      printf("\n");
    }
    if (!print_hex_view_for_path(options)) {
      goto done;
    }
    printed_output = true;
  }

  if (!output_includes_any(options, OUTPUT_VIEW_DISASSEMBLY)) {
    success = true;
    goto done;
  }

  success = true;
  if (printed_output) {
    printf("\n");
  }
  for (asection *section = abfd->sections; section != NULL;
       section = section->next) {
    if (!section_is_disassemblable(options, section)) {
      continue;
    }
    if (printed_disassembly) {
      printf("\n");
    }
    if (!disassemble_section(abfd, section, &symbols)) {
      success = false;
      goto done;
    }
    printed_disassembly = true;
  }

done:
  free_analysis_report(&report);
  free(matching);
  free_symbols(&symbols);
  if (abfd != NULL) {
    bfd_close(abfd);
  }
  return success;
}

int main(int argc, char **argv) {
  options_t options;
  parse_result_t parse_result;
  bool success;
  upx_repair_summary_t repair_summary;
  char error_buffer[512];

  bfd_init();

  parse_result = parse_options(argc, argv, &options);
  if (parse_result == PARSE_HELP) {
    free_options(&options);
    return 0;
  }
  if (parse_result == PARSE_ERROR) {
    free_options(&options);
    return 1;
  }

  if (options.repair_upx || options.repair_and_unpack_upx) {
    memset(&repair_summary, 0, sizeof(repair_summary));
    memset(error_buffer, 0, sizeof(error_buffer));

    success = options.repair_upx
                  ? repair_upx_file(options.path, options.output_path,
                                    &repair_summary, error_buffer,
                                    sizeof(error_buffer))
                  : repair_and_unpack_upx_file(options.path,
                                               options.output_path,
                                               &repair_summary, error_buffer,
                                               sizeof(error_buffer));

    if (!success) {
      fprintf(stderr, "binsight: %s\n", error_buffer);
      free_options(&options);
      return 1;
    }

    print_upx_repair_summary(options.path, options.output_path,
                             &repair_summary, options.repair_and_unpack_upx);
    free_options(&options);
    return 0;
  }

  /* Hex-only viewing and patching do not need libbfd at all, so handle those
     as direct raw-byte workflows before opening the binary as an object file. */
  if (options.patch_count != 0) {
    success = apply_byte_patches(&options);
    free_options(&options);
    return success ? 0 : 1;
  }

  if (output_uses_only_raw_views(&options)) {
    bool printed_output = false;

    success = true;
    if (output_includes_any(&options, OUTPUT_VIEW_SEARCH)) {
      success = print_search_results_for_path(&options);
      printed_output = success;
    }
    if (success && output_includes_any(&options, OUTPUT_VIEW_HEX)) {
      if (printed_output) {
        printf("\n");
      }
      success = print_hex_view_for_path(&options);
    }
    free_options(&options);
    return success ? 0 : 1;
  }

  success = inspect_binary(&options);
  free_options(&options);
  return success ? 0 : 1;
}
