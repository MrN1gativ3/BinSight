#include "native_headers.h"

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

enum {
  EI_CLASS = 4,
  EI_DATA = 5,
  EI_VERSION = 6,
  EI_OSABI = 7,
  EI_ABIVERSION = 8,
  ELFCLASS32 = 1,
  ELFCLASS64 = 2,
  ELFDATA2LSB = 1,
  ELFDATA2MSB = 2,
  PT_NULL = 0,
  PT_LOAD = 1,
  PT_DYNAMIC = 2,
  PT_INTERP = 3,
  PT_NOTE = 4,
  PT_SHLIB = 5,
  PT_PHDR = 6,
  PT_TLS = 7,
  PT_GNU_EH_FRAME = 0x6474e550,
  PT_GNU_STACK = 0x6474e551,
  PT_GNU_RELRO = 0x6474e552,
  IMAGE_FILE_MACHINE_I386 = 0x14c,
  IMAGE_FILE_MACHINE_ARMNT = 0x1c4,
  IMAGE_FILE_MACHINE_THUMB = 0x1c2,
  IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
  IMAGE_FILE_MACHINE_AMD64 = 0x8664,
};

typedef struct {
  uint32_t rva;
  uint32_t size;
} pe_data_directory_t;

typedef struct {
  uint32_t type;
  uint32_t flags;
  uint64_t offset;
  uint64_t vaddr;
  uint64_t paddr;
  uint64_t filesz;
  uint64_t memsz;
  uint64_t align;
} elf_program_header_t;

typedef struct {
  uint16_t flag;
  const char *name;
} pe_flag_t;

typedef struct {
  uint32_t value;
  const char *name;
} named_u32_t;

static const char *k_pe_data_directory_names[] = {
    "Export",          "Import",        "Resource",      "Exception",
    "Certificate",     "Base Reloc",    "Debug",         "Architecture",
    "Global Ptr",      "TLS",           "Load Config",   "Bound Import",
    "IAT",             "Delay Import",  "CLR Runtime",   "Reserved",
};

static const pe_flag_t k_pe_characteristics[] = {
    {0x0001, "RELOCS_STRIPPED"},
    {0x0002, "EXECUTABLE_IMAGE"},
    {0x0004, "LINE_NUMS_STRIPPED"},
    {0x0008, "LOCAL_SYMS_STRIPPED"},
    {0x0010, "AGGRESSIVE_WS_TRIM"},
    {0x0020, "LARGE_ADDRESS_AWARE"},
    {0x0080, "BYTES_REVERSED_LO"},
    {0x0100, "32BIT_MACHINE"},
    {0x0200, "DEBUG_STRIPPED"},
    {0x0400, "REMOVABLE_RUN_FROM_SWAP"},
    {0x0800, "NET_RUN_FROM_SWAP"},
    {0x1000, "SYSTEM"},
    {0x2000, "DLL"},
    {0x4000, "UP_SYSTEM_ONLY"},
    {0x8000, "BYTES_REVERSED_HI"},
};

static const pe_flag_t k_pe_dll_characteristics[] = {
    {0x0020, "HIGH_ENTROPY_VA"},
    {0x0040, "DYNAMIC_BASE"},
    {0x0080, "FORCE_INTEGRITY"},
    {0x0100, "NX_COMPAT"},
    {0x0200, "NO_ISOLATION"},
    {0x0400, "NO_SEH"},
    {0x0800, "NO_BIND"},
    {0x1000, "APPCONTAINER"},
    {0x2000, "WDM_DRIVER"},
    {0x4000, "GUARD_CF"},
    {0x8000, "TERMINAL_SERVER_AWARE"},
};

static const named_u32_t k_elf_program_header_types[] = {
    {PT_NULL, "NULL"},
    {PT_LOAD, "LOAD"},
    {PT_DYNAMIC, "DYNAMIC"},
    {PT_INTERP, "INTERP"},
    {PT_NOTE, "NOTE"},
    {PT_SHLIB, "SHLIB"},
    {PT_PHDR, "PHDR"},
    {PT_TLS, "TLS"},
    {PT_GNU_EH_FRAME, "GNU_EH_FRAME"},
    {PT_GNU_STACK, "GNU_STACK"},
    {PT_GNU_RELRO, "GNU_RELRO"},
};

static void set_error(char *buffer, size_t buffer_size, const char *format,
                      ...) {
  va_list arguments;

  if (buffer == NULL || buffer_size == 0) {
    return;
  }

  va_start(arguments, format);
  vsnprintf(buffer, buffer_size, format, arguments);
  va_end(arguments);
}

static bool read_file(const char *path, uint8_t **buffer, size_t *size,
                      char *error_buffer, size_t error_buffer_size) {
  FILE *stream;
  struct stat st;
  uint8_t *data;

  if (stat(path, &st) != 0) {
    set_error(error_buffer, error_buffer_size, "stat('%s') failed: %s", path,
              strerror(errno));
    return false;
  }

  if (st.st_size <= 0) {
    set_error(error_buffer, error_buffer_size, "'%s' is empty", path);
    return false;
  }

  stream = fopen(path, "rb");
  if (stream == NULL) {
    set_error(error_buffer, error_buffer_size, "open('%s') failed: %s", path,
              strerror(errno));
    return false;
  }

  data = malloc((size_t)st.st_size);
  if (data == NULL) {
    fclose(stream);
    set_error(error_buffer, error_buffer_size,
              "out of memory while reading '%s'", path);
    return false;
  }

  if (fread(data, 1, (size_t)st.st_size, stream) != (size_t)st.st_size) {
    fclose(stream);
    free(data);
    set_error(error_buffer, error_buffer_size, "read('%s') failed", path);
    return false;
  }

  fclose(stream);
  *buffer = data;
  *size = (size_t)st.st_size;
  return true;
}

static uint16_t read_u16_le(const uint8_t *buffer) {
  return (uint16_t)buffer[0] | ((uint16_t)buffer[1] << 8);
}

static uint32_t read_u32_le(const uint8_t *buffer) {
  return (uint32_t)buffer[0] | ((uint32_t)buffer[1] << 8) |
         ((uint32_t)buffer[2] << 16) | ((uint32_t)buffer[3] << 24);
}

static uint64_t read_u64_le(const uint8_t *buffer) {
  return (uint64_t)read_u32_le(buffer) |
         ((uint64_t)read_u32_le(buffer + 4) << 32);
}

static uint16_t read_u16_endian(const uint8_t *buffer, bool big_endian) {
  if (big_endian) {
    return ((uint16_t)buffer[0] << 8) | (uint16_t)buffer[1];
  }
  return read_u16_le(buffer);
}

static uint32_t read_u32_endian(const uint8_t *buffer, bool big_endian) {
  if (big_endian) {
    return ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
           ((uint32_t)buffer[2] << 8) | (uint32_t)buffer[3];
  }
  return read_u32_le(buffer);
}

static uint64_t read_u64_endian(const uint8_t *buffer, bool big_endian) {
  if (big_endian) {
    return ((uint64_t)read_u32_endian(buffer, true) << 32) |
           (uint64_t)read_u32_endian(buffer + 4, true);
  }
  return read_u64_le(buffer);
}

static const char *elf_type_name(uint16_t type) {
  switch (type) {
    case 0:
      return "NONE";
    case 1:
      return "REL";
    case 2:
      return "EXEC";
    case 3:
      return "DYN";
    case 4:
      return "CORE";
    default:
      return "UNKNOWN";
  }
}

static const char *elf_osabi_name(uint8_t osabi) {
  switch (osabi) {
    case 0:
      return "System V";
    case 1:
      return "HP-UX";
    case 2:
      return "NetBSD";
    case 3:
      return "Linux";
    case 6:
      return "Solaris";
    case 7:
      return "AIX";
    case 8:
      return "IRIX";
    case 9:
      return "FreeBSD";
    case 12:
      return "OpenBSD";
    default:
      return "Unknown";
  }
}

static const char *elf_machine_name(uint16_t machine) {
  switch (machine) {
    case 3:
      return "Intel 80386";
    case 8:
      return "MIPS";
    case 20:
      return "PowerPC";
    case 21:
      return "PowerPC64";
    case 40:
      return "ARM";
    case 42:
      return "SuperH";
    case 50:
      return "IA-64";
    case 62:
      return "x86-64";
    case 183:
      return "AArch64";
    case 243:
      return "RISC-V";
    default:
      return "Unknown";
  }
}

static const char *elf_program_header_type_name(uint32_t type) {
  for (size_t index = 0;
       index < sizeof(k_elf_program_header_types) /
                    sizeof(k_elf_program_header_types[0]);
       ++index) {
    if (k_elf_program_header_types[index].value == type) {
      return k_elf_program_header_types[index].name;
    }
  }
  return "UNKNOWN";
}

static const char *pe_machine_name(uint16_t machine) {
  switch (machine) {
    case IMAGE_FILE_MACHINE_I386:
      return "x86";
    case IMAGE_FILE_MACHINE_THUMB:
      return "Thumb";
    case IMAGE_FILE_MACHINE_ARMNT:
      return "ARM";
    case IMAGE_FILE_MACHINE_AMD64:
      return "x86-64";
    case IMAGE_FILE_MACHINE_ARM64:
      return "ARM64";
    default:
      return "Unknown";
  }
}

static const char *pe_subsystem_name(uint16_t subsystem) {
  switch (subsystem) {
    case 0:
      return "Unknown";
    case 1:
      return "Native";
    case 2:
      return "Windows GUI";
    case 3:
      return "Windows CUI";
    case 5:
      return "OS/2 CUI";
    case 7:
      return "POSIX CUI";
    case 9:
      return "Windows CE";
    case 10:
      return "EFI Application";
    case 11:
      return "EFI Boot Service Driver";
    case 12:
      return "EFI Runtime Driver";
    case 13:
      return "EFI ROM";
    case 14:
      return "XBOX";
    case 16:
      return "Windows Boot Application";
    default:
      return "Unknown";
  }
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

static const char *format_pe_flags(uint16_t value, const pe_flag_t *flags,
                                   size_t flag_count, char *buffer,
                                   size_t buffer_size) {
  size_t used = 0;
  bool first = true;

  if (buffer_size == 0) {
    return buffer;
  }

  buffer[0] = '\0';
  for (size_t index = 0; index < flag_count; ++index) {
    if ((value & flags[index].flag) == 0) {
      continue;
    }
    if (!first) {
      append_text(buffer, buffer_size, &used, ", ");
    }
    append_text(buffer, buffer_size, &used, flags[index].name);
    first = false;
  }

  if (first) {
    append_text(buffer, buffer_size, &used, "none");
  }

  return buffer;
}

static const char *elf_program_header_flags(uint32_t flags, char buffer[4]) {
  buffer[0] = (flags & 4U) != 0 ? 'R' : '-';
  buffer[1] = (flags & 2U) != 0 ? 'W' : '-';
  buffer[2] = (flags & 1U) != 0 ? 'X' : '-';
  buffer[3] = '\0';
  return buffer;
}

static const char *pe_timestamp_string(uint32_t timestamp, char *buffer,
                                       size_t buffer_size) {
  time_t seconds;
  struct tm *tm_value;

  if (timestamp == 0 || buffer == NULL || buffer_size == 0) {
    return NULL;
  }

  seconds = (time_t)timestamp;
  tm_value = gmtime(&seconds);
  if (tm_value == NULL) {
    return NULL;
  }

  if (strftime(buffer, buffer_size, "%Y-%m-%d %H:%M:%S UTC", tm_value) == 0) {
    return NULL;
  }
  return buffer;
}

static bool print_elf_header_details(const uint8_t *buffer, size_t size,
                                     char *error_buffer,
                                     size_t error_buffer_size) {
  bool is64;
  bool big_endian;
  uint16_t type;
  uint16_t machine;
  uint16_t ehsize;
  uint16_t phentsize;
  uint16_t phnum;
  uint16_t shentsize;
  uint16_t shnum;
  uint16_t shstrndx;
  uint32_t flags;
  uint64_t phoff;
  uint64_t shoff;
  uint8_t osabi;
  uint8_t abi_version;
  uint64_t entry;
  const uint8_t *interp_string = NULL;

  if (size < 64 || buffer[EI_VERSION] != 1 ||
      (buffer[EI_CLASS] != ELFCLASS32 && buffer[EI_CLASS] != ELFCLASS64) ||
      (buffer[EI_DATA] != ELFDATA2LSB && buffer[EI_DATA] != ELFDATA2MSB)) {
    set_error(error_buffer, error_buffer_size,
              "unsupported or truncated ELF header");
    return false;
  }

  is64 = buffer[EI_CLASS] == ELFCLASS64;
  big_endian = buffer[EI_DATA] == ELFDATA2MSB;
  type = read_u16_endian(buffer + 16, big_endian);
  machine = read_u16_endian(buffer + 18, big_endian);
  entry = is64 ? read_u64_endian(buffer + 24, big_endian)
               : read_u32_endian(buffer + 24, big_endian);
  phoff = is64 ? read_u64_endian(buffer + 32, big_endian)
               : read_u32_endian(buffer + 28, big_endian);
  shoff = is64 ? read_u64_endian(buffer + 40, big_endian)
               : read_u32_endian(buffer + 32, big_endian);
  flags = read_u32_endian(buffer + (is64 ? 48 : 36), big_endian);
  ehsize = read_u16_endian(buffer + (is64 ? 52 : 40), big_endian);
  phentsize = read_u16_endian(buffer + (is64 ? 54 : 42), big_endian);
  phnum = read_u16_endian(buffer + (is64 ? 56 : 44), big_endian);
  shentsize = read_u16_endian(buffer + (is64 ? 58 : 46), big_endian);
  shnum = read_u16_endian(buffer + (is64 ? 60 : 48), big_endian);
  shstrndx = read_u16_endian(buffer + (is64 ? 62 : 50), big_endian);
  osabi = buffer[EI_OSABI];
  abi_version = buffer[EI_ABIVERSION];

  printf("Native Header Details:\n");
  printf("  Container: ELF%s\n", is64 ? "64" : "32");
  printf("  Type: %s (0x%04x)\n", elf_type_name(type), type);
  printf("  Machine: %s (0x%04x)\n", elf_machine_name(machine), machine);
  printf("  OS ABI: %s  ABI version: %u\n", elf_osabi_name(osabi),
         abi_version);
  printf("  Entry: 0x%0*" PRIx64 "\n", is64 ? 16 : 8, entry);
  printf("  Flags: 0x%08" PRIx32 "\n", flags);
  printf("  ELF header size: %u bytes\n", ehsize);
  printf("  Program headers: offset=0x%" PRIx64 " entry-size=%u count=%u\n",
         phoff, phentsize, phnum);
  printf("  Section headers: offset=0x%" PRIx64 " entry-size=%u count=%u"
         " shstrndx=%u\n",
         shoff, shentsize, shnum, shstrndx);

  if (phoff != 0 && phentsize != 0 && phnum != 0 &&
      phoff + (uint64_t)phentsize * phnum <= size) {
    printf("  Program header table:\n");
    for (uint16_t index = 0; index < phnum; ++index) {
      const uint8_t *ph = buffer + phoff + (uint64_t)phentsize * index;
      elf_program_header_t current;
      char flag_text[4];

      if (is64) {
        current.type = read_u32_endian(ph, big_endian);
        current.flags = read_u32_endian(ph + 4, big_endian);
        current.offset = read_u64_endian(ph + 8, big_endian);
        current.vaddr = read_u64_endian(ph + 16, big_endian);
        current.paddr = read_u64_endian(ph + 24, big_endian);
        current.filesz = read_u64_endian(ph + 32, big_endian);
        current.memsz = read_u64_endian(ph + 40, big_endian);
        current.align = read_u64_endian(ph + 48, big_endian);
      } else {
        current.type = read_u32_endian(ph, big_endian);
        current.offset = read_u32_endian(ph + 4, big_endian);
        current.vaddr = read_u32_endian(ph + 8, big_endian);
        current.paddr = read_u32_endian(ph + 12, big_endian);
        current.filesz = read_u32_endian(ph + 16, big_endian);
        current.memsz = read_u32_endian(ph + 20, big_endian);
        current.flags = read_u32_endian(ph + 24, big_endian);
        current.align = read_u32_endian(ph + 28, big_endian);
      }

      if (current.type == PT_INTERP && current.offset < size &&
          current.offset + current.filesz <= size) {
        interp_string = buffer + current.offset;
      }

      printf("    [%02u] %-13s off=0x%0*" PRIx64 " vaddr=0x%0*" PRIx64
             " filesz=0x%0*" PRIx64 " memsz=0x%0*" PRIx64 " flags=%s"
             " align=0x%" PRIx64 "\n",
             index, elf_program_header_type_name(current.type), is64 ? 16 : 8,
             current.offset, is64 ? 16 : 8, current.vaddr, is64 ? 16 : 8,
             current.filesz, is64 ? 16 : 8, current.memsz,
             elf_program_header_flags(current.flags, flag_text), current.align);
    }
  }

  if (interp_string != NULL) {
    printf("  Interpreter: %s\n", (const char *)interp_string);
  }

  return true;
}

static bool print_pe_header_details(const uint8_t *buffer, size_t size,
                                    char *error_buffer,
                                    size_t error_buffer_size) {
  size_t pe_offset;
  const uint8_t *coff;
  const uint8_t *optional;
  uint16_t machine;
  uint16_t section_count;
  uint32_t timestamp;
  uint16_t optional_size;
  uint16_t characteristics;
  uint16_t optional_magic;
  bool pe32_plus;
  uint32_t entry_rva;
  uint64_t image_base;
  uint32_t section_alignment;
  uint32_t file_alignment;
  uint32_t size_of_image;
  uint32_t size_of_headers;
  uint32_t checksum;
  uint16_t subsystem;
  uint16_t dll_characteristics;
  uint32_t directory_count;
  pe_data_directory_t directories[16] = {0};
  char characteristics_text[512];
  char dll_text[512];
  char timestamp_text[64];

  if (size < 0x40 || buffer[0] != 'M' || buffer[1] != 'Z') {
    set_error(error_buffer, error_buffer_size,
              "unsupported or truncated DOS/PE header");
    return false;
  }

  pe_offset = read_u32_le(buffer + 0x3c);
  if (pe_offset + 4 + 20 > size ||
      memcmp(buffer + pe_offset, "PE\0\0", 4) != 0) {
    set_error(error_buffer, error_buffer_size, "PE signature not found");
    return false;
  }

  coff = buffer + pe_offset + 4;
  machine = read_u16_le(coff);
  section_count = read_u16_le(coff + 2);
  timestamp = read_u32_le(coff + 4);
  optional_size = read_u16_le(coff + 16);
  characteristics = read_u16_le(coff + 18);
  optional = coff + 20;

  if ((size_t)(optional - buffer) + optional_size > size || optional_size < 96) {
    set_error(error_buffer, error_buffer_size, "optional PE header is truncated");
    return false;
  }

  optional_magic = read_u16_le(optional);
  pe32_plus = optional_magic == 0x20b;
  if (optional_magic != 0x10b && optional_magic != 0x20b) {
    set_error(error_buffer, error_buffer_size,
              "unsupported PE optional header magic 0x%04x", optional_magic);
    return false;
  }

  entry_rva = read_u32_le(optional + 16);
  image_base = pe32_plus ? read_u64_le(optional + 24) : read_u32_le(optional + 28);
  section_alignment = read_u32_le(optional + 32);
  file_alignment = read_u32_le(optional + 36);
  size_of_image = read_u32_le(optional + 56);
  size_of_headers = read_u32_le(optional + 60);
  checksum = read_u32_le(optional + 64);
  subsystem = read_u16_le(optional + 68);
  dll_characteristics = read_u16_le(optional + 70);
  directory_count = read_u32_le(optional + (pe32_plus ? 108 : 92));

  if (directory_count > 16) {
    directory_count = 16;
  }

  for (uint32_t index = 0; index < directory_count; ++index) {
    const uint8_t *entry =
        optional + (pe32_plus ? 112 : 96) + (size_t)index * 8;
    if ((size_t)(entry - buffer) + 8 > size) {
      break;
    }
    directories[index].rva = read_u32_le(entry);
    directories[index].size = read_u32_le(entry + 4);
  }

  printf("Native Header Details:\n");
  printf("  Container: %s\n", pe32_plus ? "PE32+" : "PE32");
  printf("  DOS header e_lfanew: 0x%zx\n", pe_offset);
  printf("  COFF machine: %s (0x%04x)\n", pe_machine_name(machine), machine);
  printf("  COFF timestamp: 0x%08" PRIx32, timestamp);
  if (pe_timestamp_string(timestamp, timestamp_text, sizeof(timestamp_text)) !=
      NULL) {
    printf(" (%s)", timestamp_text);
  }
  printf("\n");
  printf("  Number of sections: %u\n", section_count);
  printf("  Characteristics: %s\n",
         format_pe_flags(characteristics, k_pe_characteristics,
                         sizeof(k_pe_characteristics) /
                             sizeof(k_pe_characteristics[0]),
                         characteristics_text, sizeof(characteristics_text)));
  printf("  Optional header size: %u bytes\n", optional_size);
  printf("  Entry RVA: 0x%08" PRIx32 "\n", entry_rva);
  printf("  Image base: 0x%" PRIx64 "\n", image_base);
  printf("  Section alignment: 0x%08" PRIx32
         "  File alignment: 0x%08" PRIx32 "\n",
         section_alignment, file_alignment);
  printf("  Size of image: 0x%08" PRIx32
         "  Size of headers: 0x%08" PRIx32 "\n",
         size_of_image, size_of_headers);
  printf("  Checksum: 0x%08" PRIx32 "\n", checksum);
  printf("  Subsystem: %s (%u)\n", pe_subsystem_name(subsystem), subsystem);
  printf("  DLL characteristics: %s\n",
         format_pe_flags(dll_characteristics, k_pe_dll_characteristics,
                         sizeof(k_pe_dll_characteristics) /
                             sizeof(k_pe_dll_characteristics[0]),
                         dll_text, sizeof(dll_text)));
  printf("  Data directories:\n");
  for (uint32_t index = 0; index < directory_count; ++index) {
    if (directories[index].rva == 0 && directories[index].size == 0) {
      continue;
    }
    printf("    [%02" PRIu32 "] %-14s RVA=0x%08" PRIx32 " Size=0x%08" PRIx32
           "\n",
           index,
           index < sizeof(k_pe_data_directory_names) /
                       sizeof(k_pe_data_directory_names[0])
               ? k_pe_data_directory_names[index]
               : "Unknown",
           directories[index].rva, directories[index].size);
  }

  return true;
}

bool print_native_header_details(const char *path, char *error_buffer,
                                 size_t error_buffer_size) {
  uint8_t *buffer = NULL;
  size_t size = 0;
  bool ok;

  if (!read_file(path, &buffer, &size, error_buffer, error_buffer_size)) {
    return false;
  }

  if (size >= 4 && buffer[0] == 0x7f && buffer[1] == 'E' && buffer[2] == 'L' &&
      buffer[3] == 'F') {
    ok = print_elf_header_details(buffer, size, error_buffer, error_buffer_size);
  } else if (size >= 2 && buffer[0] == 'M' && buffer[1] == 'Z') {
    ok = print_pe_header_details(buffer, size, error_buffer, error_buffer_size);
  } else {
    set_error(error_buffer, error_buffer_size,
              "no native ELF or PE header parser is available for this file");
    ok = false;
  }

  free(buffer);
  return ok;
}
