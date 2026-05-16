#define _GNU_SOURCE

#include "upx_repair.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

enum {
  EI_CLASS = 4,
  EI_DATA = 5,
  EI_VERSION = 6,
  ELFCLASS32 = 1,
  ELFCLASS64 = 2,
  ELFDATA2LSB = 1,
  ELFDATA2MSB = 2,
  IMAGE_FILE_MACHINE_I386 = 0x14c,
  IMAGE_FILE_MACHINE_THUMB = 0x1c2,
  IMAGE_FILE_MACHINE_ARMNT = 0x1c4,
  IMAGE_FILE_MACHINE_AMD64 = 0x8664,
  UPX_F_W32PE_I386 = 9,
  UPX_F_WINCE_ARM = 21,
  UPX_F_W64PE_AMD64 = 36,
};

typedef struct {
  bool is64;
  bool big_endian;
  bool magic_missing;
  size_t file_size;
  size_t ehsize;
  size_t phoff;
  uint16_t phentsize;
  uint16_t phnum;
  size_t linfo_offset;
  size_t pinfo_offset;
} elf_layout_t;

typedef struct {
  bool pe32_plus;
  bool is_efi;
  size_t pe_offset;
  size_t optional_header_offset;
  size_t section_table_offset;
  uint16_t machine;
  uint16_t section_count;
  uint16_t optional_header_size;
  uint32_t entry_rva;
} pe_layout_t;

typedef struct {
  char name[9];
  size_t header_offset;
  uint32_t raw_offset;
  uint32_t raw_size;
  uint32_t virtual_address;
  uint32_t virtual_size;
} pe_section_info_t;

typedef struct {
  bool found;
  bool big_endian;
  bool checksum_valid;
  size_t offset;
  size_t header_size;
  uint8_t version;
  uint8_t format;
  uint32_t unpacked_file_size;
  const uint8_t *matched_magic;
  bool matched_magic_is_upx;
} upx_pack_header_t;

static const uint8_t k_elf_magic[4] = {0x7f, 'E', 'L', 'F'};
static const uint8_t k_upx_magic[4] = {'U', 'P', 'X', '!'};

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

static bool write_file(const char *path, const uint8_t *buffer, size_t size,
                       char *error_buffer, size_t error_buffer_size) {
  FILE *stream = fopen(path, "wb");

  if (stream == NULL) {
    set_error(error_buffer, error_buffer_size, "open('%s') failed: %s", path,
              strerror(errno));
    return false;
  }

  if (fwrite(buffer, 1, size, stream) != size) {
    fclose(stream);
    set_error(error_buffer, error_buffer_size, "write('%s') failed: %s", path,
              strerror(errno));
    return false;
  }

  if (fclose(stream) != 0) {
    set_error(error_buffer, error_buffer_size, "close('%s') failed: %s", path,
              strerror(errno));
    return false;
  }

  return true;
}

static uint16_t read_u16(const uint8_t *buffer, bool big_endian) {
  if (big_endian) {
    return (uint16_t)(((uint16_t)buffer[0] << 8) | (uint16_t)buffer[1]);
  }
  return (uint16_t)(((uint16_t)buffer[1] << 8) | (uint16_t)buffer[0]);
}

static uint32_t read_u32(const uint8_t *buffer, bool big_endian) {
  if (big_endian) {
    return ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
           ((uint32_t)buffer[2] << 8) | (uint32_t)buffer[3];
  }
  return ((uint32_t)buffer[3] << 24) | ((uint32_t)buffer[2] << 16) |
         ((uint32_t)buffer[1] << 8) | (uint32_t)buffer[0];
}

static uint64_t read_u64(const uint8_t *buffer, bool big_endian) {
  uint64_t upper;
  uint64_t lower;

  if (big_endian) {
    upper = read_u32(buffer, true);
    lower = read_u32(buffer + 4, true);
    return (upper << 32) | lower;
  }

  lower = read_u32(buffer, false);
  upper = read_u32(buffer + 4, false);
  return (upper << 32) | lower;
}

static void write_u32(uint8_t *buffer, bool big_endian, uint32_t value) {
  if (big_endian) {
    buffer[0] = (uint8_t)(value >> 24);
    buffer[1] = (uint8_t)(value >> 16);
    buffer[2] = (uint8_t)(value >> 8);
    buffer[3] = (uint8_t)value;
    return;
  }

  buffer[0] = (uint8_t)value;
  buffer[1] = (uint8_t)(value >> 8);
  buffer[2] = (uint8_t)(value >> 16);
  buffer[3] = (uint8_t)(value >> 24);
}

static bool is_zero_magic(const uint8_t *magic) {
  return magic[0] == 0 && magic[1] == 0 && magic[2] == 0 && magic[3] == 0;
}

static bool infer_elf_layout(const uint8_t *buffer, size_t size,
                             elf_layout_t *layout, char *error_buffer,
                             size_t error_buffer_size) {
  bool has_magic = size >= 16 && memcmp(buffer, k_elf_magic, 4) == 0;
  bool plausible_without_magic;
  size_t ehsize_offset;
  size_t phoff_offset;
  size_t phentsize_offset;
  size_t phnum_offset;
  uint64_t phoff;
  uint16_t ehsize;
  uint16_t phentsize;
  uint16_t phnum;

  if (size < 64) {
    set_error(error_buffer, error_buffer_size,
              "file is too small to contain a valid ELF header");
    return false;
  }

  plausible_without_magic =
      (buffer[EI_CLASS] == ELFCLASS32 || buffer[EI_CLASS] == ELFCLASS64) &&
      (buffer[EI_DATA] == ELFDATA2LSB || buffer[EI_DATA] == ELFDATA2MSB) &&
      buffer[EI_VERSION] == 1;

  if (!has_magic && !plausible_without_magic) {
    set_error(error_buffer, error_buffer_size,
              "file does not look like a parseable ELF binary");
    return false;
  }

  memset(layout, 0, sizeof(*layout));
  layout->magic_missing = !has_magic;
  layout->is64 = buffer[EI_CLASS] == ELFCLASS64;
  layout->big_endian = buffer[EI_DATA] == ELFDATA2MSB;
  layout->file_size = size;

  if (layout->is64) {
    ehsize_offset = 0x34;
    phoff_offset = 0x20;
    phentsize_offset = 0x36;
    phnum_offset = 0x38;
    layout->ehsize = 64;
  } else {
    ehsize_offset = 0x28;
    phoff_offset = 0x1c;
    phentsize_offset = 0x2a;
    phnum_offset = 0x2c;
    layout->ehsize = 52;
  }

  ehsize = read_u16(buffer + ehsize_offset, layout->big_endian);
  phentsize = read_u16(buffer + phentsize_offset, layout->big_endian);
  phnum = read_u16(buffer + phnum_offset, layout->big_endian);
  phoff = layout->is64 ? read_u64(buffer + phoff_offset, layout->big_endian)
                       : read_u32(buffer + phoff_offset, layout->big_endian);

  if (ehsize != layout->ehsize) {
    set_error(error_buffer, error_buffer_size,
              "ELF header size is inconsistent");
    return false;
  }

  if (phnum == 0) {
    set_error(error_buffer, error_buffer_size,
              "ELF program header table is missing");
    return false;
  }

  if ((!layout->is64 && phentsize != 32) || (layout->is64 && phentsize != 56)) {
    set_error(error_buffer, error_buffer_size,
              "unexpected ELF program header entry size");
    return false;
  }

  if (phoff > size || phoff + (uint64_t)phentsize * phnum > size) {
    set_error(error_buffer, error_buffer_size,
              "ELF program header table points outside the file");
    return false;
  }

  layout->phoff = (size_t)phoff;
  layout->phentsize = phentsize;
  layout->phnum = phnum;
  layout->linfo_offset = layout->phoff + (size_t)layout->phentsize * layout->phnum;
  layout->pinfo_offset = layout->linfo_offset + 12;

  if (layout->pinfo_offset + 12 > size) {
    set_error(error_buffer, error_buffer_size,
              "ELF is parseable but does not contain the expected UPX loader "
              "metadata area");
    return false;
  }

  return true;
}

static bool infer_pe_layout(const uint8_t *buffer, size_t size,
                            pe_layout_t *layout, pe_section_info_t **sections,
                            char *error_buffer,
                            size_t error_buffer_size) {
  size_t pe_offset;
  size_t optional_header_offset;
  size_t section_table_offset;
  uint16_t machine;
  uint16_t section_count;
  uint16_t optional_header_size;
  uint16_t optional_magic;
  pe_section_info_t *items;

  if (size < 0x40 || buffer[0] != 'M' || buffer[1] != 'Z') {
    set_error(error_buffer, error_buffer_size,
              "file does not look like a PE executable");
    return false;
  }

  pe_offset = read_u32(buffer + 0x3c, false);
  if (pe_offset + 24 > size || memcmp(buffer + pe_offset, "PE\0\0", 4) != 0) {
    set_error(error_buffer, error_buffer_size, "PE signature not found");
    return false;
  }

  machine = read_u16(buffer + pe_offset + 4, false);
  section_count = read_u16(buffer + pe_offset + 6, false);
  optional_header_size = read_u16(buffer + pe_offset + 20, false);
  optional_header_offset = pe_offset + 24;
  section_table_offset = optional_header_offset + optional_header_size;

  if (section_count < 2 || section_count > 16) {
    set_error(error_buffer, error_buffer_size,
              "unexpected PE section count %u", section_count);
    return false;
  }

  if (section_table_offset + (size_t)section_count * 40 > size ||
      optional_header_offset + optional_header_size > size ||
      optional_header_size < 96) {
    set_error(error_buffer, error_buffer_size, "PE headers are truncated");
    return false;
  }

  optional_magic = read_u16(buffer + optional_header_offset, false);
  if (optional_magic != 0x10b && optional_magic != 0x20b) {
    set_error(error_buffer, error_buffer_size,
              "unsupported PE optional header magic 0x%04x", optional_magic);
    return false;
  }

  items = calloc(section_count, sizeof(*items));
  if (items == NULL) {
    set_error(error_buffer, error_buffer_size,
              "out of memory while parsing PE sections");
    return false;
  }

  for (uint16_t index = 0; index < section_count; ++index) {
    const uint8_t *section = buffer + section_table_offset + (size_t)index * 40;

    memcpy(items[index].name, section, 8);
    items[index].name[8] = '\0';
    items[index].header_offset = section_table_offset + (size_t)index * 40;
    items[index].virtual_size = read_u32(section + 8, false);
    items[index].virtual_address = read_u32(section + 12, false);
    items[index].raw_size = read_u32(section + 16, false);
    items[index].raw_offset = read_u32(section + 20, false);

    if (items[index].raw_size != 0 &&
        ((size_t)items[index].raw_offset > size ||
         (size_t)items[index].raw_offset + items[index].raw_size > size)) {
      free(items);
      set_error(error_buffer, error_buffer_size,
                "PE section %u points outside the file", index);
      return false;
    }
  }

  memset(layout, 0, sizeof(*layout));
  layout->pe_offset = pe_offset;
  layout->optional_header_offset = optional_header_offset;
  layout->section_table_offset = section_table_offset;
  layout->machine = machine;
  layout->section_count = section_count;
  layout->optional_header_size = optional_header_size;
  layout->pe32_plus = optional_magic == 0x20b;
  layout->entry_rva = read_u32(buffer + optional_header_offset + 16, false);
  {
    uint16_t subsystem =
        read_u16(buffer + optional_header_offset + 68, false);
    layout->is_efi = subsystem >= 10 && subsystem <= 13;
  }
  *sections = items;
  return true;
}

static bool pe_machine_to_upx_format(const pe_layout_t *layout,
                                     uint8_t *format) {
  if (layout->machine == IMAGE_FILE_MACHINE_I386) {
    *format = UPX_F_W32PE_I386;
    return true;
  }
  if (layout->machine == IMAGE_FILE_MACHINE_AMD64) {
    *format = UPX_F_W64PE_AMD64;
    return true;
  }
  if (layout->machine == IMAGE_FILE_MACHINE_THUMB ||
      layout->machine == IMAGE_FILE_MACHINE_ARMNT) {
    *format = UPX_F_WINCE_ARM;
    return true;
  }
  return false;
}

static ssize_t find_last_occurrence(const uint8_t *buffer, size_t size,
                                    const uint8_t *needle,
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

static size_t get_pack_header_size(uint8_t version, uint8_t format) {
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

static uint8_t get_pack_header_checksum(const uint8_t *buffer, size_t size) {
  unsigned checksum = 0;

  for (size_t index = 4; index < size; ++index) {
    checksum += buffer[index];
  }

  return (uint8_t)(checksum % 251U);
}

static bool parse_decimal_uintmax(const char *text, uintmax_t *value_out) {
  uintmax_t value = 0;

  if (text == NULL || text[0] == '\0' || value_out == NULL) {
    return false;
  }

  for (size_t index = 0; text[index] != '\0'; ++index) {
    unsigned char ch = (unsigned char)text[index];
    unsigned int digit;

    if (ch < '0' || ch > '9') {
      return false;
    }

    digit = (unsigned int)(ch - '0');
    if (value > (UINTMAX_MAX - digit) / 10U) {
      return false;
    }
    value = value * 10U + digit;
  }

  *value_out = value;
  return true;
}

static bool normalize_upx_version_token(const char *token, char *buffer,
                                        size_t size, bool *changed) {
  const char *dot;
  char major_text[16];
  char suffix[16];
  uintmax_t major;
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
  if (!parse_decimal_uintmax(major_text, &major)) {
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
    snprintf(buffer, size, "%" PRIuMAX ".%c.%c", major, suffix[0], suffix[1]);
    if (changed != NULL) {
      *changed = strcmp(buffer, token) != 0;
    }
    return true;
  }

  snprintf(buffer, size, "%s", token);
  return true;
}

static bool detect_upx_release_string(const uint8_t *buffer, size_t size,
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

static bool detect_upx_release_major(const uint8_t *buffer, size_t size,
                                     int *major_version) {
  static const char needle[] = "$Id: UPX ";

  for (size_t index = 0; index + sizeof(needle) < size; ++index) {
    if (memcmp(buffer + index, needle, sizeof(needle) - 1) != 0) {
      continue;
    }
    if (buffer[index + sizeof(needle) - 1] < '0' ||
        buffer[index + sizeof(needle) - 1] > '9') {
      continue;
    }

    *major_version = buffer[index + sizeof(needle) - 1] - '0';
    return true;
  }

  return false;
}

static bool detect_pack_header(const uint8_t *buffer, size_t size,
                               const uint8_t current_linfo_magic[4],
                               size_t minimum_offset,
                               uint8_t expected_version,
                               uint8_t expected_format,
                               upx_pack_header_t *header) {
  const uint8_t *pattern = k_upx_magic;
  ssize_t offset = find_last_occurrence(buffer, size, k_upx_magic, 4);
  bool used_upx_magic = true;

  memset(header, 0, sizeof(*header));

  if (offset < 0 && memcmp(current_linfo_magic, k_upx_magic, 4) != 0 &&
      !is_zero_magic(current_linfo_magic)) {
    pattern = current_linfo_magic;
    offset = find_last_occurrence(buffer, size, current_linfo_magic, 4);
    used_upx_magic = false;
  }

  if (offset < 0) {
    return false;
  }

  if ((size_t)offset + 8 > size) {
    return false;
  }
  if ((size_t)offset < minimum_offset) {
    return false;
  }

  header->offset = (size_t)offset;
  header->version = buffer[header->offset + 4];
  header->format = buffer[header->offset + 5];
  if (header->version != expected_version || header->format != expected_format) {
    return false;
  }
  if (header->version == 0 || header->version > 20 || header->format == 0) {
    return false;
  }
  header->big_endian = header->format >= 128;
  header->header_size = get_pack_header_size(header->version, header->format);
  header->matched_magic = pattern;
  header->matched_magic_is_upx = used_upx_magic;

  if (header->header_size < 28 || header->offset + header->header_size > size) {
    return false;
  }

  header->unpacked_file_size =
      read_u32(buffer + header->offset + 24, header->big_endian);
  if (header->unpacked_file_size == 0) {
    return false;
  }
  if (header->version >= 10) {
    uint8_t expected =
        get_pack_header_checksum(buffer + header->offset, header->header_size - 1);
    uint8_t current = buffer[header->offset + header->header_size - 1];
    header->checksum_valid = current == expected;
    if (!header->checksum_valid) {
      return false;
    }
  } else {
    header->checksum_valid = true;
  }

  header->found = true;
  return true;
}

static bool decode_pack_header_candidate(const uint8_t *buffer, size_t size,
                                         size_t offset,
                                         upx_pack_header_t *header) {
  size_t header_size;
  uint8_t version;
  uint8_t format;
  uint32_t length_a;
  uint32_t length_b;
  uint8_t expected_checksum;
  uint8_t current_checksum;

  if (offset + 28 > size || memcmp(buffer + offset, k_upx_magic, 4) != 0) {
    return false;
  }

  memset(header, 0, sizeof(*header));
  version = buffer[offset + 4];
  format = buffer[offset + 5];
  if (version == 0 || version > 20 || format == 0) {
    return false;
  }

  header_size = get_pack_header_size(version, format);
  if (header_size < 28 || offset + header_size > size) {
    return false;
  }

  header->offset = offset;
  header->version = version;
  header->format = format;
  header->header_size = header_size;
  header->matched_magic = k_upx_magic;
  header->matched_magic_is_upx = true;
  header->big_endian = header->format >= 128;
  header->unpacked_file_size =
      read_u32(buffer + header->offset + 24, header->big_endian);
  if (header->unpacked_file_size == 0) {
    return false;
  }

  length_a = read_u32(buffer + header->offset + 16, header->big_endian);
  length_b = read_u32(buffer + header->offset + 20, header->big_endian);
  if (length_a < 2 || length_b < 2) {
    return false;
  }
  if (length_a > size && length_b > size) {
    return false;
  }
  if (header->unpacked_file_size < length_a &&
      header->unpacked_file_size < length_b) {
    return false;
  }

  if (header->version >= 10) {
    expected_checksum = get_pack_header_checksum(buffer + header->offset,
                                                 header->header_size - 1);
    current_checksum = buffer[header->offset + header->header_size - 1];
    header->checksum_valid = current_checksum == expected_checksum;
    if (!header->checksum_valid) {
      return false;
    }
  } else {
    header->checksum_valid = true;
  }

  header->found = true;
  return true;
}

static bool detect_any_trailing_pack_header(const uint8_t *buffer, size_t size,
                                            size_t minimum_offset,
                                            upx_pack_header_t *header) {
  if (size < 28 || minimum_offset >= size) {
    return false;
  }

  for (size_t offset = size - 4 + 1; offset-- > minimum_offset;) {
    if (memcmp(buffer + offset, k_upx_magic, 4) == 0 &&
        decode_pack_header_candidate(buffer, size, offset, header)) {
      return true;
    }
    if (offset == minimum_offset) {
      break;
    }
  }

  return false;
}

static bool detect_pe_pack_header_in_window(const uint8_t *buffer, size_t size,
                                            size_t start_offset,
                                            size_t window_size,
                                            uint8_t expected_format,
                                            upx_pack_header_t *header) {
  size_t end_offset;

  memset(header, 0, sizeof(*header));

  if (start_offset >= size) {
    return false;
  }

  end_offset = start_offset + window_size;
  if (end_offset > size) {
    end_offset = size;
  }

  for (size_t offset = start_offset;
       offset + 28 <= end_offset && offset < start_offset + 128; ++offset) {
    size_t header_size;
    uint8_t version = buffer[offset + 4];
    uint8_t format = buffer[offset + 5];
    uint32_t u_len;
    uint32_t c_len;
    uint32_t u_file_size;
    uint8_t checksum;

    if (version == 0 || version > 20 || format != expected_format) {
      continue;
    }

    header_size = get_pack_header_size(version, format);
    if (header_size < 28 || offset + header_size > end_offset) {
      continue;
    }

    u_len = read_u32(buffer + offset + 16, false);
    c_len = read_u32(buffer + offset + 20, false);
    u_file_size = read_u32(buffer + offset + 24, false);
    if (u_len < 2 || c_len < 2 || u_len < c_len || u_file_size == 0) {
      continue;
    }

    if (version >= 10) {
      checksum = get_pack_header_checksum(buffer + offset, header_size - 1);
      if (buffer[offset + header_size - 1] != checksum) {
        continue;
      }
    }

    header->found = true;
    header->big_endian = false;
    header->checksum_valid = true;
    header->offset = offset;
    header->header_size = header_size;
    header->version = version;
    header->format = format;
    header->unpacked_file_size = u_file_size;
    header->matched_magic = buffer + offset;
    header->matched_magic_is_upx =
        memcmp(buffer + offset, k_upx_magic, sizeof(k_upx_magic)) == 0;
    return true;
  }

  return false;
}

static void patch_bytes(uint8_t *buffer, size_t offset, const uint8_t *bytes,
                        size_t length) {
  memcpy(buffer + offset, bytes, length);
}

static void recompute_pack_header_checksum(uint8_t *buffer,
                                           const upx_pack_header_t *header) {
  uint8_t checksum;

  if (header->version < 10) {
    return;
  }

  checksum =
      get_pack_header_checksum(buffer + header->offset, header->header_size - 1);
  buffer[header->offset + header->header_size - 1] = checksum;
}

static bool repair_upx_elf_buffer(uint8_t **buffer_ptr, size_t *size_ptr,
                                  upx_repair_summary_t *summary,
                                  char *error_buffer,
                                  size_t error_buffer_size) {
  elf_layout_t layout;
  upx_pack_header_t pack_header;
  uint8_t *buffer = *buffer_ptr;
  size_t size = *size_ptr;
  uint8_t current_linfo_magic[4];
  uint8_t expected_pack_version;
  uint8_t expected_pack_format;
  uint32_t current_p_filesize;
  uint32_t current_p_blocksize;
  int release_major = 0;
  bool has_release_major;
  bool has_release_string;
  bool release_string_normalized = false;
  bool has_inline_loader_metadata;
  bool has_healthy_inline_metadata;
  bool found_pack_header = false;
  bool used_generic_trailing_fallback = false;

  if (!infer_elf_layout(buffer, size, &layout, error_buffer, error_buffer_size)) {
    return false;
  }

  summary->format = UPX_REPAIR_FORMAT_ELF;

  if (layout.magic_missing) {
    patch_bytes(buffer, 0, k_elf_magic, sizeof(k_elf_magic));
    summary->repaired_elf_magic = true;
  }

  memcpy(current_linfo_magic, buffer + layout.linfo_offset + 4, 4);
  expected_pack_version = buffer[layout.linfo_offset + 10];
  expected_pack_format = buffer[layout.linfo_offset + 11];
  current_p_filesize =
      read_u32(buffer + layout.pinfo_offset + 4, layout.big_endian);
  current_p_blocksize =
      read_u32(buffer + layout.pinfo_offset + 8, layout.big_endian);
  has_release_string = detect_upx_release_string(
      buffer, size, summary->upx_release_raw, sizeof(summary->upx_release_raw),
      summary->upx_release_string, sizeof(summary->upx_release_string),
      &release_string_normalized);
  if (has_release_string) {
    summary->detected_upx_release_string = true;
    summary->upx_release_string_normalized = release_string_normalized;
  }
  has_release_major = detect_upx_release_major(buffer, size, &release_major);
  if (has_release_major) {
    summary->detected_upx_release_major = true;
    summary->upx_release_major = release_major;
  }

  has_inline_loader_metadata =
      expected_pack_version != 0 && expected_pack_format != 0;
  has_healthy_inline_metadata =
      has_inline_loader_metadata &&
      memcmp(current_linfo_magic, k_upx_magic, sizeof(k_upx_magic)) == 0 &&
      current_p_filesize != 0 &&
      (has_release_major && release_major == 4
           ? current_p_blocksize != 0
           : current_p_blocksize == current_p_filesize);

  if (layout.magic_missing && has_healthy_inline_metadata) {
    found_pack_header = detect_any_trailing_pack_header(
        buffer, size, layout.phoff + (size_t)layout.phentsize * layout.phnum,
        &pack_header);
    if (found_pack_header &&
        (pack_header.version != expected_pack_version ||
         pack_header.format != expected_pack_format)) {
      found_pack_header = false;
    }
    used_generic_trailing_fallback = found_pack_header;
  }

  if (has_inline_loader_metadata) {
    found_pack_header =
        found_pack_header ||
        detect_pack_header(buffer, size, current_linfo_magic,
                           layout.pinfo_offset + 12, expected_pack_version,
                           expected_pack_format, &pack_header);
  }

  if (!found_pack_header && layout.magic_missing) {
    found_pack_header = detect_any_trailing_pack_header(
        buffer, size, layout.phoff + (size_t)layout.phentsize * layout.phnum,
        &pack_header);
    used_generic_trailing_fallback = found_pack_header;
  }

  if (!found_pack_header) {
    set_error(error_buffer, error_buffer_size,
              "could not locate a plausible trailing UPX pack header");
    return false;
  }

  summary->pack_header_version = pack_header.version;
  summary->pack_header_format = pack_header.format;
  summary->unpacked_file_size = pack_header.unpacked_file_size;

  if (has_inline_loader_metadata &&
      memcmp(buffer + layout.linfo_offset + 4, k_upx_magic, 4) != 0) {
    patch_bytes(buffer, layout.linfo_offset + 4, k_upx_magic, 4);
    summary->repaired_linfo_magic = true;
  }

  if (memcmp(buffer + pack_header.offset, k_upx_magic, 4) != 0) {
    patch_bytes(buffer, pack_header.offset, k_upx_magic, 4);
    summary->repaired_pack_header_magic = true;
  }

  if (has_inline_loader_metadata && (!has_release_major || release_major != 4) &&
      (current_p_filesize == 0 || current_p_blocksize == 0 ||
       current_p_filesize != current_p_blocksize)) {
    write_u32(buffer + layout.pinfo_offset + 4, layout.big_endian,
              pack_header.unpacked_file_size);
    write_u32(buffer + layout.pinfo_offset + 8, layout.big_endian,
              pack_header.unpacked_file_size);
    summary->repaired_p_info_sizes = true;
  }

  if (!used_generic_trailing_fallback) {
    recompute_pack_header_checksum(buffer, &pack_header);
  }

  if (!used_generic_trailing_fallback &&
      pack_header.offset + pack_header.header_size < size) {
    size_t new_size = pack_header.offset + pack_header.header_size;
    uint8_t *shrunk = realloc(buffer, new_size);

    if (shrunk == NULL && new_size != 0) {
      set_error(error_buffer, error_buffer_size,
                "out of memory while trimming overlay bytes");
      return false;
    }

    summary->removed_overlay = true;
    summary->overlay_bytes_removed = size - new_size;
    *buffer_ptr = shrunk;
    *size_ptr = new_size;
  }

  return true;
}

static bool repair_upx_pe_buffer(uint8_t **buffer_ptr, size_t *size_ptr,
                                 upx_repair_summary_t *summary,
                                 char *error_buffer,
                                 size_t error_buffer_size) {
  uint8_t *buffer = *buffer_ptr;
  size_t size = *size_ptr;
  pe_layout_t layout;
  pe_section_info_t *sections = NULL;
  upx_pack_header_t pack_header;
  uint8_t expected_format;
  bool found_pack_header = false;
  uint16_t min_sections;
  uint16_t max_sections;

  (void)size_ptr;

  if (!infer_pe_layout(buffer, size, &layout, &sections, error_buffer,
                       error_buffer_size)) {
    return false;
  }

  if (!pe_machine_to_upx_format(&layout, &expected_format)) {
    free(sections);
    set_error(error_buffer, error_buffer_size,
              "unsupported PE machine for UPX repair");
    return false;
  }

  min_sections = layout.is_efi ? 2 : 3;
  max_sections = expected_format == UPX_F_WINCE_ARM ? 4 : 3;
  if (layout.section_count < min_sections || layout.section_count > max_sections) {
    free(sections);
    set_error(error_buffer, error_buffer_size,
              "PE does not match the small UPX section layout");
    return false;
  }

  if (sections[1].raw_offset >= 64) {
    found_pack_header = detect_pe_pack_header_in_window(
        buffer, size, sections[1].raw_offset - 64, 1024, expected_format,
        &pack_header);
  }
  if (!found_pack_header && layout.section_count >= 3) {
    found_pack_header = detect_pe_pack_header_in_window(
        buffer, size, sections[2].raw_offset, 1024, expected_format,
        &pack_header);
  }
  if (!found_pack_header) {
    free(sections);
    set_error(error_buffer, error_buffer_size,
              "could not locate a plausible UPX pack header in the PE scan "
              "window");
    return false;
  }

  summary->format = UPX_REPAIR_FORMAT_PE;
  summary->pack_header_version = pack_header.version;
  summary->pack_header_format = pack_header.format;
  summary->unpacked_file_size = pack_header.unpacked_file_size;

  if (!pack_header.matched_magic_is_upx) {
    patch_bytes(buffer, pack_header.offset, k_upx_magic, sizeof(k_upx_magic));
    summary->repaired_pack_header_magic = true;
  }

  if (memcmp(buffer + sections[0].header_offset, "UPX0", 4) != 0) {
    static const uint8_t k_upx0_name[8] = {'U', 'P', 'X', '0', 0, 0, 0, 0};
    patch_bytes(buffer, sections[0].header_offset, k_upx0_name,
                sizeof(k_upx0_name));
    summary->repaired_pe_section_names = true;
    ++summary->pe_section_names_restored;
  }

  if (memcmp(buffer + sections[1].header_offset, "UPX1", 4) != 0) {
    static const uint8_t k_upx1_name[8] = {'U', 'P', 'X', '1', 0, 0, 0, 0};
    patch_bytes(buffer, sections[1].header_offset, k_upx1_name,
                sizeof(k_upx1_name));
    summary->repaired_pe_section_names = true;
    ++summary->pe_section_names_restored;
  }

  recompute_pack_header_checksum(buffer, &pack_header);
  free(sections);
  return true;
}

static bool make_temp_path(char *path_buffer, size_t path_buffer_size,
                           char *error_buffer, size_t error_buffer_size) {
  int fd;

  if (path_buffer_size < 32) {
    set_error(error_buffer, error_buffer_size, "internal buffer too small");
    return false;
  }

  snprintf(path_buffer, path_buffer_size, "/tmp/binsight-upx-XXXXXX");
  fd = mkstemp(path_buffer);
  if (fd < 0) {
    set_error(error_buffer, error_buffer_size, "mkstemp failed: %s",
              strerror(errno));
    return false;
  }

  close(fd);
  return true;
}

static bool managed_upx_candidate(const char *root, const char *version,
                                  char *path_buffer, size_t path_buffer_size) {
  int written;

  if (root == NULL || root[0] == '\0' || version == NULL ||
      version[0] == '\0') {
    return false;
  }

  written = snprintf(path_buffer, path_buffer_size, "%s/%s/upx", root, version);
  if (written < 0 || (size_t)written >= path_buffer_size) {
    return false;
  }

  return access(path_buffer, X_OK) == 0;
}

static bool find_managed_upx_version(const char *version, char *path_buffer,
                                     size_t path_buffer_size) {
  const char *env_root = getenv("BINSIGHT_UPX_DIR");
  const char *home = getenv("HOME");
  char user_root[PATH_MAX];
  int written;

  if (managed_upx_candidate(env_root, version, path_buffer, path_buffer_size)) {
    return true;
  }
  if (managed_upx_candidate("tools/upx", version, path_buffer,
                            path_buffer_size)) {
    return true;
  }

  if (home != NULL && home[0] != '\0') {
    written = snprintf(user_root, sizeof(user_root),
                       "%s/.local/share/binsight/upx", home);
    if (written >= 0 && (size_t)written < sizeof(user_root) &&
        managed_upx_candidate(user_root, version, path_buffer,
                              path_buffer_size)) {
      return true;
    }
  }

  return false;
}

static bool run_upx_fetcher(const char *version, char *error_buffer,
                            size_t error_buffer_size) {
  const char *fetcher = getenv("BINSIGHT_UPX_FETCHER");
  pid_t pid;
  int status = 0;

  if (version == NULL || version[0] == '\0') {
    set_error(error_buffer, error_buffer_size,
              "cannot auto-fetch UPX because no exact version was detected");
    return false;
  }

  if (fetcher == NULL || fetcher[0] == '\0') {
    fetcher = "tools/fetch-upx.sh";
  }

  pid = fork();
  if (pid < 0) {
    set_error(error_buffer, error_buffer_size, "fork failed: %s",
              strerror(errno));
    return false;
  }

  if (pid == 0) {
    execl(fetcher, fetcher, version, (char *)NULL);
    _exit(127);
  }

  if (waitpid(pid, &status, 0) < 0) {
    set_error(error_buffer, error_buffer_size, "waitpid failed: %s",
              strerror(errno));
    return false;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    return true;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
    set_error(error_buffer, error_buffer_size,
              "UPX fetcher '%s' was not found or could not run; set "
              "BINSIGHT_UPX_FETCHER if binsight is not running from the "
              "repository root",
              fetcher);
    return false;
  }

  set_error(error_buffer, error_buffer_size,
            "UPX fetcher '%s' failed with status %d", fetcher,
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  return false;
}

static bool resolve_upx_executable(const char *requested_path,
                                   const char *requested_version,
                                   bool auto_fetch,
                                   const upx_repair_summary_t *summary,
                                   char *path_buffer, size_t path_buffer_size,
                                   bool *uses_path_lookup,
                                   char *error_buffer,
                                   size_t error_buffer_size) {
  const char *env_path = getenv("BINSIGHT_UPX");
  const char *auto_version = NULL;

  if (uses_path_lookup != NULL) {
    *uses_path_lookup = false;
  }

  if (requested_path != NULL && requested_path[0] != '\0') {
    if (access(requested_path, X_OK) != 0) {
      set_error(error_buffer, error_buffer_size,
                "UPX executable '%s' is not executable", requested_path);
      return false;
    }
    snprintf(path_buffer, path_buffer_size, "%s", requested_path);
    return true;
  }

  if (env_path != NULL && env_path[0] != '\0') {
    if (access(env_path, X_OK) != 0) {
      set_error(error_buffer, error_buffer_size,
                "BINSIGHT_UPX '%s' is not executable", env_path);
      return false;
    }
    snprintf(path_buffer, path_buffer_size, "%s", env_path);
    return true;
  }

  if (requested_version != NULL && requested_version[0] != '\0') {
    if (!find_managed_upx_version(requested_version, path_buffer,
                                  path_buffer_size)) {
      if (auto_fetch) {
        if (!run_upx_fetcher(requested_version, error_buffer,
                             error_buffer_size)) {
          return false;
        }
        if (find_managed_upx_version(requested_version, path_buffer,
                                     path_buffer_size)) {
          return true;
        }
        set_error(error_buffer, error_buffer_size,
                  "UPX version '%s' was fetched but no managed executable was "
                  "found afterward",
                  requested_version);
        return false;
      }
      set_error(error_buffer, error_buffer_size,
                "managed UPX version '%s' was not found; run "
                "`make upx-tools UPX_VERSION=%s`, pass --upx-auto-fetch, "
                "or set BINSIGHT_UPX_DIR",
                requested_version, requested_version);
      return false;
    }
    return true;
  }

  if (summary != NULL && summary->detected_upx_release_string) {
    auto_version = summary->upx_release_string;
  }
  if (auto_version != NULL && auto_version[0] != '\0') {
    if (find_managed_upx_version(auto_version, path_buffer, path_buffer_size)) {
      return true;
    }
    if (auto_fetch) {
      if (!run_upx_fetcher(auto_version, error_buffer, error_buffer_size)) {
        return false;
      }
      if (find_managed_upx_version(auto_version, path_buffer,
                                   path_buffer_size)) {
        return true;
      }
      set_error(error_buffer, error_buffer_size,
                "UPX version '%s' was fetched but no managed executable was "
                "found afterward",
                auto_version);
      return false;
    }
  } else if (auto_fetch) {
    set_error(error_buffer, error_buffer_size,
              "cannot auto-fetch UPX because the packed file does not expose "
              "an exact UPX release string; pass --upx-version or --upx");
    return false;
  }

  snprintf(path_buffer, path_buffer_size, "upx");
  if (uses_path_lookup != NULL) {
    *uses_path_lookup = true;
  }
  return true;
}

static bool run_upx_unpack(const char *repaired_path, const char *output_path,
                           const char *upx_executable,
                           bool uses_path_lookup,
                           char *error_buffer, size_t error_buffer_size) {
  pid_t pid = fork();
  int status = 0;

  if (pid < 0) {
    set_error(error_buffer, error_buffer_size, "fork failed: %s",
              strerror(errno));
    return false;
  }

  if (pid == 0) {
    if (uses_path_lookup) {
      execlp(upx_executable, upx_executable, "-d", "-o", output_path,
             repaired_path, (char *)NULL);
    } else {
      execl(upx_executable, upx_executable, "-d", "-o", output_path,
            repaired_path, (char *)NULL);
    }
    _exit(127);
  }

  if (waitpid(pid, &status, 0) < 0) {
    set_error(error_buffer, error_buffer_size, "waitpid failed: %s",
              strerror(errno));
    return false;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    return true;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
    set_error(error_buffer, error_buffer_size,
              "UPX executable '%s' was not found or could not run",
              upx_executable);
    return false;
  }

  set_error(error_buffer, error_buffer_size,
            "external '%s -d' failed with status %d", upx_executable,
            WIFEXITED(status) ? WEXITSTATUS(status) : -1);
  return false;
}

static bool looks_like_elf_for_repair(const uint8_t *buffer, size_t size) {
  elf_layout_t layout;

  return infer_elf_layout(buffer, size, &layout, NULL, 0);
}

static bool repair_upx_file_impl(const char *input_path, const char *output_path,
                                 upx_repair_summary_t *summary,
                                 char *error_buffer,
                                 size_t error_buffer_size,
                                 upx_repair_format_t required_format) {
  uint8_t *buffer = NULL;
  size_t size = 0;
  bool ok = false;

  memset(summary, 0, sizeof(*summary));

  if (!read_file(input_path, &buffer, &size, error_buffer, error_buffer_size)) {
    return false;
  }

  if (looks_like_elf_for_repair(buffer, size)) {
    if (required_format == UPX_REPAIR_FORMAT_PE ||
        !repair_upx_elf_buffer(&buffer, &size, summary, error_buffer,
                               error_buffer_size)) {
      free(buffer);
      if (required_format == UPX_REPAIR_FORMAT_PE) {
        set_error(error_buffer, error_buffer_size,
                  "input looks like ELF, not PE");
      }
      return false;
    }
  } else if (size >= 2 && buffer[0] == 'M' && buffer[1] == 'Z') {
    if (required_format == UPX_REPAIR_FORMAT_ELF ||
        !repair_upx_pe_buffer(&buffer, &size, summary, error_buffer,
                              error_buffer_size)) {
      free(buffer);
      if (required_format == UPX_REPAIR_FORMAT_ELF) {
        set_error(error_buffer, error_buffer_size,
                  "input looks like PE, not ELF");
      }
      return false;
    }
  } else {
    free(buffer);
    set_error(error_buffer, error_buffer_size,
              "unsupported input: only UPX-packed ELF and PE files are "
              "supported");
    return false;
  }

  ok = write_file(output_path, buffer, size, error_buffer, error_buffer_size);
  free(buffer);
  return ok;
}

bool repair_upx_file(const char *input_path, const char *output_path,
                     upx_repair_summary_t *summary, char *error_buffer,
                     size_t error_buffer_size) {
  return repair_upx_file_impl(input_path, output_path, summary, error_buffer,
                              error_buffer_size, UPX_REPAIR_FORMAT_UNKNOWN);
}

bool repair_upx_elf_file(const char *input_path, const char *output_path,
                         upx_repair_summary_t *summary, char *error_buffer,
                         size_t error_buffer_size) {
  return repair_upx_file_impl(input_path, output_path, summary, error_buffer,
                              error_buffer_size, UPX_REPAIR_FORMAT_ELF);
}

bool repair_upx_pe_file(const char *input_path, const char *output_path,
                        upx_repair_summary_t *summary, char *error_buffer,
                        size_t error_buffer_size) {
  return repair_upx_file_impl(input_path, output_path, summary, error_buffer,
                              error_buffer_size, UPX_REPAIR_FORMAT_PE);
}

bool repair_and_unpack_upx_file(const char *input_path,
                                const char *output_path,
                                const char *upx_path,
                                const char *upx_version,
                                bool upx_auto_fetch,
                                upx_repair_summary_t *summary,
                                char *error_buffer,
                                size_t error_buffer_size) {
  char temp_path[PATH_MAX];
  char upx_executable[PATH_MAX];
  bool uses_path_lookup = false;
  bool ok = false;

  if (!make_temp_path(temp_path, sizeof(temp_path), error_buffer,
                      error_buffer_size)) {
    return false;
  }

  if (!repair_upx_file(input_path, temp_path, summary, error_buffer,
                       error_buffer_size)) {
    unlink(temp_path);
    return false;
  }

  if (!resolve_upx_executable(upx_path, upx_version, upx_auto_fetch, summary,
                              upx_executable, sizeof(upx_executable),
                              &uses_path_lookup, error_buffer,
                              error_buffer_size)) {
    unlink(temp_path);
    return false;
  }

  ok = run_upx_unpack(temp_path, output_path, upx_executable, uses_path_lookup,
                      error_buffer, error_buffer_size);
  unlink(temp_path);
  return ok;
}

void print_upx_repair_summary(const char *input_path, const char *output_path,
                              const upx_repair_summary_t *summary,
                              bool unpacked) {
  const char *format_name =
      summary->format == UPX_REPAIR_FORMAT_PE ? "PE" : "ELF";

  printf("UPX %s %s:\n", format_name, unpacked ? "Repair + Unpack" : "Repair");
  printf("  Input: %s\n", input_path);
  printf("  Output: %s\n", output_path);
  printf("  Pack header version: %u\n", summary->pack_header_version);
  printf("  Pack header format: %u\n", summary->pack_header_format);
  if (summary->format == UPX_REPAIR_FORMAT_ELF &&
      summary->detected_upx_release_string) {
    printf("  Detected UPX release: %s", summary->upx_release_raw);
    if (summary->upx_release_string_normalized) {
      printf(" (normalized %s)", summary->upx_release_string);
    }
    printf("\n");
  } else if (summary->format == UPX_REPAIR_FORMAT_ELF) {
    printf("  Detected UPX release: unavailable\n");
  }
  if (summary->format == UPX_REPAIR_FORMAT_ELF &&
      summary->detected_upx_release_major) {
    printf("  Detected UPX release major: %d\n", summary->upx_release_major);
  } else if (summary->format == UPX_REPAIR_FORMAT_ELF) {
    printf("  Detected UPX release major: unavailable\n");
  }
  printf("  Unpacked file size from UPX metadata: %u bytes\n",
         summary->unpacked_file_size);
  printf("  Fixes applied:\n");
  if (summary->format == UPX_REPAIR_FORMAT_ELF) {
    printf("    - ELF magic restored: %s\n",
           summary->repaired_elf_magic ? "yes" : "no");
    printf("    - l_info magic restored: %s\n",
           summary->repaired_linfo_magic ? "yes" : "no");
  }
  printf("    - PackHeader magic restored: %s\n",
         summary->repaired_pack_header_magic ? "yes" : "no");
  if (summary->format == UPX_REPAIR_FORMAT_ELF) {
    printf("    - p_info sizes restored: %s\n",
           summary->repaired_p_info_sizes ? "yes" : "no");
    printf("    - Overlay trimmed: %s", summary->removed_overlay ? "yes" : "no");
    if (summary->removed_overlay) {
      printf(" (%zu bytes)", summary->overlay_bytes_removed);
    }
    printf("\n");
  } else if (summary->format == UPX_REPAIR_FORMAT_PE) {
    printf("    - PE section names restored: %s",
           summary->repaired_pe_section_names ? "yes" : "no");
    if (summary->repaired_pe_section_names) {
      printf(" (%u sections)", summary->pe_section_names_restored);
    }
    printf("\n");
  }
}
