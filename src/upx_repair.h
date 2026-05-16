#ifndef BINSIGHT_UPX_REPAIR_H
#define BINSIGHT_UPX_REPAIR_H

#include <stdbool.h>
#include <stddef.h>

typedef enum {
  UPX_REPAIR_FORMAT_UNKNOWN = 0,
  UPX_REPAIR_FORMAT_ELF,
  UPX_REPAIR_FORMAT_PE,
} upx_repair_format_t;

typedef struct {
  upx_repair_format_t format;
  bool repaired_elf_magic;
  bool repaired_linfo_magic;
  bool repaired_pack_header_magic;
  bool repaired_p_info_sizes;
  bool repaired_pe_section_names;
  unsigned pe_section_names_restored;
  bool removed_overlay;
  size_t overlay_bytes_removed;
  bool detected_upx_release_major;
  int upx_release_major;
  bool detected_upx_release_string;
  bool upx_release_string_normalized;
  char upx_release_raw[32];
  char upx_release_string[32];
  unsigned pack_header_version;
  unsigned pack_header_format;
  unsigned unpacked_file_size;
} upx_repair_summary_t;

bool repair_upx_file(const char *input_path, const char *output_path,
                     upx_repair_summary_t *summary, char *error_buffer,
                     size_t error_buffer_size);

bool repair_upx_elf_file(const char *input_path, const char *output_path,
                         upx_repair_summary_t *summary, char *error_buffer,
                         size_t error_buffer_size);

bool repair_upx_pe_file(const char *input_path, const char *output_path,
                        upx_repair_summary_t *summary, char *error_buffer,
                        size_t error_buffer_size);

bool repair_and_unpack_upx_file(const char *input_path, const char *output_path,
                                const char *upx_path,
                                const char *upx_version,
                                bool upx_auto_fetch,
                                upx_repair_summary_t *summary,
                                char *error_buffer,
                                size_t error_buffer_size);

void print_upx_repair_summary(const char *input_path, const char *output_path,
                              const upx_repair_summary_t *summary,
                              bool unpacked);

#endif
