#ifndef BINSIGHT_NATIVE_HEADERS_H
#define BINSIGHT_NATIVE_HEADERS_H

#include <stdbool.h>
#include <stddef.h>

bool print_native_header_details(const char *path, char *error_buffer,
                                 size_t error_buffer_size);

#endif
