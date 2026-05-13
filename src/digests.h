#ifndef BINSIGHT_DIGESTS_H
#define BINSIGHT_DIGESTS_H

#include <stddef.h>
#include <stdint.h>

void binsight_md5(const uint8_t *data, size_t size, uint8_t out[16]);
void binsight_sha256(const uint8_t *data, size_t size, uint8_t out[32]);
void binsight_digest_hex(const uint8_t *digest, size_t digest_size, char *buffer,
                         size_t buffer_size);

#endif
