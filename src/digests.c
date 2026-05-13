#include "digests.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static uint32_t read_u32_le(const uint8_t *buffer) {
  return (uint32_t)buffer[0] | ((uint32_t)buffer[1] << 8) |
         ((uint32_t)buffer[2] << 16) | ((uint32_t)buffer[3] << 24);
}

static uint32_t read_u32_be(const uint8_t *buffer) {
  return ((uint32_t)buffer[0] << 24) | ((uint32_t)buffer[1] << 16) |
         ((uint32_t)buffer[2] << 8) | (uint32_t)buffer[3];
}

static void write_u32_le(uint8_t *buffer, uint32_t value) {
  buffer[0] = (uint8_t)(value & 0xffU);
  buffer[1] = (uint8_t)((value >> 8) & 0xffU);
  buffer[2] = (uint8_t)((value >> 16) & 0xffU);
  buffer[3] = (uint8_t)((value >> 24) & 0xffU);
}

static void write_u32_be(uint8_t *buffer, uint32_t value) {
  buffer[0] = (uint8_t)((value >> 24) & 0xffU);
  buffer[1] = (uint8_t)((value >> 16) & 0xffU);
  buffer[2] = (uint8_t)((value >> 8) & 0xffU);
  buffer[3] = (uint8_t)(value & 0xffU);
}

static uint32_t rotl32(uint32_t value, unsigned int count) {
  return (value << count) | (value >> (32U - count));
}

static uint32_t rotr32(uint32_t value, unsigned int count) {
  return (value >> count) | (value << (32U - count));
}

static void md5_process_block(uint32_t state[4], const uint8_t block[64]) {
  static const uint32_t shifts[64] = {
      7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22, 7,  12, 17, 22,
      5,  9,  14, 20, 5,  9,  14, 20, 5,  9,  14, 20, 5,  9,  14, 20,
      4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23, 4,  11, 16, 23,
      6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21, 6,  10, 15, 21,
  };
  static const uint32_t table[64] = {
      0xd76aa478U, 0xe8c7b756U, 0x242070dbU, 0xc1bdceeeU, 0xf57c0fafU,
      0x4787c62aU, 0xa8304613U, 0xfd469501U, 0x698098d8U, 0x8b44f7afU,
      0xffff5bb1U, 0x895cd7beU, 0x6b901122U, 0xfd987193U, 0xa679438eU,
      0x49b40821U, 0xf61e2562U, 0xc040b340U, 0x265e5a51U, 0xe9b6c7aaU,
      0xd62f105dU, 0x02441453U, 0xd8a1e681U, 0xe7d3fbc8U, 0x21e1cde6U,
      0xc33707d6U, 0xf4d50d87U, 0x455a14edU, 0xa9e3e905U, 0xfcefa3f8U,
      0x676f02d9U, 0x8d2a4c8aU, 0xfffa3942U, 0x8771f681U, 0x6d9d6122U,
      0xfde5380cU, 0xa4beea44U, 0x4bdecfa9U, 0xf6bb4b60U, 0xbebfbc70U,
      0x289b7ec6U, 0xeaa127faU, 0xd4ef3085U, 0x04881d05U, 0xd9d4d039U,
      0xe6db99e5U, 0x1fa27cf8U, 0xc4ac5665U, 0xf4292244U, 0x432aff97U,
      0xab9423a7U, 0xfc93a039U, 0x655b59c3U, 0x8f0ccc92U, 0xffeff47dU,
      0x85845dd1U, 0x6fa87e4fU, 0xfe2ce6e0U, 0xa3014314U, 0x4e0811a1U,
      0xf7537e82U, 0xbd3af235U, 0x2ad7d2bbU, 0xeb86d391U,
  };
  uint32_t words[16];
  uint32_t a = state[0];
  uint32_t b = state[1];
  uint32_t c = state[2];
  uint32_t d = state[3];

  for (size_t index = 0; index < 16; ++index) {
    words[index] = read_u32_le(block + index * 4);
  }

  for (size_t index = 0; index < 64; ++index) {
    uint32_t f;
    size_t g;
    uint32_t tmp;

    if (index < 16) {
      f = (b & c) | (~b & d);
      g = index;
    } else if (index < 32) {
      f = (d & b) | (~d & c);
      g = (5 * index + 1) % 16;
    } else if (index < 48) {
      f = b ^ c ^ d;
      g = (3 * index + 5) % 16;
    } else {
      f = c ^ (b | ~d);
      g = (7 * index) % 16;
    }

    tmp = d;
    d = c;
    c = b;
    b = b + rotl32(a + f + table[index] + words[g], shifts[index]);
    a = tmp;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
}

void binsight_md5(const uint8_t *data, size_t size, uint8_t out[16]) {
  uint32_t state[4] = {
      0x67452301U,
      0xefcdab89U,
      0x98badcfeU,
      0x10325476U,
  };
  uint8_t tail[128];
  size_t offset = 0;
  size_t tail_size;
  uint64_t bit_size = (uint64_t)size * 8U;

  while (offset + 64 <= size) {
    md5_process_block(state, data + offset);
    offset += 64;
  }

  tail_size = size - offset;
  memset(tail, 0, sizeof(tail));
  if (tail_size != 0) {
    memcpy(tail, data + offset, tail_size);
  }
  tail[tail_size] = 0x80U;

  if (tail_size >= 56) {
    write_u32_le(tail + 120, (uint32_t)(bit_size & 0xffffffffU));
    write_u32_le(tail + 124, (uint32_t)(bit_size >> 32));
    md5_process_block(state, tail);
    md5_process_block(state, tail + 64);
  } else {
    write_u32_le(tail + 56, (uint32_t)(bit_size & 0xffffffffU));
    write_u32_le(tail + 60, (uint32_t)(bit_size >> 32));
    md5_process_block(state, tail);
  }

  for (size_t index = 0; index < 4; ++index) {
    write_u32_le(out + index * 4, state[index]);
  }
}

static void sha256_process_block(uint32_t state[8], const uint8_t block[64]) {
  static const uint32_t table[64] = {
      0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU,
      0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U,
      0x243185beU, 0x550c7dc3U, 0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U,
      0xc19bf174U, 0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
      0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU, 0x983e5152U,
      0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
      0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU,
      0x53380d13U, 0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
      0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U, 0xd192e819U,
      0xd6990624U, 0xf40e3585U, 0x106aa070U, 0x19a4c116U, 0x1e376c08U,
      0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU,
      0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
      0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U,
  };
  uint32_t words[64];
  uint32_t a = state[0];
  uint32_t b = state[1];
  uint32_t c = state[2];
  uint32_t d = state[3];
  uint32_t e = state[4];
  uint32_t f = state[5];
  uint32_t g = state[6];
  uint32_t h = state[7];

  for (size_t index = 0; index < 16; ++index) {
    words[index] = read_u32_be(block + index * 4);
  }

  for (size_t index = 16; index < 64; ++index) {
    uint32_t s0 = rotr32(words[index - 15], 7) ^
                  rotr32(words[index - 15], 18) ^
                  (words[index - 15] >> 3);
    uint32_t s1 = rotr32(words[index - 2], 17) ^
                  rotr32(words[index - 2], 19) ^
                  (words[index - 2] >> 10);
    words[index] = words[index - 16] + s0 + words[index - 7] + s1;
  }

  for (size_t index = 0; index < 64; ++index) {
    uint32_t sum1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t choice = (e & f) ^ (~e & g);
    uint32_t temp1 = h + sum1 + choice + table[index] + words[index];
    uint32_t sum0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = sum0 + majority;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

void binsight_sha256(const uint8_t *data, size_t size, uint8_t out[32]) {
  uint32_t state[8] = {
      0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
      0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U,
  };
  uint8_t tail[128];
  size_t offset = 0;
  size_t tail_size;
  uint64_t bit_size = (uint64_t)size * 8U;

  while (offset + 64 <= size) {
    sha256_process_block(state, data + offset);
    offset += 64;
  }

  tail_size = size - offset;
  memset(tail, 0, sizeof(tail));
  if (tail_size != 0) {
    memcpy(tail, data + offset, tail_size);
  }
  tail[tail_size] = 0x80U;

  if (tail_size >= 56) {
    write_u32_be(tail + 120, (uint32_t)(bit_size >> 32));
    write_u32_be(tail + 124, (uint32_t)(bit_size & 0xffffffffU));
    sha256_process_block(state, tail);
    sha256_process_block(state, tail + 64);
  } else {
    write_u32_be(tail + 56, (uint32_t)(bit_size >> 32));
    write_u32_be(tail + 60, (uint32_t)(bit_size & 0xffffffffU));
    sha256_process_block(state, tail);
  }

  for (size_t index = 0; index < 8; ++index) {
    write_u32_be(out + index * 4, state[index]);
  }
}

void binsight_digest_hex(const uint8_t *digest, size_t digest_size, char *buffer,
                         size_t buffer_size) {
  static const char hex_digits[] = "0123456789abcdef";
  size_t required_size = digest_size * 2 + 1;

  if (buffer == NULL || buffer_size == 0) {
    return;
  }

  if (required_size > buffer_size) {
    buffer[0] = '\0';
    return;
  }

  for (size_t index = 0; index < digest_size; ++index) {
    buffer[index * 2] = hex_digits[digest[index] >> 4];
    buffer[index * 2 + 1] = hex_digits[digest[index] & 0x0fU];
  }
  buffer[digest_size * 2] = '\0';
}
