#include "ripemd160.h"
#include <string.h>

typedef struct {
  uint8_t  buf[64];
  uint32_t state[5];
  uint64_t bitlen;
} ripemd160_ctx_internal;

static_assert(sizeof(ripemd160_ctx) >= sizeof(ripemd160_ctx_internal),
               "ripemd160_ctx too small");

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static const uint32_t KL[5] = {
  0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e
};

static const uint32_t KR[5] = {
  0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000
};

static const int SL[80] = {
  11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
  7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
  11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
  11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
  9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
};

static const int SR[80] = {
  8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
  9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
  9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
  15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
  8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
};

static const int RL[80] = {
  0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
  7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
  3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
  1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
  4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
};

static const int RR[80] = {
  5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
  6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
  15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
  8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
  12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
};

static uint32_t F(uint32_t x, uint32_t y, uint32_t z, int j) {
  if (j < 16) return x ^ y ^ z;
  if (j < 32) return (x & y) | (~x & z);
  if (j < 48) return (x | ~y) ^ z;
  if (j < 64) return (x & z) | (y & ~z);
  return x ^ (y | ~z);
}

static void ripemd160_transform(uint32_t state[5], const uint8_t block[64]) {
  uint32_t X[16];
  uint32_t AL = state[0], BL = state[1], CL = state[2], DL = state[3], EL = state[4];
  uint32_t AR = state[0], BR = state[1], CR = state[2], DR = state[3], ER = state[4];
  uint32_t T;

  for (int i = 0; i < 16; i++)
    X[i] = ((uint32_t)block[i*4]) | ((uint32_t)block[i*4+1] << 8) |
           ((uint32_t)block[i*4+2] << 16) | ((uint32_t)block[i*4+3] << 24);

  for (int j = 0; j < 80; j++) {
    int round = j / 16;
    T = ROL32(AL + F(BL, CL, DL, j) + X[RL[j]] + KL[round], SL[j]) + EL;
    AL = EL; EL = DL; DL = ROL32(CL, 10); CL = BL; BL = T;

    T = ROL32(AR + F(BR, CR, DR, 79 - j) + X[RR[j]] + KR[round], SR[j]) + ER;
    AR = ER; ER = DR; DR = ROL32(CR, 10); CR = BR; BR = T;
  }

  T = state[1] + CL + DR;
  state[1] = state[2] + DL + ER;
  state[2] = state[3] + EL + AR;
  state[3] = state[4] + AL + BR;
  state[4] = state[0] + BL + CR;
  state[0] = T;
}

void ripemd160_init(ripemd160_ctx *ctx) {
  ripemd160_ctx_internal *c = (ripemd160_ctx_internal *)ctx;
  c->state[0] = 0x67452301;
  c->state[1] = 0xefcdab89;
  c->state[2] = 0x98badcfe;
  c->state[3] = 0x10325476;
  c->state[4] = 0xc3d2e1f0;
  c->bitlen = 0;
}

void ripemd160_update(ripemd160_ctx *ctx, const uint8_t *data, size_t len) {
  ripemd160_ctx_internal *c = (ripemd160_ctx_internal *)ctx;
  size_t offset = (size_t)(c->bitlen >> 3) & 63;

  c->bitlen += (uint64_t)len << 3;

  if (offset > 0) {
    size_t fill = 64 - offset;
    if (len < fill) {
      memcpy(c->buf + offset, data, len);
      return;
    }
    memcpy(c->buf + offset, data, fill);
    ripemd160_transform(c->state, c->buf);
    data += fill;
    len -= fill;
  }

  while (len >= 64) {
    ripemd160_transform(c->state, data);
    data += 64;
    len -= 64;
  }

  if (len > 0)
    memcpy(c->buf, data, len);
}

void ripemd160_final(ripemd160_ctx *ctx, uint8_t hash[RIPEMD160_DIGEST_LENGTH]) {
  ripemd160_ctx_internal *c = (ripemd160_ctx_internal *)ctx;
  size_t offset = (size_t)(c->bitlen >> 3) & 63;

  c->buf[offset++] = 0x80;
  if (offset > 56) {
    memset(c->buf + offset, 0, 64 - offset);
    ripemd160_transform(c->state, c->buf);
    offset = 0;
  }
  memset(c->buf + offset, 0, 56 - offset);

  for (int i = 0; i < 8; i++)
    c->buf[56 + i] = (uint8_t)(c->bitlen >> (i * 8));

  ripemd160_transform(c->state, c->buf);

  for (int i = 0; i < 5; i++) {
    hash[i*4]     = (uint8_t)(c->state[i]);
    hash[i*4 + 1] = (uint8_t)(c->state[i] >> 8);
    hash[i*4 + 2] = (uint8_t)(c->state[i] >> 16);
    hash[i*4 + 3] = (uint8_t)(c->state[i] >> 24);
  }
}

void ripemd160(const uint8_t *data, size_t len, uint8_t hash[RIPEMD160_DIGEST_LENGTH]) {
  ripemd160_ctx ctx;
  ripemd160_init(&ctx);
  ripemd160_update(&ctx, data, len);
  ripemd160_final(&ctx, hash);
}
