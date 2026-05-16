#include "sha512.h"

#ifdef __APPLE__
#include <CommonCrypto/CommonDigest.h>

void sha512_init(sha512_ctx *ctx) {
  CC_SHA512_Init((CC_SHA512_CTX *)ctx);
}

void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len) {
  CC_SHA512_Update((CC_SHA512_CTX *)ctx, data, (CC_LONG)len);
}

void sha512_final(sha512_ctx *ctx, uint8_t hash[SHA512_DIGEST_LENGTH]) {
  CC_SHA512_Final(hash, (CC_SHA512_CTX *)ctx);
}

void sha512(const uint8_t *data, size_t len, uint8_t hash[SHA512_DIGEST_LENGTH]) {
  CC_SHA512(data, (CC_LONG)len, hash);
}

#else

#include <string.h>

static const uint64_t K[80] = {
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
  0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
  0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
  0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
  0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
  0x0fc19dc68ca8cc5ULL,  0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
  0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
  0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
  0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
  0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
  0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
  0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
  0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
  0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
  0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
  0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
  0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
  0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
  0x0a637dc5a2c898a6ULL,  0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
  0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
  0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

typedef struct {
  uint8_t  buf[128];
  uint64_t state[8];
  uint64_t bitlen_hi;
  uint64_t bitlen_lo;
} sha512_internal_ctx;

static void store64_be(uint8_t *p, uint64_t v) {
  p[0] = (uint8_t)(v >> 56); p[1] = (uint8_t)(v >> 48);
  p[2] = (uint8_t)(v >> 40); p[3] = (uint8_t)(v >> 32);
  p[4] = (uint8_t)(v >> 24); p[5] = (uint8_t)(v >> 16);
  p[6] = (uint8_t)(v >> 8);  p[7] = (uint8_t)(v);
}

static uint64_t rotr(uint64_t x, unsigned int n) {
  return (x >> n) | (x << (64 - n));
}

static void sha512_transform(sha512_internal_ctx *ictx) {
  uint64_t m[80];
  uint64_t a, b, c, d, e, f, g, h, t1, t2;

  for (int i = 0; i < 16; i++) {
    int p = i * 8;
    m[i] = ((uint64_t)ictx->buf[p]     << 56) |
           ((uint64_t)ictx->buf[p + 1] << 48) |
           ((uint64_t)ictx->buf[p + 2] << 40) |
           ((uint64_t)ictx->buf[p + 3] << 32) |
           ((uint64_t)ictx->buf[p + 4] << 24) |
           ((uint64_t)ictx->buf[p + 5] << 16) |
           ((uint64_t)ictx->buf[p + 6] << 8)  |
           ((uint64_t)ictx->buf[p + 7]);
  }
  for (int i = 16; i < 80; i++) {
    uint64_t s0 = rotr(m[i - 15], 1) ^ rotr(m[i - 15], 8) ^ (m[i - 15] >> 7);
    uint64_t s1 = rotr(m[i - 2], 19) ^ rotr(m[i - 2], 61) ^ (m[i - 2] >> 6);
    m[i] = m[i - 16] + s0 + m[i - 7] + s1;
  }

  a = ictx->state[0]; b = ictx->state[1];
  c = ictx->state[2]; d = ictx->state[3];
  e = ictx->state[4]; f = ictx->state[5];
  g = ictx->state[6]; h = ictx->state[7];

  for (int i = 0; i < 80; i++) {
    uint64_t S1 = rotr(e, 14) ^ rotr(e, 18) ^ rotr(e, 41);
    uint64_t ch = (e & f) ^ ((~e) & g);
    t1 = h + S1 + ch + K[i] + m[i];
    uint64_t S0 = rotr(a, 28) ^ rotr(a, 34) ^ rotr(a, 39);
    uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
    t2 = S0 + maj;
    h = g; g = f; f = e; e = d + t1;
    d = c; c = b; b = a; a = t1 + t2;
  }

  ictx->state[0] += a; ictx->state[1] += b;
  ictx->state[2] += c; ictx->state[3] += d;
  ictx->state[4] += e; ictx->state[5] += f;
  ictx->state[6] += g; ictx->state[7] += h;
}

void sha512_init(sha512_ctx *ctx) {
  sha512_internal_ctx *ictx = (sha512_internal_ctx *)ctx;
  memset(ictx, 0, sizeof(*ictx));
  ictx->state[0] = 0x6a09e667f3bcc908ULL;
  ictx->state[1] = 0xbb67ae8584caa73bULL;
  ictx->state[2] = 0x3c6ef372fe94f82bULL;
  ictx->state[3] = 0xa54ff53a5f1d36f1ULL;
  ictx->state[4] = 0x510e527fade682d1ULL;
  ictx->state[5] = 0x9b05688c2b3e6c1fULL;
  ictx->state[6] = 0x1f83d9abfb41bd6bULL;
  ictx->state[7] = 0x5be0cd19137e2179ULL;
}

void sha512_update(sha512_ctx *ctx, const uint8_t *data, size_t len) {
  sha512_internal_ctx *ictx = (sha512_internal_ctx *)ctx;
  size_t idx = (size_t)(ictx->bitlen_lo / 8) % 128;
  ictx->bitlen_lo += (uint64_t)len * 8;
  if (ictx->bitlen_lo < (uint64_t)len * 8) ictx->bitlen_hi++;

  while (len > 0) {
    size_t space = 128 - idx;
    size_t copy = (len < space) ? len : space;
    memcpy(ictx->buf + idx, data, copy);
    idx += copy;
    data += copy;
    len -= copy;
    if (idx == 128) { sha512_transform(ictx); idx = 0; }
  }
}

void sha512_final(sha512_ctx *ctx, uint8_t hash[SHA512_DIGEST_LENGTH]) {
  sha512_internal_ctx *ictx = (sha512_internal_ctx *)ctx;
  size_t idx = (size_t)(ictx->bitlen_lo / 8) % 128;
  ictx->buf[idx++] = 0x80;
  if (idx > 112) {
    memset(ictx->buf + idx, 0, 128 - idx);
    sha512_transform(ictx);
    idx = 0;
  }
  memset(ictx->buf + idx, 0, 112 - idx);
  store64_be(ictx->buf + 112, ictx->bitlen_hi);
  store64_be(ictx->buf + 120, ictx->bitlen_lo);
  sha512_transform(ictx);
  for (int i = 0; i < 8; i++)
    store64_be(hash + i * 8, ictx->state[i]);
}

void sha512(const uint8_t *data, size_t len, uint8_t hash[SHA512_DIGEST_LENGTH]) {
  sha512_ctx ctx;
  sha512_init(&ctx);
  if (data && len > 0) sha512_update(&ctx, data, len);
  sha512_final(&ctx, hash);
}

#endif
