#include "bip32.h"
#include "hmac_sha512.h"
#include "se051_hal.h"
#include <string.h>

static const char BIP32_SEED_KEY[] = "Bitcoin seed";

static void secure_zero(void *buf, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)buf;
  while (len--) *p++ = 0;
}

// ─── 256-bit & 512-bit integers ──────────────────────────────────────────

typedef struct { uint64_t d[4]; } u256;
typedef struct { uint64_t d[8]; } u512;

// ─── u256 helpers ────────────────────────────────────────────────────────

static int u256_cmp64(const uint64_t *a, const uint64_t *b) {
  for (int i = 3; i >= 0; i--) {
    if (a[i] > b[i]) return 1;
    if (a[i] < b[i]) return -1;
  }
  return 0;
}

static bool u256_gte64(const uint64_t *a, const uint64_t *b) { return u256_cmp64(a, b) >= 0; }
static bool u256_is_zero64(const uint64_t *a) { return a[0]==0 && a[1]==0 && a[2]==0 && a[3]==0; }
static bool u256_is_one64(const uint64_t *a) { return a[0]==1 && a[1]==0 && a[2]==0 && a[3]==0; }

static void u256_sub64(uint64_t *r, const uint64_t *a, const uint64_t *b) {
  uint64_t borrow = 0;
  for (int i = 0; i < 4; i++) {
    uint64_t diff = a[i];
    uint64_t next_borrow = 0;
    diff -= borrow;
    if (a[i] < borrow) next_borrow = 1;
    uint64_t after = diff;
    after -= b[i];
    if (after > diff) next_borrow = 1;
    r[i] = after;
    borrow = next_borrow;
  }
}

static void u256_add64(uint64_t *r, const uint64_t *a, const uint64_t *b) {
  uint64_t carry = 0;
  for (int i = 0; i < 4; i++) {
    uint64_t s = a[i];
    uint64_t next_carry = 0;
    s += b[i];
    if (s < a[i]) next_carry = 1;
    if (carry) {
      uint64_t after = s + 1;
      if (after == 0) next_carry = 1;
      s = after;
    }
    r[i] = s;
    carry = next_carry;
  }
}

static void u256_set64(uint64_t *r, const uint64_t *a) {
  r[0]=a[0]; r[1]=a[1]; r[2]=a[2]; r[3]=a[3];
}

static void u256_set_uint64(uint64_t *r, uint64_t v) {
  r[0]=v; r[1]=0; r[2]=0; r[3]=0;
}

static void u256_from_be(uint64_t *out, const uint8_t b[32]) {
  for (int i = 0; i < 4; i++) {
    uint64_t v = 0;
    int base = 24 - i * 8;
    for (int j = 0; j < 8; j++) v = (v << 8) | b[base + j];
    out[i] = v;
  }
}

static void u256_to_be(const uint64_t *a, uint8_t b[32]) {
  for (int i = 0; i < 4; i++) {
    uint64_t v = a[i];
    int base = 24 - i * 8;
    for (int j = 7; j >= 0; j--) { b[base + j] = (uint8_t)(v & 0xFF); v >>= 8; }
  }
}

// Portable 64x64 → 128 multiply (no __uint128_t on 32-bit Xtensa)
static void mul64x64(uint64_t a, uint64_t b, uint64_t *lo, uint64_t *hi) {
  uint64_t al = (uint32_t)a;
  uint64_t ah = a >> 32;
  uint64_t bl = (uint32_t)b;
  uint64_t bh = b >> 32;
  uint64_t p0 = al * bl;
  uint64_t p1 = ah * bl;
  uint64_t p2 = al * bh;
  uint64_t p3 = ah * bh;
  uint64_t mid = p1 + p2;
  uint64_t carry = (mid < p1);
  uint64_t mid_lo = mid << 32;
  uint64_t mid_hi = (mid >> 32) | (carry << 32);
  *lo = p0 + mid_lo;
  *hi = p3 + mid_hi + ((*lo < p0) ? 1 : 0);
}

// 256x256 → 512 multiplication
static void u512_mul(uint64_t r[8], const uint64_t a[4], const uint64_t b[4]) {
  memset(r, 0, 64);
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      uint64_t lo, hi;
      mul64x64(a[i], b[j], &lo, &hi);
      int k = i + j;
      lo += r[k];
      hi += (lo < r[k]) ? 1 : 0;
      r[k] = lo;
      k++;
      while (hi) {
        uint64_t s = r[k] + hi;
        hi = (s < r[k]) ? 1 : 0;
        r[k] = s;
        k++;
      }
    }
  }
}

// ─── secp256k1 fast modular reduction ───────────────────────────────────
//
// p = 2^256 - 2^32 - 977 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
//
// For c = a * b (512 bits): c = c0 + c1 * 2^256
// Since 2^256 ≡ 2^32 + 977 (mod p): c ≡ c0 + c1*(2^32+977) (mod p)
// The result may need one more reduction pass.

static const uint64_t SECP_P[4] = {
  0xFFFFFFFEFFFFFC2FULL, 0xFFFFFFFFFFFFFFFFULL,
  0xFFFFFFFFFFFFFFFFULL, 0xFFFFFFFFFFFFFFFFULL
};
static const uint64_t SECP_N[4] = {
  0xBFD25E8CD0364141ULL, 0xBAAEDCE6AF48A03BULL,
  0xFFFFFFFFFFFFFFFEULL, 0xFFFFFFFFFFFFFFFFULL
};

static void secp_reduce(uint64_t r[4], const uint64_t a[8]) {
  uint64_t sum8[8];
  memset(sum8, 0, sizeof(sum8));

  // sum8 = c0 + c1*2^32 + c1*977

  // Step 1: sum8 = c0 (low 256 bits)
  u256_set64(sum8, a);

  // Step 2: add c1 << 32
  // c1 = a[4..7], up to 256 bits. c1 << 32 is up to 288 bits.
  // The low 256 bits: c1_words shifted left by 32 with carries between words.
  // The overflow (top 32 bits of a[7]) goes to sum8[4].
  {
    uint64_t carry = a[7] >> 32;  // bits that overflow past word 3
    uint64_t w3 = (a[6] >> 32) | (a[7] << 32);
    uint64_t w2 = (a[5] >> 32) | (a[6] << 32);
    uint64_t w1 = (a[4] >> 32) | (a[5] << 32);
    uint64_t w0 = a[4] << 32;

    // Add w0..w3 to sum8[0..3] with proper multi-precision carry
    {
      uint64_t carry_acc = 0;
      for (int i = 0; i < 4; i++) {
        uint64_t addend = (i==0) ? w0 : (i==1) ? w1 : (i==2) ? w2 : w3;
        uint64_t a = sum8[i];
        uint64_t r = a + carry_acc;
        carry_acc = (r < a) ? 1 : 0;
        r += addend;
        if (r < addend) carry_acc++;
        sum8[i] = r;
      }
      sum8[4] += carry_acc + carry;
    }
  }

  // Step 3: add c1 * 977
  for (int i = 0; i < 4; i++) {
    uint64_t lo, hi;
    mul64x64(a[4 + i], 977ULL, &lo, &hi);
    int k = i;
    lo += sum8[k];
    hi += (lo < sum8[k]) ? 1 : 0;
    sum8[k] = lo;
    k++;
    while (hi) {
      uint64_t s = sum8[k] + hi;
      hi = (s < sum8[k]) ? 1 : 0;
      sum8[k] = s;
      k++;
    }
  }

  // If sum8[4..7] non-zero, do second reduction pass
  if (sum8[4] || sum8[5] || sum8[6] || sum8[7]) {
    uint64_t r2[8];
    memset(r2, 0, sizeof(r2));
    u256_set64(r2, sum8);

    // Add high word * 2^32
    {
      uint64_t carry = sum8[7] >> 32;
      uint64_t w3 = (sum8[6] >> 32) | (sum8[7] << 32);
      uint64_t w2 = (sum8[5] >> 32) | (sum8[6] << 32);
      uint64_t w1 = (sum8[4] >> 32) | (sum8[5] << 32);
      uint64_t w0 = sum8[4] << 32;

      // Add w0..w3 to r2[0..3] with proper carry
      {
        uint64_t carry_acc = 0;
        for (int i = 0; i < 4; i++) {
          uint64_t addend = (i==0) ? w0 : (i==1) ? w1 : (i==2) ? w2 : w3;
          uint64_t a = r2[i];
          uint64_t r = a + carry_acc;
          carry_acc = (r < a) ? 1 : 0;
          r += addend;
          if (r < addend) carry_acc++;
          r2[i] = r;
        }
        r2[4] += carry_acc + carry;
      }
    }

    // Add high word * 977
    for (int i = 0; i < 4 && (i + 4) < 8; i++) {
      uint64_t lo, hi;
      mul64x64(sum8[4 + i], 977ULL, &lo, &hi);
      int k = i;
      lo += r2[k];
      hi += (lo < r2[k]) ? 1 : 0;
      r2[k] = lo;
      k++;
      while (hi) {
        uint64_t s = r2[k] + hi;
        hi = (s < r2[k]) ? 1 : 0;
        r2[k] = s;
        k++;
      }
    }

    // After second pass, result should be < 2p
    u256_set64(r, r2);
    while (u256_gte64(r, SECP_P)) {
      uint64_t tmp[4];
      u256_sub64(tmp, r, SECP_P);
      u256_set64(r, tmp);
    }
  } else {
    // Result fits in 256 bits
    u256_set64(r, sum8);
    while (u256_gte64(r, SECP_P)) {
      uint64_t tmp[4];
      u256_sub64(tmp, r, SECP_P);
      u256_set64(r, tmp);
    }
  }
}

// Generic reduction for N (group order, no nice structure):
// After add/sub, result < 2N, so one conditional subtract suffices.
// After mul, use fast reduction via high-half estimate.

static void secp_mod_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
  uint64_t prod[8];
  u512_mul(prod, a, b);
  secp_reduce(r, prod);
}

static void secp_mod_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
  uint64_t sum[4];
  u256_add64(sum, a, b);
  if (u256_gte64(sum, SECP_P)) {
    u256_sub64(r, sum, SECP_P);
  } else {
    u256_set64(r, sum);
  }
}

static void secp_mod_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
  if (u256_gte64(a, b)) {
    u256_sub64(r, a, b);
  } else {
    // r = a - b + p = a + (p - b)
    // If a + (p-b) >= 2^256, we lose the carry.
    // Since p = 2^256 - (2^32+977):
    //   a + p - b = 2^256 + (a - (2^32+977) - b) when a >= (2^32+977) + b
    // But instead of detecting carry, compute directly:
    //   r = (a - b) + p, doing a - b underflow-corrected
    uint64_t diff[4], tmp[4];
    u256_sub64(diff, b, a);           // diff = b - a (> 0)
    u256_sub64(tmp, SECP_P, diff);    // tmp = p - (b - a) = p - b + a = (a - b) + p
    // Since diff < p (because b - a < p):
    //   p - diff < p, so no wrap needed
    u256_set64(r, tmp);
  }
}

static void secp_mod_inv(uint64_t r[4], const uint64_t a[4]) {
  uint64_t two[4] = {2,0,0,0};
  uint64_t exp[4];
  u256_sub64(exp, SECP_P, two);

  uint64_t base[4], res[4];
  u256_set64(base, a);
  u256_set_uint64(res, 1);

  for (int w = 0; w < 4; w++) {
    uint64_t bits = exp[w];
    for (int b = 0; b < 64; b++) {
      if (bits & 1) secp_mod_mul(res, res, base);
      bits >>= 1;
      secp_mod_mul(base, base, base);
    }
  }
  u256_set64(r, res);
}

// Modulo N (group order) operations
// For add/sub: simple conditional. For mul: use N-reduction.

static void n_mod_add(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
  uint64_t sum[4];
  u256_add64(sum, a, b);
  if (u256_gte64(sum, SECP_N)) {
    u256_sub64(r, sum, SECP_N);
  } else {
    u256_set64(r, sum);
  }
}

static void n_mod_sub(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
  if (u256_gte64(a, b)) {
    u256_sub64(r, a, b);
  } else {
    // r = a - b + N = N - (b - a)
    uint64_t diff[4], tmp[4];
    u256_sub64(diff, b, a);
    u256_sub64(tmp, SECP_N, diff);
    u256_set64(r, tmp);
  }
}

static void n_mod_mul(uint64_t r[4], const uint64_t a[4], const uint64_t b[4]) {
  uint64_t prod[8];
  u512_mul(prod, a, b);

  // Use high 4 words as estimate of quotient, then reduce
  // q_est ≈ floor(prod / N), then r = prod - q_est * N
  // This is approximate but good enough because q_est is close to true q
  uint64_t q_est[8];
  memset(q_est, 0, sizeof(q_est));
  for (int i = 0; i < 4; i++) q_est[i] = prod[i + 4];

  // r1 = prod - q_est * N (low 256 bits matter)
  uint64_t qn_prod[8];
  memset(qn_prod, 0, sizeof(qn_prod));
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      uint64_t lo, hi;
      mul64x64(q_est[i], SECP_N[j], &lo, &hi);
      int k2 = i + j;
      lo += qn_prod[k2];
      hi += (lo < qn_prod[k2]) ? 1 : 0;
      qn_prod[k2] = lo;
      k2++;
      while (hi) {
        uint64_t s = qn_prod[k2] + hi;
        hi = (s < qn_prod[k2]) ? 1 : 0;
        qn_prod[k2] = s;
        k2++;
      }
    }
  }

  // r = prod[0..3] - qn_prod[0..3]
  uint64_t r_n[4];
  if (u256_gte64(prod, qn_prod)) {
    u256_sub64(r_n, prod, qn_prod);
  } else {
    // prod + N - qn_prod[0..3] (since N is close to 2^256)
    uint64_t tmp[4];
    u256_add64(tmp, prod, SECP_N);
    u256_sub64(r_n, tmp, qn_prod);
  }

  // Subtract N until < N
  while (u256_gte64(r_n, SECP_N)) {
    uint64_t tmp[4];
    u256_sub64(tmp, r_n, SECP_N);
    u256_set64(r_n, tmp);
  }

  u256_set64(r, r_n);
}

// ─── EC Point operations (secp256k1 affine) ──────────────────────────────

typedef struct { uint64_t x[4], y[4]; bool inf; } ec_pt;

static void ec_copy(ec_pt *d, const ec_pt *s) { *d = *s; }

static void ec_set(ec_pt *pt, const uint64_t x[4], const uint64_t y[4]) {
  u256_set64(pt->x, x); u256_set64(pt->y, y); pt->inf = false;
}

static void ec_double(ec_pt *r, const ec_pt *p) {
  if (p->inf || u256_is_zero64(p->y)) { r->inf = true; return; }

  uint64_t px[4], py[4];
  u256_set64(px, p->x);
  u256_set64(py, p->y);

  // s = 3x^2 / 2y mod P
  uint64_t x2[4], three_x2[4], two_y[4], two_y_inv[4], s[4];
  secp_mod_mul(x2, px, px);
  uint64_t three[4] = {3, 0, 0, 0};
  secp_mod_mul(three_x2, x2, three);
  secp_mod_add(two_y, py, py);
  secp_mod_inv(two_y_inv, two_y);
  secp_mod_mul(s, three_x2, two_y_inv);

  // xr = s^2 - 2x
  uint64_t s2[4], two_x[4];
  secp_mod_mul(s2, s, s);
  secp_mod_add(two_x, px, px);
  secp_mod_sub(r->x, s2, two_x);

  // yr = s(x - xr) - y
  uint64_t xmxr[4], sxmxr[4];
  secp_mod_sub(xmxr, px, r->x);
  secp_mod_mul(sxmxr, s, xmxr);
  secp_mod_sub(r->y, sxmxr, py);

  r->inf = false;
}

static void ec_add(ec_pt *r, const ec_pt *a, const ec_pt *b) {
  if (a->inf) { *r = *b; return; }
  if (b->inf) { *r = *a; return; }
  if (u256_cmp64(a->x, b->x) == 0) {
    if (u256_cmp64(a->y, b->y) == 0) { ec_double(r, a); return; }
    r->inf = true; return;
  }

  uint64_t ax[4], ay[4], bx[4], by[4];
  u256_set64(ax, a->x);
  u256_set64(ay, a->y);
  u256_set64(bx, b->x);
  u256_set64(by, b->y);

  // s = (y2 - y1) / (x2 - x1) mod P
  uint64_t num[4], den[4], den_inv[4], s[4];
  secp_mod_sub(num, by, ay);
  secp_mod_sub(den, bx, ax);
  secp_mod_inv(den_inv, den);
  secp_mod_mul(s, num, den_inv);

  // xr = s^2 - x1 - x2
  uint64_t s2[4];
  secp_mod_mul(s2, s, s);
  secp_mod_sub(r->x, s2, ax);
  secp_mod_sub(r->x, r->x, bx);

  // yr = s(x1 - xr) - y1
  uint64_t xmxr[4], sxmxr[4];
  secp_mod_sub(xmxr, ax, r->x);
  secp_mod_mul(sxmxr, s, xmxr);
  secp_mod_sub(r->y, sxmxr, ay);

  r->inf = false;
}

static void ec_scalar_mult_G(ec_pt *r, const uint64_t k[4]) {
  r->inf = true;
  uint64_t gx[4] = {0x59F2815B16F81798ULL, 0x029BFCDB2DCE28D9ULL,
                    0x55A06295CE870B07ULL, 0x79BE667EF9DCBBACULL};
  uint64_t gy[4] = {0x9C47D08FFB10D4B8ULL, 0xFD17B448A6855419ULL,
                    0x5DA4FBFC0E1108A8ULL, 0x483ADA7726A3C465ULL};

  ec_pt addend;
  ec_set(&addend, gx, gy);

  for (int w = 0; w < 4; w++) {
    uint64_t bits = k[w];
    for (int b = 0; b < 64; b++) {
      if (bits & 1) ec_add(r, r, &addend);
      bits >>= 1;
      ec_double(&addend, &addend);
    }
  }
}

static void ec_to_pubkey(const ec_pt *p, uint8_t pk[33]) {
  pk[0] = (p->y[0] & 1) ? 0x03 : 0x02;
  u256_to_be(p->x, pk + 1);
}

static bool pubkey_to_ec(const uint8_t pk[33], ec_pt *p) {
  if (pk[0] != 0x02 && pk[0] != 0x03) return false;
  u256_from_be(p->x, pk + 1);
  bool want_odd = (pk[0] == 0x03);

  // y^2 = x^3 + 7 mod P
  uint64_t x3[4], rhs[4];
  secp_mod_mul(x3, p->x, p->x);
  secp_mod_mul(x3, x3, p->x);
  uint64_t seven[4] = {7, 0, 0, 0};
  secp_mod_add(rhs, x3, seven);

  // y = rhs^((P+1)/4) mod P  (since P ≡ 3 mod 4)
  uint64_t one[4] = {1,0,0,0};
  uint64_t p1[4];
  u256_add64(p1, SECP_P, one);
  // exp = (P+1)/4
  uint64_t exp[4];
  {
    uint64_t carry = 0;
    for (int i = 3; i >= 0; i--) {
      uint64_t cur = p1[i];
      exp[i] = (cur >> 2) | (carry << 62);
      carry = cur & 3;
    }
  }

  uint64_t base[4], res[4];
  u256_set64(base, rhs);
  u256_set_uint64(res, 1);

  for (int w = 0; w < 4; w++) {
    uint64_t bits = exp[w];
    for (int b = 0; b < 64; b++) {
      if (bits & 1) secp_mod_mul(res, res, base);
      bits >>= 1;
      secp_mod_mul(base, base, base);
    }
  }

  bool is_odd = (res[0] & 1);
  if (is_odd != want_odd) {
    uint64_t neg_y[4];
    u256_sub64(neg_y, SECP_P, res);
    u256_set64(p->y, neg_y);
  } else {
    u256_set64(p->y, res);
  }
  p->inf = false;
  return true;
}

// ─── BIP32 derivation ────────────────────────────────────────────────────

bool hd_derive_master_from_seed(const uint8_t *seed, size_t seed_len,
                                uint8_t master_key[BIP32_KEY_LEN],
                                uint8_t chain_code[BIP32_CHAIN_LEN]) {
  if (!seed || !master_key || !chain_code) return false;
  uint8_t I[HMAC_SHA512_OUTPUT_SIZE];
  hmac_sha512((const uint8_t *)BIP32_SEED_KEY, sizeof(BIP32_SEED_KEY) - 1,
              seed, seed_len, I);
  memcpy(master_key, I, BIP32_KEY_LEN);
  memcpy(chain_code, I + BIP32_KEY_LEN, BIP32_CHAIN_LEN);
  secure_zero(I, sizeof(I));
  return true;
}

bool hd_ckd_priv(const uint8_t parent_key[BIP32_KEY_LEN],
                 const uint8_t parent_chain[BIP32_CHAIN_LEN],
                 uint32_t index,
                 uint8_t child_key[BIP32_KEY_LEN],
                 uint8_t child_chain[BIP32_CHAIN_LEN]) {
  if (!parent_key || !parent_chain || !child_key || !child_chain)
    return false;

  uint8_t I[HMAC_SHA512_OUTPUT_SIZE];
  uint8_t data[37];

  if (index & HD_HARDENED) {
    data[0] = 0x00;
    memcpy(data + 1, parent_key, 32);
  } else {
    uint64_t pk[4];
    u256_from_be(pk, parent_key);
    ec_pt pub;
    ec_scalar_mult_G(&pub, pk);
    ec_to_pubkey(&pub, data);
  }

  data[33] = (uint8_t)(index >> 24);
  data[34] = (uint8_t)(index >> 16);
  data[35] = (uint8_t)(index >> 8);
  data[36] = (uint8_t)(index);

  hmac_sha512(parent_chain, BIP32_CHAIN_LEN, data, 37, I);

  uint64_t IL[4], pkey[4], child_k[4];
  u256_from_be(IL, I);
  u256_from_be(pkey, parent_key);
  n_mod_add(child_k, IL, pkey);

  u256_to_be(child_k, child_key);
  memcpy(child_chain, I + 32, BIP32_CHAIN_LEN);

  secure_zero(I, sizeof(I));
  secure_zero(data, sizeof(data));
  return true;
}

bool hd_ckd_pub(const uint8_t parent_pubkey[BIP32_PUBKEY_LEN],
                const uint8_t parent_chain[BIP32_CHAIN_LEN],
                uint32_t index,
                uint8_t child_pubkey[BIP32_PUBKEY_LEN],
                uint8_t child_chain[BIP32_CHAIN_LEN]) {
  if (!parent_pubkey || !parent_chain || !child_pubkey || !child_chain)
    return false;
  if (index & HD_HARDENED) return false;

  uint8_t I[HMAC_SHA512_OUTPUT_SIZE];
  uint8_t data[37];

  memcpy(data, parent_pubkey, 33);
  data[33] = (uint8_t)(index >> 24);
  data[34] = (uint8_t)(index >> 16);
  data[35] = (uint8_t)(index >> 8);
  data[36] = (uint8_t)(index);

  hmac_sha512(parent_chain, BIP32_CHAIN_LEN, data, 37, I);

  uint64_t IL[4];
  u256_from_be(IL, I);

  ec_pt IL_pt, parent_pt, child_pt;
  ec_scalar_mult_G(&IL_pt, IL);
  pubkey_to_ec(parent_pubkey, &parent_pt);
  ec_add(&child_pt, &IL_pt, &parent_pt);

  ec_to_pubkey(&child_pt, child_pubkey);
  memcpy(child_chain, I + 32, BIP32_CHAIN_LEN);

  secure_zero(I, sizeof(I));
  secure_zero(data, sizeof(data));
  return true;
}

bool hd_public_derive_path(const uint8_t pubkey_in[BIP32_PUBKEY_LEN],
                           const uint8_t chain_in[BIP32_CHAIN_LEN],
                           uint32_t change, uint32_t addr_index,
                           uint8_t pubkey_out[BIP32_PUBKEY_LEN],
                           uint8_t chain_out[BIP32_CHAIN_LEN]) {
  uint8_t pk[33], cc[32];
  memcpy(pk, pubkey_in, 33);
  memcpy(cc, chain_in, 32);

  if (!hd_ckd_pub(pk, cc, change, pk, cc)) return false;
  if (!hd_ckd_pub(pk, cc, addr_index, pk, cc)) return false;

  memcpy(pubkey_out, pk, BIP32_PUBKEY_LEN);
  if (chain_out) memcpy(chain_out, cc, BIP32_CHAIN_LEN);
  return true;
}

bool hd_derive_pubkey(const hd_path_t *path, uint32_t index,
                      uint8_t pubkey_out[BIP32_PUBKEY_LEN]) {
  if (!path || !pubkey_out) return false;
  if (index & HD_HARDENED) return false;

  uint8_t master_pubkey[BIP32_PUBKEY_LEN];
  if (se051_get_pubkey(SE051_KEY_BIP32_MASTER, master_pubkey) != SE_OK)
    return false;

  uint8_t chain_code[BIP32_CHAIN_LEN];
  size_t cc_len = 0;
  if (se051_read_object(SE051_KEY_CHAIN_CODE, chain_code, BIP32_CHAIN_LEN,
                        &cc_len) != SE_OK)
    return false;
  if (cc_len < BIP32_CHAIN_LEN) return false;

  // For the stub: derive full hardened path in software from stored master key.
  // For real HW: hardened derivation uses SE-internal functions.
  // Public derivation proceeds on ESP32-S3.

  uint8_t current_pk[33];
  uint8_t current_cc[32];
  memcpy(current_pk, master_pubkey, 33);
  memcpy(current_cc, chain_code, 32);

  // Derive non-hardened: change (path[3]) + address (index)
  uint32_t change = path->path[3] & ~HD_HARDENED;
  if (!hd_ckd_pub(current_pk, current_cc, change, current_pk, current_cc))
    return false;
  if (!hd_ckd_pub(current_pk, current_cc, index, current_pk, current_cc))
    return false;

  memcpy(pubkey_out, current_pk, BIP32_PUBKEY_LEN);
  return true;
}

bool hd_pubkey_from_priv(const uint8_t privkey[BIP32_KEY_LEN],
                         uint8_t pubkey_out[BIP32_PUBKEY_LEN]) {
  if (!privkey || !pubkey_out) return false;
  uint64_t pk[4];
  u256_from_be(pk, privkey);
  if (u256_is_zero64(pk)) return false;
  ec_pt pt;
  ec_scalar_mult_G(&pt, pk);
  ec_to_pubkey(&pt, pubkey_out);
  return true;
}

bool hd_ec_pubkey_tweak(const uint8_t pubkey[BIP32_PUBKEY_LEN],
                        const uint8_t tweak[32],
                        uint8_t xonly_out[32]) {
  if (!pubkey || !tweak || !xonly_out) return false;
  if (pubkey[0] != 0x02 && pubkey[0] != 0x03) return false;

  ec_pt P;
  if (!pubkey_to_ec(pubkey, &P)) return false;

  uint64_t t[4];
  u256_from_be(t, tweak);

  ec_pt T;
  ec_scalar_mult_G(&T, t);

  ec_pt Q;
  ec_add(&Q, &P, &T);

  if (Q.inf) return false;

  u256_to_be(Q.x, xonly_out);
  return true;
}

bool hd_test_mod_mul(const uint8_t a[32], const uint8_t b[32],
                     uint8_t result[32]) {
  if (!a || !b || !result) return false;
  uint64_t av[4], bv[4], rv[4];
  u256_from_be(av, a);
  u256_from_be(bv, b);
  secp_mod_mul(rv, av, bv);
  u256_to_be(rv, result);
  return true;
}

bool hd_test_mod_inv(const uint8_t a[32], uint8_t result[32]) {
  if (!a || !result) return false;
  uint64_t av[4], rv[4];
  u256_from_be(av, a);
  if (u256_is_zero64(av)) return false;
  secp_mod_inv(rv, av);
  u256_to_be(rv, result);
  return true;
}
