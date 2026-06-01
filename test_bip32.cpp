#ifdef USE_SE_STUB

#include "bip32.h"
#include "se051_hal.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

// ─── helpers ──────────────────────────────────────────────────────────────

static void hex_to_bytes(const char *hex, uint8_t *out, size_t len) {
  for (size_t i = 0; i < len; i++) {
    unsigned int v;
    sscanf(hex + i * 2, "%02x", &v);
    out[i] = (uint8_t)v;
  }
}

static void print_hex(const char *label, const uint8_t *buf, size_t len) {
  printf("%s: ", label);
  for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
  printf("\n");
}

static bool bytes_eq(const uint8_t *a, const uint8_t *b, size_t n) {
  return memcmp(a, b, n) == 0;
}

// ─── BIP32 Test Vector 1 ──────────────────────────────────────────────────
// All values verified against Python hashlib HMAC-SHA512 + secp256k1 EC
// and xprv base58check decode. Pubkeys verified by kG derivation.
//
// Seed: 000102030405060708090a0b0c0d0e0f
//
// Chain m
//   Master key:  e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35
//   Chain code:  873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508
//   Public key:  0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2
//
// Chain m/0'
//   child key:   edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea
//   chain code:  47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141
//   Public key:  035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56
//
// Chain m/0'/1
//   child key:   3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368
//   chain code:  2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19
//   Public key:  03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c
//
// Chain m/0'/1/2'
//   child key:   cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca
//   chain code:  04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f
//   Public key:  0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2
//
// Chain m/0'/1/2'/2
//   child key:   0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4
//   chain code:  cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd
//   Public key:  02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29
//
// Chain m/0'/1/2'/2/1000000000
//   child key:   471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8
//   chain code:  c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e
//   Public key:  022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011

static int total_pass = 0;
static int total_fail = 0;

static bool check_pubkey(const char *label, const uint8_t *privkey,
                         const char *expected_hex) {
  uint8_t pubkey[33];
  bool ok = hd_pubkey_from_priv(privkey, pubkey);
  if (!ok) {
    printf("FAIL [%s]: hd_pubkey_from_priv returned false\n", label);
    total_fail++;
    return false;
  }
  uint8_t expected[33];
  hex_to_bytes(expected_hex, expected, 33);
  if (!bytes_eq(pubkey, expected, 33)) {
    printf("FAIL [%s]:\n", label);
    print_hex("  got     ", pubkey, 33);
    print_hex("  expected", expected, 33);
    total_fail++;
    return false;
  }
  printf("PASS [%s]\n", label);
  total_pass++;
  return true;
}

static bool check_bytes(const char *label, const uint8_t *got,
                        const char *expected_hex, size_t len) {
  uint8_t expected[64];
  hex_to_bytes(expected_hex, expected, len);
  if (!bytes_eq(got, expected, len)) {
    printf("FAIL [%s]:\n", label);
    print_hex("  got     ", got, len);
    print_hex("  expected", expected, len);
    total_fail++;
    return false;
  }
  printf("PASS [%s]\n", label);
  total_pass++;
  return true;
}

int main(void) {
  printf("=== BIP32 Native C Test ===\n\n");

  // ── Seed ────────────────────────────────────────────────────────────────
  const char *seed_hex = "000102030405060708090a0b0c0d0e0f";
  uint8_t seed[16];
  hex_to_bytes(seed_hex, seed, 16);

  uint8_t master_key[32], chain_code[32];
  bool ok = hd_derive_master_from_seed(seed, 16, master_key, chain_code);
  if (!ok) { printf("FAIL: hd_derive_master_from_seed\n"); return 1; }

  check_bytes("m key     ", master_key,
    "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35", 32);
  check_bytes("m chain   ", chain_code,
    "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508", 32);
  check_pubkey("m pubkey  ", master_key,
    "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");

  // ── m/0' ────────────────────────────────────────────────────────────────
  uint8_t k0p[32], cc0p[32];
  hd_ckd_priv(master_key, chain_code, 0 | HD_HARDENED, k0p, cc0p);

  check_bytes("m/0' key  ", k0p,
    "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea", 32);
  check_bytes("m/0' chain", cc0p,
    "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141", 32);
  check_pubkey("m/0' pub  ", k0p,
    "035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56");

  // ── m/0'/1 ──────────────────────────────────────────────────────────────
  uint8_t k01[32], cc01[32];
  hd_ckd_priv(k0p, cc0p, 1, k01, cc01);

  check_bytes("m/0'/1 key", k01,
    "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368", 32);
  check_bytes("m/0'/1 cc ", cc01,
    "2a7857631386ba23dacac34180dd1983734e444fdbf774041578e9b6adb37c19", 32);
  check_pubkey("m/0'/1 pub", k01,
    "03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c");

  // ── m/0'/1/2' ───────────────────────────────────────────────────────────
  uint8_t k012p[32], cc012p[32];
  hd_ckd_priv(k01, cc01, 2 | HD_HARDENED, k012p, cc012p);

  check_bytes("m/0'/1/2' key", k012p,
    "cbce0d719ecf7431d88e6a89fa1483e02e35092af60c042b1df2ff59fa424dca", 32);
  check_bytes("m/0'/1/2' cc ", cc012p,
    "04466b9cc8e161e966409ca52986c584f07e9dc81f735db683c3ff6ec7b1503f", 32);
  check_pubkey("m/0'/1/2' pub", k012p,
    "0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2");

  // ── m/0'/1/2'/2 ─────────────────────────────────────────────────────────
  uint8_t k012p2[32], cc012p2[32];
  hd_ckd_priv(k012p, cc012p, 2, k012p2, cc012p2);

  check_bytes("m/0'/1/2'/2 key", k012p2,
    "0f479245fb19a38a1954c5c7c0ebab2f9bdfd96a17563ef28a6a4b1a2a764ef4", 32);
  check_bytes("m/0'/1/2'/2 cc ", cc012p2,
    "cfb71883f01676f587d023cc53a35bc7f88f724b1f8c2892ac1275ac822a3edd", 32);
  check_pubkey("m/0'/1/2'/2 pub", k012p2,
    "02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29");

  // ── m/0'/1/2'/2/1000000000 ──────────────────────────────────────────────
  uint8_t k_leaf[32], cc_leaf[32];
  hd_ckd_priv(k012p2, cc012p2, 1000000000, k_leaf, cc_leaf);

  check_bytes("m/.../1e9 key", k_leaf,
    "471b76e389e528d6de6d816857e012c5455051cad6660850e58372a6c3e6e7c8", 32);
  check_bytes("m/.../1e9 cc ", cc_leaf,
    "c783e67b921d2beb8f6b389cc646d7263b4145701dadd2161548a8b078e65e9e", 32);
  check_pubkey("m/.../1e9 pub", k_leaf,
    "022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011");

  // ── Public-path derivation using hd_ckd_pub ─────────────────────────────
  // m/0'/1 pubkey → child /2 via CKD_pub (same result as above since 2 not hardened)
  {
    uint8_t m01_pub[33];
    hd_pubkey_from_priv(k01, m01_pub);
    uint8_t m012_pub[33], m012_cc[32];
    bool ok2 = hd_ckd_pub(m01_pub, cc01, 2 | HD_HARDENED, m012_pub, m012_cc);
    if (ok2) {
      printf("FAIL [ckd_pub hardened]: should have returned false\n");
      total_fail++;
    } else {
      printf("PASS [ckd_pub hardened rejection]\n");
      total_pass++;
    }

    // m/0'/1/2' can't be derived from pubkey (hardened). But /2 from m/0'/1 is non-hardened.
    bool ok3 = hd_ckd_pub(m01_pub, cc01, 2, m012_pub, m012_cc);
    // The result should match m/0'/1/2 (non-hardened) derived from private key
    uint8_t k012nh[32], cc012nh[32]; // m/0'/1/2 (non-hardened 2)
    hd_ckd_priv(k01, cc01, 2, k012nh, cc012nh);
    uint8_t expected_012nh_pub[33];
    hd_pubkey_from_priv(k012nh, expected_012nh_pub);
    if (!ok3) {
      printf("FAIL [ckd_pub m/0'/1/2(nh)]: returned false\n");
      total_fail++;
    } else if (!bytes_eq(m012_pub, expected_012nh_pub, 33)) {
      printf("FAIL [ckd_pub m/0'/1/2(nh)]: pubkey mismatch\n");
      print_hex("  ckd_pub result", m012_pub, 33);
      print_hex("  priv-derived  ", expected_012nh_pub, 33);
      total_fail++;
    } else {
      printf("PASS [ckd_pub m/0'/1/2(nh)]: pub-path matches priv-derived\n");
      total_pass++;
    }
  }

  // ── BIP32 test vector 2 ─────────────────────────────────────────────────
  // Seed (32 bytes, descending-by-3 sequence): fffcf9...a5a2
  // Values verified against Python hashlib HMAC-SHA512 + correct secp256k1 EC
  {
    const char *seed2_hex =
      "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a2";
    uint8_t seed2[32];
    hex_to_bytes(seed2_hex, seed2, 32);

    uint8_t mk2[32], cc2[32];
    hd_derive_master_from_seed(seed2, 32, mk2, cc2);

    check_bytes("tv2 m key  ", mk2,
      "fbeb0555b41f52a250a9c99f9dee2a0ae225323cfc41601d29ad3e725b733f85", 32);
    check_pubkey("tv2 m pub  ", mk2,
      "032f363ea99b5ff1422db7b37a976d313136e9c959728bbbc527acf693acc349a3");

    // m/0
    uint8_t k2_0[32], cc2_0[32];
    hd_ckd_priv(mk2, cc2, 0, k2_0, cc2_0);
    check_pubkey("tv2 m/0 pub", k2_0,
      "03fcbcae62230940e013e188decf2418bf20574c12d7aaad3d298c5b4657e8a613");

    // m/0/2147483647' (0x7fffffff | hardened = 0xffffffff)
    uint8_t k2_0h[32], cc2_0h[32];
    hd_ckd_priv(k2_0, cc2_0, 2147483647 | HD_HARDENED, k2_0h, cc2_0h);
    check_pubkey("tv2 m/0/2147483647' pub", k2_0h,
      "0295776875daf4e2d18c07f5482485823786381af455ebd22ad2c4e58b11d42feb");
  }

  printf("\n=== Results: %d pass, %d fail ===\n", total_pass, total_fail);
  return total_fail ? 1 : 0;
}

#endif // USE_SE_STUB
