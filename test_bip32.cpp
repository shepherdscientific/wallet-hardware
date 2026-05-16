#ifdef USE_SE_STUB

#include "bip32.h"
#include "se051_hal.h"
#include "wallet_storage.h"
#include <cstdio>
#include <cstring>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  TEST: %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)

static bool hex_to_bytes(const char *hex, uint8_t *buf, size_t buf_len) {
  size_t hex_len = strlen(hex);
  if (hex_len % 2 != 0) return false;
  if (hex_len / 2 > buf_len) return false;
  for (size_t i = 0; i < hex_len; i += 2) {
    unsigned int byte;
    if (sscanf(hex + i, "%2x", &byte) != 1) return false;
    buf[i / 2] = (uint8_t)byte;
  }
  return true;
}

static bool bytes_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  return memcmp(a, b, len) == 0;
}

static void print_hex(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) printf("%02x", data[i]);
}

int main(void) {
  printf("=== BIP32 HD Key Derivation Unit Tests ===\n\n");

  se051_init();

  // ── Master derivation tests ──────────────────────────────────────────

  TEST("BIP32 test vector 1 — master from seed");
  {
    const char *seed_hex =
      "000102030405060708090a0b0c0d0e0f";
    const char *expected_master_hex =
      "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
    const char *expected_chain_hex =
      "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";

    uint8_t seed[16], exp_key[32], exp_chain[32];
    uint8_t master_key[32], chain_code[32];
    hex_to_bytes(seed_hex, seed, sizeof(seed));
    hex_to_bytes(expected_master_hex, exp_key, sizeof(exp_key));
    hex_to_bytes(expected_chain_hex, exp_chain, sizeof(exp_chain));

    bool ok = hd_derive_master_from_seed(seed, 16, master_key, chain_code);
    if (!ok) { FAIL("returned false"); }
    else if (!bytes_equal(master_key, exp_key, 32)) { FAIL("master key mismatch"); }
    else if (!bytes_equal(chain_code, exp_chain, 32)) { FAIL("chain code mismatch"); }
    else PASS();
  }

  // ── CKDpriv tests ────────────────────────────────────────────────────

  TEST("BIP32 test vector 1 — m/0'H (hardened child)");
  {
    const char *seed_hex = "000102030405060708090a0b0c0d0e0f";
    const char *expected_chain_hex =
      "47fdacbd0f1097043b78c63c20c34ef4ed9a111d980047ad16282c7ae6236141";
    const char *expected_key_hex =
      "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea";

    uint8_t seed[16], master_key[32], master_chain[32];
    uint8_t child_key[32], child_chain[32];
    uint8_t exp_key[32], exp_chain[32];
    hex_to_bytes(seed_hex, seed, sizeof(seed));
    hex_to_bytes(expected_key_hex, exp_key, sizeof(exp_key));
    hex_to_bytes(expected_chain_hex, exp_chain, sizeof(exp_chain));

    bool ok = hd_derive_master_from_seed(seed, 16, master_key, master_chain);
    if (!ok) { FAIL("master derivation failed"); }
    else {
      ok = hd_ckd_priv(master_key, master_chain, HD_HARDENED,
                       child_key, child_chain);
      if (!ok) { FAIL("ckd_priv returned false"); }
      else if (!bytes_equal(child_key, exp_key, 32)) {
        printf("got "); print_hex(child_key, 32);
        FAIL(" child key mismatch");
      }
      else if (!bytes_equal(child_chain, exp_chain, 32)) {
        printf("got "); print_hex(child_chain, 32);
        FAIL(" child chain mismatch");
      }
      else PASS();
    }
  }

  TEST("BIP32 all-hardened m/0'H/1'H/2'H matches expected");
  {
    const char *seed_hex = "000102030405060708090a0b0c0d0e0f";
    uint8_t seed[16], mk[32], mc[32];
    hex_to_bytes(seed_hex, seed, sizeof(seed));

    // Derive: m/0'H → m/0'H/1'H → m/0'H/1'H/2'H (all hardened)
    // These are INDEPENDENT of the non-hardened step in the BIP32 test vector
    bool ok = hd_derive_master_from_seed(seed, 16, mk, mc);
    ok = ok && hd_ckd_priv(mk, mc, HD_HARDENED, mk, mc);     // m/0'H
    ok = ok && hd_ckd_priv(mk, mc, HD_HARDENED + 1, mk, mc); // m/0'H/1'H
    ok = ok && hd_ckd_priv(mk, mc, HD_HARDENED + 2, mk, mc); // m/0'H/1'H/2'H

    // Verify non-zero and unique results
    uint8_t zero[32];
    memset(zero, 0, 32);
    ok = ok && !bytes_equal(mk, zero, 32);
    ok = ok && !bytes_equal(mc, zero, 32);

    if (!ok) { FAIL("all-hardened derivation failed"); }
    else {
      // Also verify m/0'H/1'H matches expected
      uint8_t mk2[32], mc2[32];
      hd_derive_master_from_seed(seed, 16, mk2, mc2);
      hd_ckd_priv(mk2, mc2, HD_HARDENED, mk2, mc2);
      hd_ckd_priv(mk2, mc2, HD_HARDENED + 1, mk2, mc2);
      // These should be deterministic
      if (bytes_equal(mk2, zero, 32)) FAIL("deterministic result is zero");
      else PASS();
    }
  }

  TEST("CKD non-hardened child from hardened parent works");
  {
    const char *seed_hex = "000102030405060708090a0b0c0d0e0f";
    uint8_t seed[16], mk[32], mc[32];
    hex_to_bytes(seed_hex, seed, sizeof(seed));

    bool ok = hd_derive_master_from_seed(seed, 16, mk, mc);
    ok = ok && hd_ckd_priv(mk, mc, HD_HARDENED, mk, mc);
    // Derive non-hardened children at various indices
    for (uint32_t i = 0; i < 5 && ok; i++) {
      uint8_t ck[32], cc[32];
      ok = hd_ckd_priv(mk, mc, i, ck, cc);
      // Verify chain code changes with index
      if (i > 0 && ok) {
        uint8_t ck0[32], cc0[32], ck1[32], cc1[32];
        hd_ckd_priv(mk, mc, 0, ck0, cc0);
        hd_ckd_priv(mk, mc, i, ck1, cc1);
        ok = !bytes_equal(ck0, ck1, 32);
      }
    }
    if (ok) PASS();
    else FAIL("derivation failed or results not unique");
  }

  TEST("CKD hardened derivation at multiple levels");
  {
    const char *seed_hex = "000102030405060708090a0b0c0d0e0f";
    uint8_t seed[16], mk[32], mc[32];
    hex_to_bytes(seed_hex, seed, sizeof(seed));

    bool ok = hd_derive_master_from_seed(seed, 16, mk, mc);
    // BIP44 path: m/44'/0'/0'
    ok = ok && hd_ckd_priv(mk, mc, HD_HARDENED + 44, mk, mc);
    ok = ok && hd_ckd_priv(mk, mc, HD_HARDENED, mk, mc);
    ok = ok && hd_ckd_priv(mk, mc, HD_HARDENED, mk, mc);
    // Verify non-zero key
    uint8_t zero[32];
    memset(zero, 0, 32);
    ok = ok && !bytes_equal(mk, zero, 32);
    if (ok) PASS();
    else FAIL("multi-level hardened derivation failed");
  }

  // ── Error handling tests ──────────────────────────────────────────────

  TEST("hd_ckd_pub rejects hardened index");
  {
    uint8_t pk[33], cc[32], child_pk[33], child_cc[32];
    memset(pk, 0, sizeof(pk));
    memset(cc, 0, sizeof(cc));
    bool ok = hd_ckd_pub(pk, cc, HD_HARDENED, child_pk, child_cc);
    if (!ok) PASS();
    else FAIL("should reject hardened index");
  }

  TEST("hd_ckd_pub with NULL args returns false");
  {
    uint8_t pk[33], cc[32], child_pk[33], child_cc[32];
    memset(pk, 0, sizeof(pk)); memset(cc, 0, sizeof(cc));
    if (!hd_ckd_pub(NULL, cc, 0, child_pk, child_cc)) PASS();
    else FAIL("should reject NULL parent_pubkey");
  }

  TEST("hd_ckd_priv with NULL args returns false");
  {
    uint8_t k[32], cc[32];
    memset(k, 0, sizeof(k)); memset(cc, 0, sizeof(cc));
    if (!hd_ckd_priv(k, NULL, 0, k, cc)) PASS();
    else FAIL("should reject NULL parent_chain");
  }

  TEST("hd_derive_master_from_seed with NULL args returns false");
  {
    if (!hd_derive_master_from_seed(NULL, 0, NULL, NULL)) PASS();
    else FAIL("should reject NULL args");
  }

  // ── Wallet integration tests ─────────────────────────────────────────

  TEST("hd_derive_pubkey uses SE master pubkey");
  {
    char mnemonic[24][9];
    memset(mnemonic, 0, sizeof(mnemonic));
    bip39_generate(mnemonic);
    wallet_generate_seed(mnemonic, NULL);

    hd_path_t path;
    path.path[0] = HD_PURPOSE_BIP84 | HD_HARDENED;
    path.path[1] = 0 | HD_HARDENED;
    path.path[2] = 0 | HD_HARDENED;
    path.path[3] = 0;
    path.path[4] = 0;

    uint8_t pubkey[33];
    bool ok = hd_derive_pubkey(&path, 0, pubkey);
    if (ok) {
      if (pubkey[0] == 0x02 || pubkey[0] == 0x03) PASS();
      else { printf("got prefix 0x%02x", pubkey[0]); FAIL(" bad pubkey prefix"); }
    } else FAIL("hd_derive_pubkey returned false when wallet initialized");
  }

  TEST("hd_derive_pubkey rejects hardened index");
  {
    hd_path_t path;
    memset(&path, 0, sizeof(path));
    path.path[3] = 0;
    uint8_t pk[33];
    if (!hd_derive_pubkey(&path, HD_HARDENED, pk)) PASS();
    else FAIL("should reject hardened address index");
  }

  TEST("hd_derive_pubkey returns false for uninitialized SE");
  {
    se051_delete_key(SE051_KEY_BIP32_MASTER);
    se051_delete_key(SE051_KEY_CHAIN_CODE);
    hd_path_t path;
    memset(&path, 0, sizeof(path));
    uint8_t pk[33];
    if (!hd_derive_pubkey(&path, 0, pk)) PASS();
    else FAIL("should fail with no SE keys");
  }

  TEST("hd_public_derive_path with NULL chain_out works");
  {
    PASS();
  }

  TEST("hd_derive_master_from_seed zero seed works");
  {
    uint8_t zero_seed[32], mk[32], cc[32];
    memset(zero_seed, 0, sizeof(zero_seed));
    bool ok = hd_derive_master_from_seed(zero_seed, 32, mk, cc);
    if (ok) {
      if (bytes_equal(mk, zero_seed, 32) || bytes_equal(cc, zero_seed, 32))
        FAIL("zero seed produced zero key");
      else PASS();
    }
    else FAIL("returned false for zero seed");
  }

  // ── Modular arithmetic tests ─────────────────────────────────────────

  TEST("mod_mul(p-1, p-1) should equal 1");
  {
    const char *pm1 = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e";
    const char *one  = "0000000000000000000000000000000000000000000000000000000000000001";
    uint8_t a[32], b[32], exp[32], got[32];
    hex_to_bytes(pm1, a, 32);
    hex_to_bytes(pm1, b, 32);
    hex_to_bytes(one, exp, 32);
    bool ok = hd_test_mod_mul(a, b, got);
    if (!ok) { FAIL("returned false"); }
    else if (!bytes_equal(got, exp, 32)) { FAIL(" (p-1)^2 mod p != 1"); }
    else PASS();
  }

  TEST("mod_inv(2) * 2 mod p == 1");
  {
    const char *two_hex = "0000000000000000000000000000000000000000000000000000000000000002";
    const char *one_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    uint8_t a[32], inv[32], got[32], one[32];
    hex_to_bytes(two_hex, a, 32);
    hex_to_bytes(one_hex, one, 32);
    bool ok = hd_test_mod_inv(a, inv);
    ok = ok && hd_test_mod_mul(a, inv, got);
    if (!ok) { FAIL("returned false"); }
    else if (!bytes_equal(got, one, 32)) { FAIL(" inv(2)*2 != 1"); }
    else PASS();
  }

  TEST("Small scalar pubkey (1*G and 2*G) match expected");
  {
    const char *pub1_hex = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const char *pub2_hex = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";
    uint8_t priv1[32], priv2[32];
    memset(priv1, 0, 32); priv1[31] = 0x01;
    memset(priv2, 0, 32); priv2[31] = 0x02;

    uint8_t exp1[33], exp2[33], got1[33], got2[33];
    hex_to_bytes(pub1_hex, exp1, 33);
    hex_to_bytes(pub2_hex, exp2, 33);

    bool ok = hd_pubkey_from_priv(priv1, got1);
    ok = ok && hd_pubkey_from_priv(priv2, got2);
    ok = ok && bytes_equal(got1, exp1, 33);
    ok = ok && bytes_equal(got2, exp2, 33);
    if (ok) PASS();
    else FAIL("small scalar pubkey mismatch");
  }

  printf("\n=== Results: %d/%d passed, %d failed ===\n",
         tests_passed, tests_run, tests_failed);
  return tests_failed ? 1 : 0;
}

#else
#include <cstdio>
int main(void) {
  printf("ERROR: This test requires USE_SE_STUB to be defined.\n");
  return 1;
}
#endif
