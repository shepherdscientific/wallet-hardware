#ifdef USE_SE_STUB

#include "se051_hal.h"
#include <cstdio>
#include <cstring>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
  tests_run++; \
  printf("  TEST: %s ... ", name); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)

int main(void) {
  printf("=== SE051 HAL Stub Unit Tests ===\n\n");

  // Test 1: init returns SE_OK
  TEST("se051_init returns SE_OK");
  if (se051_init() == SE_OK) PASS(); else FAIL("init failed");

  // Test 2: selftest returns SE_OK after init
  TEST("se051_selftest returns SE_OK");
  if (se051_selftest() == SE_OK) PASS(); else FAIL("selftest failed");

  // Test 3: get_random produces 32 bytes
  TEST("se051_get_random returns 32 bytes");
  {
    uint8_t buf[32];
    memset(buf, 0, 32);
    if (se051_get_random(buf, 32) == SE_OK) {
      int non_zero = 0;
      for (int i = 0; i < 32; i++) {
        if (buf[i] != 0) non_zero = 1;
      }
      if (non_zero) PASS(); else FAIL("all bytes are zero");
    } else {
      FAIL("get_random returned error");
    }
  }

  // Test 4: get_random produces non-identical output across calls
  TEST("se051_get_random produces varied output");
  {
    uint8_t bufs[10][32];
    int all_identical = 1;
    for (int call = 0; call < 10; call++) {
      memset(bufs[call], 0, 32);
      if (se051_get_random(bufs[call], 32) != SE_OK) {
        FAIL("get_random call failed");
        all_identical = 0;
        break;
      }
    }
    if (all_identical) {
      all_identical = 1;
      for (int call = 1; call < 10; call++) {
        if (memcmp(bufs[0], bufs[call], 32) != 0) {
          all_identical = 0;
          break;
        }
      }
      if (all_identical) FAIL("all 10 calls returned identical data");
      else PASS();
    }
  }

  // Test 5: get_random never returns all-zero
  TEST("se051_get_random never all-zero (10 calls)");
  {
    int any_all_zero = 0;
    for (int call = 0; call < 10; call++) {
      uint8_t buf[32];
      se051_get_random(buf, 32);
      int all_zero = 1;
      for (int i = 0; i < 32; i++) {
        if (buf[i] != 0x00) { all_zero = 0; break; }
      }
      if (all_zero) { any_all_zero = 1; break; }
    }
    if (any_all_zero) FAIL("one call produced all-zero output");
    else PASS();
  }

  // Test 6: get_random never returns all-FF
  TEST("se051_get_random never all-FF (10 calls)");
  {
    int any_all_ff = 0;
    for (int call = 0; call < 10; call++) {
      uint8_t buf[32];
      se051_get_random(buf, 32);
      int all_ff = 1;
      for (int i = 0; i < 32; i++) {
        if (buf[i] != 0xFF) { all_ff = 0; break; }
      }
      if (all_ff) { any_all_ff = 1; break; }
    }
    if (any_all_ff) FAIL("one call produced all-FF output");
    else PASS();
  }

  // Test 7: get_random with NULL buffer returns error
  TEST("se051_get_random NULL buf returns SE_ERR_PARAM");
  if (se051_get_random(NULL, 32) == SE_ERR_PARAM) PASS();
  else FAIL("did not return SE_ERR_PARAM");

  // Test 8: get_random with zero length returns error
  TEST("se051_get_random len=0 returns SE_ERR_PARAM");
  {
    uint8_t buf[1];
    if (se051_get_random(buf, 0) == SE_ERR_PARAM) PASS();
    else FAIL("did not return SE_ERR_PARAM");
  }

  // Test 9: store_key returns SE_OK
  TEST("se051_store_key returns SE_OK");
  {
    uint8_t key_material[32];
    se051_get_random(key_material, 32);
    if (se051_store_key(SE051_KEY_BIP32_MASTER, key_material, 32) == SE_OK)
      PASS();
    else FAIL("store_key failed");
  }

  // Test 10: get_pubkey on stored key returns SE_OK and 33 bytes
  TEST("se051_get_pubkey returns compressed pubkey");
  {
    uint8_t pubkey[SE051_PUBKEY_COMPRESSED];
    memset(pubkey, 0, SE051_PUBKEY_COMPRESSED);
    if (se051_get_pubkey(SE051_KEY_BIP32_MASTER, pubkey) == SE_OK) {
      if (pubkey[0] == 0x02 || pubkey[0] == 0x03) PASS();
      else FAIL("first byte not 0x02 or 0x03");
    } else {
      FAIL("get_pubkey failed");
    }
  }

  // Test 11: get_pubkey on unknown key returns SE_ERR_NOTFOUND
  TEST("se051_get_pubkey unknown key returns SE_ERR_NOTFOUND");
  {
    uint8_t pubkey[SE051_PUBKEY_COMPRESSED];
    if (se051_get_pubkey(0xFE, pubkey) == SE_ERR_NOTFOUND) PASS();
    else FAIL("did not return SE_ERR_NOTFOUND");
  }

  // Test 12: delete_key then get_pubkey returns error
  TEST("se051_delete_key then get_pubkey returns SE_ERR_NOTFOUND");
  {
    se051_delete_key(SE051_KEY_BIP32_MASTER);
    uint8_t pubkey[SE051_PUBKEY_COMPRESSED];
    if (se051_get_pubkey(SE051_KEY_BIP32_MASTER, pubkey) == SE_ERR_NOTFOUND)
      PASS();
    else FAIL("get_pubkey succeeded after delete");
  }

  // Test 13: ecdsa_sign on stored key returns SE_OK
  TEST("se051_ecdsa_sign on stored key returns SE_OK");
  {
    uint8_t key_material[32];
    uint8_t hash[SE051_HASH_LEN];
    uint8_t sig[SE051_ECDSA_MAX_DER_LEN];
    size_t sig_len = 0;
    se051_get_random(key_material, 32);
    se051_get_random(hash, SE051_HASH_LEN);
    se051_store_key(SE051_KEY_BIP32_MASTER, key_material, 32);
    if (se051_ecdsa_sign(SE051_KEY_BIP32_MASTER, hash, sig, &sig_len) == SE_OK) {
      if (sig_len > 0 && sig_len <= SE051_ECDSA_MAX_DER_LEN &&
          sig[0] == 0x30) PASS();
      else FAIL("invalid DER signature");
    } else {
      FAIL("ecdsa_sign failed");
    }
  }

  // Test 14: schnorr_sign on stored key returns SE_OK
  TEST("se051_schnorr_sign on stored key returns SE_OK");
  {
    uint8_t hash[SE051_HASH_LEN];
    uint8_t sig[SE051_SCHNORR_SIG_LEN];
    se051_get_random(hash, SE051_HASH_LEN);
    if (se051_schnorr_sign(SE051_KEY_BIP32_MASTER, hash, sig) == SE_OK)
      PASS();
    else FAIL("schnorr_sign failed");
  }

  // Test 15: ecdsa_sign with NULL sig_out returns SE_ERR_PARAM
  TEST("se051_ecdsa_sign NULL sig returns SE_ERR_PARAM");
  {
    uint8_t hash[SE051_HASH_LEN];
    se051_get_random(hash, SE051_HASH_LEN);
    if (se051_ecdsa_sign(SE051_KEY_BIP32_MASTER, hash, NULL, NULL) == SE_ERR_PARAM)
      PASS();
    else FAIL("did not return SE_ERR_PARAM");
  }

  // Test 16: schnorr_sign with NULL sig returns SE_ERR_PARAM
  TEST("se051_schnorr_sign NULL sig returns SE_ERR_PARAM");
  {
    uint8_t hash[SE051_HASH_LEN];
    se051_get_random(hash, SE051_HASH_LEN);
    if (se051_schnorr_sign(SE051_KEY_BIP32_MASTER, hash, NULL) == SE_ERR_PARAM)
      PASS();
    else FAIL("did not return SE_ERR_PARAM");
  }

  // Test 17: store_key with NULL material returns error
  TEST("se051_store_key NULL material returns SE_ERR_PARAM");
  if (se051_store_key(0x10, NULL, 32) == SE_ERR_PARAM) PASS();
  else FAIL("did not return SE_ERR_PARAM");

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
