#ifdef USE_SE_STUB

#include "wallet_storage.h"
#include "se051_hal.h"
#include "pin_manager.h"
#include "sha512.h"
#include "hmac_sha512.h"
#include "bip39.h"
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

int main(void) {
  printf("=== Wallet Storage Unit Tests ===\n\n");

  se051_init();

  TEST("sha512 empty string");
  {
    const char *expected_hex =
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    uint8_t hash[SHA512_DIGEST_LENGTH];
    uint8_t expected[SHA512_DIGEST_LENGTH];
    sha512(NULL, 0, hash);
    hex_to_bytes(expected_hex, expected, sizeof(expected));
    if (bytes_equal(hash, expected, SHA512_DIGEST_LENGTH)) PASS();
    else FAIL("empty string hash mismatch");
  }

  TEST("sha512 'abc'");
  {
    const char *expected_hex =
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
    uint8_t hash[SHA512_DIGEST_LENGTH];
    uint8_t expected[SHA512_DIGEST_LENGTH];
    sha512((const uint8_t *)"abc", 3, hash);
    hex_to_bytes(expected_hex, expected, sizeof(expected));
    if (bytes_equal(hash, expected, SHA512_DIGEST_LENGTH)) PASS();
    else FAIL("'abc' hash mismatch");
  }

  TEST("hmac_sha512 RFC 4231 test case 1");
  {
    const char *key_hex   = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    const char *msg       = "Hi There";
    const char *expected_hex =
      "87aa7cdea5ef619d4ff0b4241a1d6cb0"
      "2379f4e2ce4ec2787ad0b30545e17cde"
      "daa833b7d6b8a702038b274eaea3f4e4"
      "be9d914eeb61f1702e696c203a126854";
    uint8_t key[64];
    uint8_t expected[64];
    uint8_t mac[64];
    hex_to_bytes(key_hex, key, 20);
    hex_to_bytes(expected_hex, expected, sizeof(expected));
    hmac_sha512(key, 20, (const uint8_t *)msg, strlen(msg), mac);
    if (bytes_equal(mac, expected, sizeof(expected))) PASS();
    else FAIL("RFC 4231 test case 1 mismatch");
  }

  TEST("hmac_sha512 RFC 4231 test case 2 (key > block size)");
  {
    const char *expected_hex =
      "80b24263c7c1a3ebb71493c1dd7be8b4"
      "9b46d1f41b4aeec1121b013783f8f352"
      "6b56d037e05f2598bd0fd2215d6a1e52"
      "95e64f73f63f0aec8b915a985d786598";
    uint8_t key[131];
    uint8_t expected[64];
    uint8_t mac[64];
    memset(key, 0xAA, 131);
    const char *msg = "Test Using Larger Than Block-Size Key - Hash Key First";
    hex_to_bytes(expected_hex, expected, sizeof(expected));
    hmac_sha512(key, 131, (const uint8_t *)msg, strlen(msg), mac);
    if (bytes_equal(mac, expected, sizeof(expected))) PASS();
    else FAIL("RFC 4231 test case 2 mismatch");
  }

  TEST("hmac_sha512 RFC 4231 test case 3 (key + data > block size)");
  {
    const char *expected_hex =
      "fdb75a1f56367a0b80308341eb1f0868"
      "95981efc861f858b9931b88928781ac0"
      "5c65fc9fe2b91ead800dad863cf7ed42"
      "76bed43693a81f72903f55b5e8bc4885";
    uint8_t key[131];
    uint8_t expected[64];
    uint8_t mac[64];
    memset(key, 0xAA, 131);
    hex_to_bytes(expected_hex, expected, sizeof(expected));
    char large_msg[200];
    memset(large_msg, 0xDD, sizeof(large_msg));
    hmac_sha512(key, 131, (const uint8_t *)large_msg, sizeof(large_msg), mac);
    if (bytes_equal(mac, expected, sizeof(expected))) PASS();
    else FAIL("RFC 4231 test case 3 mismatch");
  }

  TEST("BIP32 master key derivation vector 1");
  {
    const char *seed_hex =
      "000102030405060708090a0b0c0d0e0f";
    const char *expected_il_hex =
      "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35";
    const char *expected_ir_hex =
      "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
    uint8_t seed[16];
    uint8_t bip32_i[64];
    uint8_t expected_il[32];
    uint8_t expected_ir[32];
    hex_to_bytes(seed_hex, seed, sizeof(seed));
    hex_to_bytes(expected_il_hex, expected_il, sizeof(expected_il));
    hex_to_bytes(expected_ir_hex, expected_ir, sizeof(expected_ir));
    const char *key = "Bitcoin seed";
    hmac_sha512((const uint8_t *)key, strlen(key), seed, 16, bip32_i);
    if (bytes_equal(bip32_i, expected_il, 32) &&
        bytes_equal(bip32_i + 32, expected_ir, 32)) PASS();
    else FAIL("BIP32 master key derivation mismatch");
  }

  TEST("wallet_is_initialized returns false on fresh SE");
  {
    se051_delete_key(SE051_KEY_BIP32_MASTER);
    se051_delete_key(SE051_KEY_CHAIN_CODE);
    if (!wallet_is_initialized()) PASS();
    else FAIL("should return false when no keys stored");
  }

  TEST("wallet_generate_seed with valid mnemonic returns true");
  {
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    memset(mnemonic, 0, sizeof(mnemonic));
    bip39_generate(mnemonic);
    if (wallet_generate_seed(mnemonic, NULL)) PASS();
    else FAIL("wallet_generate_seed returned false");
  }

  TEST("wallet_is_initialized returns true after generate_seed");
  {
    if (wallet_is_initialized()) PASS();
    else FAIL("should return true after seed generation");
  }

  TEST("wallet_generate_seed with passphrase works");
  {
    se051_delete_key(SE051_KEY_BIP32_MASTER);
    se051_delete_key(SE051_KEY_CHAIN_CODE);
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    memset(mnemonic, 0, sizeof(mnemonic));
    bip39_generate(mnemonic);
    if (wallet_generate_seed(mnemonic, "TEST_PASSPHRASE")) PASS();
    else FAIL("wallet_generate_seed with passphrase returned false");
  }

  TEST("wallet_generate_seed stores key 0x01 (master) in SE");
  {
    uint8_t pubkey[SE051_PUBKEY_COMPRESSED];
    if (se051_get_pubkey(SE051_KEY_BIP32_MASTER, pubkey) == SE_OK) PASS();
    else FAIL("key 0x01 not found in SE");
  }

  TEST("wallet_generate_seed stores key 0x02 (chain code) in SE");
  {
    uint8_t pubkey[SE051_PUBKEY_COMPRESSED];
    if (se051_get_pubkey(SE051_KEY_CHAIN_CODE, pubkey) == SE_OK) PASS();
    else FAIL("key 0x02 not found in SE");
  }

  TEST("wallet_generate_seed with empty mnemonic returns false");
  {
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    memset(mnemonic, 0, sizeof(mnemonic));
    if (!wallet_generate_seed(mnemonic, NULL)) PASS();
    else FAIL("should reject empty mnemonic");
  }

  TEST("delete key 0x01 makes wallet uninitialized");
  {
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    memset(mnemonic, 0, sizeof(mnemonic));
    bip39_generate(mnemonic);
    wallet_generate_seed(mnemonic, NULL);
    se051_delete_key(SE051_KEY_BIP32_MASTER);
    if (!wallet_is_initialized()) PASS();
    else FAIL("should return false when only chain code exists");
  }

  TEST("delete key 0x02 makes wallet uninitialized");
  {
    se051_delete_key(SE051_KEY_CHAIN_CODE);
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    memset(mnemonic, 0, sizeof(mnemonic));
    bip39_generate(mnemonic);
    wallet_generate_seed(mnemonic, NULL);
    se051_delete_key(SE051_KEY_CHAIN_CODE);
    if (!wallet_is_initialized()) PASS();
    else FAIL("should return false when only master key exists");
  }

  TEST("wallet_generate_seed returns null-terminated mnemonic correctly");
  {
    se051_delete_key(SE051_KEY_BIP32_MASTER);
    se051_delete_key(SE051_KEY_CHAIN_CODE);
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    memset(mnemonic, 0, sizeof(mnemonic));
    bip39_generate(mnemonic);
    bool ok = wallet_generate_seed(mnemonic, NULL) &&
              wallet_is_initialized();
    if (ok) PASS();
    else FAIL("mnemonic processing failed");
  }

  TEST("wallet_has_passphrase returns false by default");
  {
    se051_delete_key(SE051_OBJ_HAS_PASSPHRASE);
    if (!wallet_has_passphrase()) PASS();
    else FAIL("should return false when no passphrase flag set");
  }

  TEST("wallet_set_passphrase_flag(true) works");
  {
    if (wallet_set_passphrase_flag(true)) PASS();
    else FAIL("setting passphrase flag failed");
  }

  TEST("wallet_has_passphrase returns true after set");
  {
    if (wallet_has_passphrase()) PASS();
    else FAIL("should return true after flag was set");
  }

  TEST("wallet_set_passphrase_flag(false) clears the flag");
  {
    if (wallet_set_passphrase_flag(false)) PASS();
    else FAIL("clearing passphrase flag failed");
  }

  TEST("wallet_has_passphrase returns false after clear");
  {
    if (!wallet_has_passphrase()) PASS();
    else FAIL("should return false after flag was cleared");
  }

  TEST("passphrase flag survives factory reset (deleted)");
  {
    wallet_set_passphrase_flag(true);
    wallet_factory_reset();
    if (!wallet_has_passphrase()) PASS();
    else FAIL("passphrase flag should be deleted by factory reset");
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
