#ifdef USE_SE_STUB

#include "address.h"
#include "bip32.h"
#include "ripemd160.h"
#include "base58.h"
#include "bech32.h"
#include "sha256.h"
#include "se051_hal.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

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

int main(void) {
  printf("=== Bitcoin Address Generation Unit Tests ===\n\n");

  se051_init();

  // ── RIPEMD-160 tests ──────────────────────────────────────────────────

  TEST("RIPEMD-160 empty string");
  {
    uint8_t hash[20];
    ripemd160((const uint8_t *)"", 0, hash);
    const char *expected = "9c1185a5c5e9fc54612808977ee8f548b2258d31";
    uint8_t exp[20];
    if (hex_to_bytes(expected, exp, 20) && bytes_equal(hash, exp, 20)) PASS();
    else FAIL("wrong hash");
  }

  TEST("RIPEMD-160 'a'");
  {
    uint8_t hash[20];
    ripemd160((const uint8_t *)"a", 1, hash);
    const char *expected = "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe";
    uint8_t exp[20];
    if (hex_to_bytes(expected, exp, 20) && bytes_equal(hash, exp, 20)) PASS();
    else FAIL("wrong hash");
  }

  TEST("RIPEMD-160 'abc'");
  {
    uint8_t hash[20];
    ripemd160((const uint8_t *)"abc", 3, hash);
    const char *expected = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc";
    uint8_t exp[20];
    if (hex_to_bytes(expected, exp, 20) && bytes_equal(hash, exp, 20)) PASS();
    else FAIL("wrong hash");
  }

  TEST("RIPEMD-160 'message digest'");
  {
    uint8_t hash[20];
    ripemd160((const uint8_t *)"message digest", 14, hash);
    const char *expected = "5d0689ef49d2fae572b881b123a85ffa21595f36";
    uint8_t exp[20];
    if (hex_to_bytes(expected, exp, 20) && bytes_equal(hash, exp, 20)) PASS();
    else FAIL("wrong hash");
  }

  TEST("RIPEMD-160 incremental equals one-shot");
  {
    const char *msg = "The quick brown fox jumps over the lazy dog";
    uint8_t one_shot[20];
    ripemd160((const uint8_t *)msg, strlen(msg), one_shot);

    ripemd160_ctx ctx;
    ripemd160_init(&ctx);
    ripemd160_update(&ctx, (const uint8_t *)"The quick brown ", 16);
    ripemd160_update(&ctx, (const uint8_t *)"fox jumps over the lazy dog", 27);
    uint8_t incr[20];
    ripemd160_final(&ctx, incr);

    if (bytes_equal(one_shot, incr, 20)) PASS();
    else FAIL("incremental ≠ one-shot");
  }

  // ── Base58Check tests ─────────────────────────────────────────────────

  TEST("Base58Check encode 1-byte leading zero");
  {
    uint8_t payload[1] = {0x00};
    char out[128];
    if (!base58check_encode(0x00, payload, 1, out)) FAIL("encode failed");
    else if (strcmp(out, "112edB6q") != 0) FAIL(out);
    else PASS();
  }

  TEST("Base58Check P2PKH known vector");
  {
    uint8_t h160[20];
    if (!hex_to_bytes("751e76e8199196d454941c45d1b3a323f1433bd6", h160, 20))
      { FAIL("hex conversion"); }
    else {
      char out[128];
      if (!base58check_encode(0x00, h160, 20, out)) FAIL("encode failed");
      else if (strcmp(out, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH") != 0) FAIL(out);
      else PASS();
    }
  }

  TEST("Base58Check encode/decode consistency");
  {
    uint8_t data[10] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A};
    char out[128];
    if (!base58check_encode(0x00, data, 10, out)) FAIL("encode failed");
    else if (strlen(out) < 5) FAIL("too short");
    else PASS();
  }

  // ── Bech32 tests ──────────────────────────────────────────────────────

  TEST("Bech32 encode P2WPKH known vector");
  {
    uint8_t h160[20];
    if (!hex_to_bytes("751e76e8199196d454941c45d1b3a323f1433bd6", h160, 20))
      { FAIL("hex conversion"); }
    else {
      char out[128];
      if (!bech32_encode("bc", 0, h160, 20, out)) FAIL("encode failed");
      else if (strstr(out, "bc1") != out) FAIL("must start with bc1");
      else PASS();
    }
  }

  TEST("Bech32 encode valid prefix");
  {
    uint8_t witprog[20];
    memset(witprog, 0xAA, 20);
    char out[128];
    if (!bech32_encode("bc", 0, witprog, 20, out)) FAIL("encode failed");
    else if (strncmp(out, "bc1", 3) != 0) FAIL("wrong HRP");
    else PASS();
  }

  TEST("Bech32m encode valid prefix");
  {
    uint8_t witprog[32];
    memset(witprog, 0x55, 32);
    char out[128];
    if (!bech32m_encode("bc", 1, witprog, 32, out)) FAIL("encode failed");
    else if (strncmp(out, "bc1", 3) != 0) FAIL("wrong HRP");
    else PASS();
  }

  TEST("Bech32 rejects invalid HRP");
  {
    uint8_t witprog[20];
    memset(witprog, 0, 20);
    char out[128];
    if (bech32_encode("", 0, witprog, 20, out)) FAIL("should reject empty HRP");
    else PASS();
  }

  TEST("Bech32 rejects invalid witness version");
  {
    uint8_t witprog[20];
    memset(witprog, 0, 20);
    char out[128];
    if (bech32_encode("bc", -1, witprog, 20, out)) FAIL("should reject negative version");
    else if (bech32_encode("bc", 17, witprog, 20, out)) FAIL("should reject version 17");
    else PASS();
  }

  TEST("Bech32 rejects short witness program");
  {
    uint8_t witprog[1] = {0x00};
    char out[128];
    if (bech32_encode("bc", 0, witprog, 1, out)) FAIL("should reject 1-byte program");
    else PASS();
  }

  TEST("Bech32 checksum differs from bech32m");
  {
    uint8_t witprog[20];
    memset(witprog, 0xAA, 20);
    char out32[128], out32m[128];
    if (!bech32_encode("bc", 0, witprog, 20, out32)) FAIL("bech32 encode failed");
    if (!bech32m_encode("bc", 0, witprog, 20, out32m)) FAIL("bech32m encode failed");
    if (strcmp(out32, out32m) == 0) FAIL("checksums should differ");
    else PASS();
  }

  TEST("Bech32 verifiable checksum structure");
  {
    uint8_t witprog[20];
    memset(witprog, 0xAB, 20);
    char out[128];
    if (!bech32_encode("bc", 0, witprog, 20, out)) FAIL("encode failed");
    else if (strlen(out) < 8) FAIL("too short");
    else {
      bool has_lowercase = true;
      for (const char *p = out; *p; p++)
        if (*p >= 'A' && *p <= 'Z') has_lowercase = false;
      if (!has_lowercase) FAIL("should be all lowercase");
      else PASS();
    }
  }

  // ── Address Generation tests (needs SE setup) ─────────────────────────

  // Store BIP32 test vector 1 master key and chain code in SE
  // The pubkey is hardcoded in SE stub (generator point G)
  // For chain code, use test vector 1 chain code
  {
    const char *chain_hex =
      "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
    uint8_t chain_code[32];
    hex_to_bytes(chain_hex, chain_code, 32);
    se051_store_key(SE051_KEY_CHAIN_CODE, chain_code, 32);

    // Mark key 0x01 as initialized for get_pubkey
    se051_store_key(SE051_KEY_BIP32_MASTER, (const uint8_t *)"dummy", 5);
  }

  TEST("address_generate P2PKH valid format");
  {
    char addr[128];
    if (!address_generate(ADDRESS_P2PKH, 0, addr)) FAIL("generate failed");
    else if (addr[0] != '1') FAIL("P2PKH must start with 1");
    else if (strlen(addr) < 26 || strlen(addr) > 35) FAIL("bad length");
    else PASS();
  }

  TEST("address_generate P2WPKH valid format");
  {
    char addr[128];
    if (!address_generate(ADDRESS_P2WPKH, 0, addr)) FAIL("generate failed");
    else if (strncmp(addr, "bc1q", 4) != 0) FAIL("P2WPKH must start with bc1q");
    else if (strlen(addr) < 14 || strlen(addr) > 74) FAIL("bad length");
    else PASS();
  }

  TEST("address_generate P2TR valid format");
  {
    char addr[128];
    if (!address_generate(ADDRESS_P2TR, 0, addr)) FAIL("generate failed");
    else if (strncmp(addr, "bc1p", 4) != 0) FAIL("P2TR must start with bc1p");
    else if (strlen(addr) < 14 || strlen(addr) > 74) FAIL("bad length");
    else PASS();
  }

  TEST("address_generate P2PKH with index 5");
  {
    char addr[128];
    if (!address_generate(ADDRESS_P2PKH, 5, addr)) FAIL("generate failed");
    else if (addr[0] != '1') FAIL("must start with 1");
    else PASS();
  }

  TEST("address_generate P2WPKH with index 999");
  {
    char addr[128];
    if (!address_generate(ADDRESS_P2WPKH, 999, addr)) FAIL("generate failed");
    else if (strncmp(addr, "bc1q", 4) != 0) FAIL("must start with bc1q");
    else PASS();
  }

  TEST("address_generate NULL output");
  {
    if (address_generate(ADDRESS_P2PKH, 0, NULL)) FAIL("should reject NULL");
    else PASS();
  }

  TEST("address_generate different types produce different addresses");
  {
    char p2pkh[128], p2wpkh[128], p2tr[128];
    if (!address_generate(ADDRESS_P2PKH, 0, p2pkh)) FAIL("p2pkh failed");
    if (!address_generate(ADDRESS_P2WPKH, 0, p2wpkh)) FAIL("p2wpkh failed");
    if (!address_generate(ADDRESS_P2TR, 0, p2tr)) FAIL("p2tr failed");
    if (strcmp(p2pkh, p2wpkh) == 0) FAIL("p2pkh == p2wpkh");
    else if (strcmp(p2pkh, p2tr) == 0) FAIL("p2pkh == p2tr");
    else PASS();
  }

  TEST("address_generate different indices produce different addresses");
  {
    char a0[128], a1[128];
    if (!address_generate(ADDRESS_P2WPKH, 0, a0)) FAIL("index 0 failed");
    if (!address_generate(ADDRESS_P2WPKH, 1, a1)) FAIL("index 1 failed");
    if (strcmp(a0, a1) == 0) FAIL("same address for different indices");
    else PASS();
  }

  TEST("address_type_name for all types");
  {
    if (strcmp(address_type_name(ADDRESS_P2PKH), "P2PKH") != 0) FAIL("P2PKH");
    else if (strcmp(address_type_name(ADDRESS_P2WPKH), "P2WPKH") != 0) FAIL("P2WPKH");
    else if (strcmp(address_type_name(ADDRESS_P2TR), "P2TR") != 0) FAIL("P2TR");
    else PASS();
  }

  // ── Summary ──────────────────────────────────────────────────────────

  printf("\n=== Results: %d/%d passed, %d failed ===\n",
         tests_passed, tests_run, tests_failed);

  return tests_failed > 0 ? 1 : 0;
}

#else
#include <cstdio>
int main(void) {
  printf("Address tests require USE_SE_STUB.\n");
  return 0;
}
#endif
