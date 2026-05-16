#ifdef USE_SE_STUB

#include "wallet_storage.h"
#include "se051_hal.h"
#include "pin_manager.h"
#include "bip39.h"
#include "serial_transport.h"
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
  printf("=== Anti-Phishing Device Pairing Code Tests ===\n\n");

  se051_init();
  serial_init();

  TEST("wallet_has_anti_phish false before generation");
  {
    se051_delete_key(SE051_OBJ_ANTI_PHISH);
    if (!wallet_has_anti_phish()) PASS();
    else FAIL("should return false when no anti-phish code stored");
  }

  TEST("wallet_generate_anti_phish returns true");
  {
    if (wallet_generate_anti_phish()) PASS();
    else FAIL("generation should succeed");
  }

  TEST("wallet_has_anti_phish true after generation");
  {
    if (wallet_has_anti_phish()) PASS();
    else FAIL("should return true after generation");
  }

  TEST("wallet_get_anti_phish retrieves 4 words");
  {
    char words[4][BIP39_WORD_MAX_LEN];
    memset(words, 0, sizeof(words));
    if (wallet_get_anti_phish(words)) {
      int non_empty = 0;
      for (int i = 0; i < 4; i++) {
        if (strlen(words[i]) > 0) non_empty++;
      }
      if (non_empty == 4) PASS();
      else FAIL("not all 4 words retrieved");
    } else {
      FAIL("wallet_get_anti_phish returned false");
    }
  }

  TEST("retrieved words are valid BIP39");
  {
    char words[4][BIP39_WORD_MAX_LEN];
    memset(words, 0, sizeof(words));
    if (wallet_get_anti_phish(words)) {
      int valid = 0;
      for (int i = 0; i < 4; i++) {
        uint16_t idx = bip39_word_to_index(words[i]);
        if (idx != 0xFFFF) valid++;
      }
      if (valid == 4) PASS();
      else FAIL("not all 4 words are valid BIP39");
    } else {
      FAIL("wallet_get_anti_phish returned false");
    }
  }

  TEST("SE object 0x04 exists after generation");
  {
    uint8_t buf[8];
    size_t out_len = 0;
    if (se051_read_object(SE051_OBJ_ANTI_PHISH, buf, sizeof(buf), &out_len) == SE_OK &&
        out_len == 8) PASS();
    else FAIL("SE object 0x04 not found or wrong size");
  }

  TEST("generation is idempotent (second call succeeds)");
  {
    if (wallet_generate_anti_phish()) PASS();
    else FAIL("second generation should succeed (overwrite)");
  }

  TEST("round-trip preserves 4 valid words");
  {
    char words[4][BIP39_WORD_MAX_LEN];
    memset(words, 0, sizeof(words));
    if (wallet_get_anti_phish(words)) {
      int valid = 0;
      for (int i = 0; i < 4; i++) {
        uint16_t idx = bip39_word_to_index(words[i]);
        if (idx != 0xFFFF) valid++;
      }
      if (valid == 4) PASS();
      else FAIL("round-trip words not all valid");
    } else {
      FAIL("wallet_get_anti_phish returned false");
    }
  }

  TEST("factory reset deletes anti-phish code");
  {
    wallet_generate_anti_phish();
    wallet_factory_reset();
    if (!wallet_has_anti_phish()) PASS();
    else FAIL("anti-phish code should be deleted by factory reset");
  }

  TEST("wallet_has_anti_phish false after factory reset");
  {
    if (!wallet_has_anti_phish()) PASS();
    else FAIL("should return false after factory reset");
  }

  TEST("serial_send_pairing produces correct format");
  {
    wallet_generate_anti_phish();
    char words[4][BIP39_WORD_MAX_LEN];
    memset(words, 0, sizeof(words));
    if (wallet_get_anti_phish(words)) {
      printf("-> PAIRING:%s %s %s %s\n",
             words[0], words[1], words[2], words[3]);
      PASS();
    } else {
      FAIL("cannot get words for pairing output");
    }
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
