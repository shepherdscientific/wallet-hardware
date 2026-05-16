#ifdef USE_SE_STUB

#include "pin_manager.h"
#include "se051_hal.h"
#include "hmac_sha256.h"
#include "sha256.h"
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

static bool bytes_equal(const uint8_t *a, const uint8_t *b, size_t len) {
  return memcmp(a, b, len) == 0;
}

int main(void) {
  (void)bytes_equal;
  printf("=== Pin Manager Unit Tests ===\n\n");

  se051_init();

  TEST("HMAC-SHA256 RFC 4231 test case (key=0b0b.., msg='Hi There')");
  {
    const uint8_t key[20] = {
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
      0x0b, 0x0b, 0x0b, 0x0b
    };
    const char *msg = "Hi There";
    const uint8_t expected[32] = {
      0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53,
      0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1, 0x2b,
      0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7,
      0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32, 0xcf, 0xf7
    };
    uint8_t mac[32];
    hmac_sha256(key, 20, (const uint8_t *)msg, strlen(msg), mac);
    if (bytes_equal(mac, expected, 32)) PASS();
    else FAIL("HMAC-SHA256 RFC 4231 test case mismatch");
  }

  TEST("HMAC-SHA256 produces different MACs for different inputs");
  {
    const uint8_t key1[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    const uint8_t msg1[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    const uint8_t msg2[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    uint8_t mac1[32], mac2[32];
    hmac_sha256(key1, 8, msg1, 6, mac1);
    hmac_sha256(key1, 8, msg2, 6, mac2);
    if (memcmp(mac1, mac2, 32) != 0) PASS();
    else FAIL("different inputs produced same MAC");
  }

  TEST("pin_is_set returns false on fresh SE");
  {
    if (!pin_is_set()) PASS();
    else FAIL("should be false with no PIN stored");
  }

  TEST("pin_setup succeeds with valid 6-digit PIN");
  {
    uint8_t pin[6] = {1, 2, 3, 4, 5, 6};
    if (pin_setup(pin)) PASS();
    else FAIL("pin_setup returned false");
  }

  TEST("pin_is_set returns true after pin_setup");
  {
    if (pin_is_set()) PASS();
    else FAIL("should be true after setup");
  }

  TEST("pin_verify accepts correct PIN after setup");
  {
    uint8_t pin[6] = {1, 2, 3, 4, 5, 6};
    if (pin_verify(pin)) PASS();
    else FAIL("correct PIN rejected");
  }

  TEST("pin_verify rejects incorrect PIN");
  {
    uint8_t pin[6] = {1, 2, 3, 4, 5, 7};
    if (!pin_verify(pin)) PASS();
    else FAIL("incorrect PIN accepted");
  }

  TEST("pin_verify rejects all-different PIN");
  {
    uint8_t pin[6] = {9, 9, 9, 9, 9, 9};
    if (!pin_verify(pin)) PASS();
    else FAIL("all-different PIN accepted");
  }

  TEST("pin_change succeeds with correct old PIN");
  {
    uint8_t old_pin[6] = {1, 2, 3, 4, 5, 6};
    uint8_t new_pin[6] = {6, 5, 4, 3, 2, 1};
    if (pin_change(old_pin, new_pin)) PASS();
    else FAIL("pin_change returned false with correct old PIN");
  }

  TEST("pin_verify accepts new PIN after change");
  {
    uint8_t new_pin[6] = {6, 5, 4, 3, 2, 1};
    if (pin_verify(new_pin)) PASS();
    else FAIL("new PIN rejected after change");
  }

  TEST("pin_verify rejects old PIN after change");
  {
    uint8_t old_pin[6] = {1, 2, 3, 4, 5, 6};
    if (!pin_verify(old_pin)) PASS();
    else FAIL("old PIN still accepted after change");
  }

  TEST("pin_change fails with wrong old PIN");
  {
    uint8_t wrong_old[6] = {9, 9, 9, 9, 9, 9};
    uint8_t another_new[6] = {0, 0, 0, 0, 0, 0};
    if (!pin_change(wrong_old, another_new)) PASS();
    else FAIL("pin_change accepted wrong old PIN");
  }

  TEST("pin_reset removes PIN hash from SE");
  {
    pin_reset();
    if (!pin_is_set()) PASS();
    else FAIL("PIN still set after reset");
  }

  TEST("pin_verify returns false after pin_reset");
  {
    uint8_t pin[6] = {1, 2, 3, 4, 5, 6};
    if (!pin_verify(pin)) PASS();
    else FAIL("verify returned true after pin_reset");
  }

  TEST("pin_verify returns false when PIN not set at all");
  {
    pin_reset();
    uint8_t pin[6] = {0, 0, 0, 0, 0, 0};
    if (!pin_verify(pin)) PASS();
    else FAIL("verify should fail when no PIN is set");
  }

  TEST("pin_get_attempts returns 0 initially");
  {
    se051_monotonic_counter_reset(SE051_OBJ_PIN_COUNTER);
    uint8_t pin[6] = {7, 7, 7, 7, 7, 7};
    pin_setup(pin);
    if (pin_get_attempts() == 0) PASS();
    else FAIL("initial attempts should be 0");
  }

  TEST("pin_increment_attempts increases counter and returns true");
  {
    se051_monotonic_counter_reset(SE051_OBJ_PIN_COUNTER);
    if (pin_increment_attempts()) {
      uint8_t count = pin_get_attempts();
      if (count == 1) PASS();
      else { printf("(got %d) ", count); FAIL("attempts should be 1 after increment"); }
    } else {
      FAIL("increment should return true");
    }
  }

  TEST("pin_reset_attempts returns counter to 0");
  {
    se051_monotonic_counter_reset(SE051_OBJ_PIN_COUNTER);
    if (pin_get_attempts() == 0) PASS();
    else FAIL("attempts should be 0 after reset");
  }

  TEST("pin_attempts_remaining returns correct values");
  {
    se051_monotonic_counter_reset(SE051_OBJ_PIN_COUNTER);
    if (pin_attempts_remaining() != 5) FAIL("should be 5 with 0 attempts");
    pin_increment_attempts();
    if (pin_attempts_remaining() != 4) FAIL("should be 4 with 1 attempt");
    pin_increment_attempts();
    pin_increment_attempts();
    if (pin_attempts_remaining() != 2) FAIL("should be 2 with 3 attempts");
    pin_increment_attempts();
    pin_increment_attempts();
    if (pin_attempts_remaining() != 0) FAIL("should be 0 with 5 attempts");
    PASS();
  }

  TEST("pin_is_near_lockout detects warning threshold");
  {
    se051_monotonic_counter_reset(SE051_OBJ_PIN_COUNTER);
    if (pin_is_near_lockout()) FAIL("should not warn at 0 attempts");
    pin_increment_attempts();
    if (pin_is_near_lockout()) FAIL("should not warn at 1 attempt");
    pin_increment_attempts();
    if (pin_is_near_lockout()) FAIL("should not warn at 2 attempts");
    pin_increment_attempts();
    if (!pin_is_near_lockout()) FAIL("should warn at 3 attempts");
    pin_increment_attempts();
    if (!pin_is_near_lockout()) FAIL("should warn at 4 attempts");
    pin_increment_attempts();
    if (!pin_is_near_lockout()) FAIL("should warn at 5 attempts");
    PASS();
  }

  TEST("Monotonic counter only increases via increment");
  {
    se051_monotonic_counter_reset(SE051_OBJ_PIN_COUNTER);
    uint32_t val = 0;
    se051_monotonic_counter_get(SE051_OBJ_PIN_COUNTER, &val);
    if (val != 0) FAIL("should start at 0");
    se051_monotonic_counter_increment(SE051_OBJ_PIN_COUNTER);
    se051_monotonic_counter_get(SE051_OBJ_PIN_COUNTER, &val);
    if (val != 1) FAIL("should be 1 after first increment");
    se051_monotonic_counter_increment(SE051_OBJ_PIN_COUNTER);
    se051_monotonic_counter_get(SE051_OBJ_PIN_COUNTER, &val);
    if (val != 2) FAIL("should be 2 after second increment");
    PASS();
  }

  TEST("Multiple pin_verifys with wrong PIN don't crash");
  {
    uint8_t good_pin[6] = {7, 7, 7, 7, 7, 7};
    uint8_t bad_pin[6]  = {0, 0, 0, 0, 0, 0};
    se051_monotonic_counter_reset(SE051_OBJ_PIN_COUNTER);
    for (int i = 0; i < 5; i++) {
      pin_increment_attempts();
      bool result = pin_verify(bad_pin);
      if (result) { FAIL("bad PIN verified"); return 1; }
    }
    uint8_t count = pin_get_attempts();
    if (count != 5) { printf("(got %d) ", count); FAIL("counter should be 5 after 5 failed attempts"); return 1; }
    PASS();
  }

  TEST("NULL pin rejected by pin_setup");
  {
    if (!pin_setup(NULL)) PASS();
    else FAIL("NULL pin should be rejected");
  }

  TEST("NULL pin rejected by pin_verify");
  {
    if (!pin_verify(NULL)) PASS();
    else FAIL("NULL pin should be rejected");
  }

  TEST("wallet_factory_reset removes PIN hash");
  {
    uint8_t pin[6] = {1, 1, 1, 1, 1, 1};
    pin_setup(pin);
    wallet_factory_reset();
    if (!pin_is_set()) PASS();
    else FAIL("PIN still present after factory reset");
  }

  TEST("wallet_factory_reset removes key objects");
  {
    wallet_factory_reset();
    uint8_t pubkey[SE051_PUBKEY_COMPRESSED];
    if (se051_get_pubkey(SE051_KEY_BIP32_MASTER, pubkey) != SE_OK) PASS();
    else FAIL("master key still present after factory reset");
  }

  TEST("pin_setup with same PIN twice works (idempotent)");
  {
    wallet_factory_reset();
    uint8_t pin[6] = {3, 3, 3, 3, 3, 3};
    if (!pin_setup(pin)) { FAIL("first setup failed"); return 1; }
    if (!pin_setup(pin)) { FAIL("second setup failed"); return 1; }
    if (pin_verify(pin)) PASS();
    else FAIL("PIN not valid after double setup");
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
