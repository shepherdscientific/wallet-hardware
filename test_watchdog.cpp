#include "watchdog.h"
#include <string.h>
#include <stdio.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
  printf("  %s ... ", (name)); fflush(stdout); \
} while(0)

#define PASS() do { \
  printf("PASS\n"); fflush(stdout); tests_passed++; \
} while(0)

#define FAIL(msg) do { \
  printf("FAIL: %s\n", (msg)); fflush(stdout); tests_failed++; \
} while(0)

#define ASSERT_EQ(a, b, msg) do { \
  if ((a) != (b)) { FAIL(msg); return; } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
  if (!(cond)) { FAIL(msg); return; } \
} while(0)

static void test_init_clears_signing(void) {
  TEST("init clears signing_active");
  watchdog_set_signing_active(true);
  ASSERT_TRUE(watchdog_is_signing_active(), "should be active before init");
  watchdog_init();
  ASSERT_TRUE(!watchdog_is_signing_active(), "should be cleared after init");
  PASS();
}

static void test_signing_active_set_clear(void) {
  TEST("set/clear signing_active flag");
  watchdog_init();
  watchdog_set_signing_active(true);
  ASSERT_TRUE(watchdog_is_signing_active(), "should be active");
  watchdog_set_signing_active(false);
  ASSERT_TRUE(!watchdog_is_signing_active(), "should be cleared");
  PASS();
}

static void test_clear_signing_active(void) {
  TEST("clear_signing_active works");
  watchdog_init();
  watchdog_set_signing_active(true);
  ASSERT_TRUE(watchdog_is_signing_active(), "should be active");
  watchdog_clear_signing_active();
  ASSERT_TRUE(!watchdog_is_signing_active(), "should be cleared");
  PASS();
}

static void test_no_crash_after_init(void) {
  TEST("no crash log after fresh init");
  watchdog_init();
  ASSERT_TRUE(watchdog_get_last_crash() == nullptr, "should be null after clean init");
  PASS();
}

static void test_not_wdt_reset_after_init(void) {
  TEST("not WDT reset after fresh init");
  watchdog_init();
  ASSERT_TRUE(!watchdog_last_reset_was_wdt(), "should not be WDT reset");
  PASS();
}

static void test_feed_is_noop_stub(void) {
  TEST("watchdog_feed is noop in stub mode");
  watchdog_init();
  watchdog_feed();
  PASS();
}

static void test_multiple_signing_active_toggle(void) {
  TEST("multiple toggle of signing_active");
  watchdog_init();
  for (int i = 0; i < 5; i++) {
    watchdog_set_signing_active(true);
    ASSERT_TRUE(watchdog_is_signing_active(), "should be active");
    watchdog_set_signing_active(false);
    ASSERT_TRUE(!watchdog_is_signing_active(), "should not be active");
  }
  PASS();
}

int main(void) {
  printf("\n=== Watchdog Module Tests ===\n\n");

  test_init_clears_signing();
  test_signing_active_set_clear();
  test_clear_signing_active();
  test_no_crash_after_init();
  test_not_wdt_reset_after_init();
  test_feed_is_noop_stub();
  test_multiple_signing_active_toggle();

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);
  return tests_failed ? 1 : 0;
}
