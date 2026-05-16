#include "settings.h"
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

static void test_defaults_after_init(void) {
  TEST("defaults after init");
  settings_init();
  ASSERT_EQ(settings_get_display_timeout(), SETTINGS_DISP_TIMEOUT_30S, "default disp timeout");
  ASSERT_EQ(settings_get_auto_lock(), SETTINGS_AUTOLOCK_1M, "default auto lock");
  ASSERT_EQ(settings_get_contrast(), SETTINGS_CONTRAST_DEFAULT, "default contrast");
  PASS();
}

static void test_set_get_display_timeout(void) {
  TEST("set/get display timeout");
  settings_init();
  settings_set_display_timeout(SETTINGS_DISP_TIMEOUT_2M);
  ASSERT_EQ(settings_get_display_timeout(), SETTINGS_DISP_TIMEOUT_2M, "set 2m");
  settings_set_display_timeout(SETTINGS_DISP_TIMEOUT_NEVER);
  ASSERT_EQ(settings_get_display_timeout(), SETTINGS_DISP_TIMEOUT_NEVER, "set never");
  settings_set_display_timeout(SETTINGS_DISP_TIMEOUT_1M);
  ASSERT_EQ(settings_get_display_timeout(), SETTINGS_DISP_TIMEOUT_1M, "set 1m");
  PASS();
}

static void test_set_get_auto_lock(void) {
  TEST("set/get auto lock");
  settings_init();
  settings_set_auto_lock(SETTINGS_AUTOLOCK_15M);
  ASSERT_EQ(settings_get_auto_lock(), SETTINGS_AUTOLOCK_15M, "set 15m");
  settings_set_auto_lock(SETTINGS_AUTOLOCK_NEVER);
  ASSERT_EQ(settings_get_auto_lock(), SETTINGS_AUTOLOCK_NEVER, "set never");
  PASS();
}

static void test_set_get_contrast(void) {
  TEST("set/get contrast");
  settings_init();
  settings_set_contrast(64);
  ASSERT_EQ(settings_get_contrast(), 64, "set 64");
  settings_set_contrast(255);
  ASSERT_EQ(settings_get_contrast(), 255, "set 255");
  settings_set_contrast(0);
  ASSERT_EQ(settings_get_contrast(), 0, "set 0");
  PASS();
}

static void test_disp_timeout_ms(void) {
  TEST("disp timeout ms");
  ASSERT_EQ(settings_disp_timeout_ms(SETTINGS_DISP_TIMEOUT_30S), 30000, "30s");
  ASSERT_EQ(settings_disp_timeout_ms(SETTINGS_DISP_TIMEOUT_1M), 60000, "1m");
  ASSERT_EQ(settings_disp_timeout_ms(SETTINGS_DISP_TIMEOUT_2M), 120000, "2m");
  ASSERT_EQ(settings_disp_timeout_ms(SETTINGS_DISP_TIMEOUT_5M), 300000, "5m");
  ASSERT_EQ(settings_disp_timeout_ms(SETTINGS_DISP_TIMEOUT_NEVER), 0, "never");
  PASS();
}

static void test_auto_lock_ms(void) {
  TEST("auto lock ms");
  ASSERT_EQ(settings_auto_lock_ms(SETTINGS_AUTOLOCK_1M), 60000, "1m");
  ASSERT_EQ(settings_auto_lock_ms(SETTINGS_AUTOLOCK_5M), 300000, "5m");
  ASSERT_EQ(settings_auto_lock_ms(SETTINGS_AUTOLOCK_15M), 900000, "15m");
  ASSERT_EQ(settings_auto_lock_ms(SETTINGS_AUTOLOCK_30M), 1800000, "30m");
  ASSERT_EQ(settings_auto_lock_ms(SETTINGS_AUTOLOCK_NEVER), 0, "never");
  PASS();
}

static void test_labels(void) {
  TEST("timeout labels");
  ASSERT_TRUE(strcmp(settings_disp_timeout_label(SETTINGS_DISP_TIMEOUT_30S), "30s") == 0, "30s label");
  ASSERT_TRUE(strcmp(settings_disp_timeout_label(SETTINGS_DISP_TIMEOUT_NEVER), "Never") == 0, "never label");
  ASSERT_TRUE(strcmp(settings_auto_lock_label(SETTINGS_AUTOLOCK_30M), "30m") == 0, "30m label");
  PASS();
}

static void test_out_of_range_clamp(void) {
  TEST("out of range clamp");
  settings_init();
  settings_set_display_timeout(99);
  ASSERT_EQ(settings_get_display_timeout(), SETTINGS_DISP_TIMEOUT_30S, "clamped disp timeout");
  settings_set_auto_lock(99);
  ASSERT_EQ(settings_get_auto_lock(), SETTINGS_AUTOLOCK_1M, "clamped auto lock");
  PASS();
}

static void test_contrast_wraps(void) {
  TEST("contrast full range");
  settings_init();
  for (int v = 0; v <= 255; v += 32) {
    settings_set_contrast((uint8_t)v);
    ASSERT_EQ(settings_get_contrast(), (uint8_t)v, "contrast step");
  }
  PASS();
}

static void test_persistence_roundtrip(void) {
  TEST("persistence roundtrip");
  settings_init();
  settings_set_display_timeout(SETTINGS_DISP_TIMEOUT_5M);
  settings_set_auto_lock(SETTINGS_AUTOLOCK_30M);
  settings_set_contrast(192);
  ASSERT_EQ(settings_get_display_timeout(), SETTINGS_DISP_TIMEOUT_5M, "read disp");
  ASSERT_EQ(settings_get_auto_lock(), SETTINGS_AUTOLOCK_30M, "read lock");
  ASSERT_EQ(settings_get_contrast(), 192, "read contrast");
  PASS();
}

int main(void) {
  printf("=== Settings Module Tests ===\n");

  test_defaults_after_init();
  test_set_get_display_timeout();
  test_set_get_auto_lock();
  test_set_get_contrast();
  test_disp_timeout_ms();
  test_auto_lock_ms();
  test_labels();
  test_out_of_range_clamp();
  test_contrast_wraps();
  test_persistence_roundtrip();

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
