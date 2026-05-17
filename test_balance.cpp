#include "balance.h"
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

#define ASSERT_FALSE(cond, msg) do { \
  if (cond) { FAIL(msg); return; } \
} while(0)

#define ASSERT_STR_EQ(a, b, msg) do { \
  if (strcmp((a), (b)) != 0) { FAIL(msg); return; } \
} while(0)

static void test_no_cache_after_init(void) {
  TEST("no cache after init");
  balance_init();
  ASSERT_FALSE(balance_has_cached(), "has_cached should be false");
  uint64_t c = 999, u = 999;
  ASSERT_FALSE(balance_get_cached(&c, &u), "get_cached should return false");
  PASS();
}

static void test_set_get_roundtrip(void) {
  TEST("set/get roundtrip");
  balance_init();
  balance_set_cached(100000000, 50000000);
  ASSERT_TRUE(balance_has_cached(), "should have cached");
  uint64_t c = 0, u = 0;
  ASSERT_TRUE(balance_get_cached(&c, &u), "get_cached should return true");
  ASSERT_EQ(c, 100000000ULL, "confirmed mismatch");
  ASSERT_EQ(u, 50000000ULL, "unconfirmed mismatch");
  PASS();
}

static void test_get_with_null(void) {
  TEST("get_cached with NULL pointers");
  balance_init();
  balance_set_cached(42, 7);
  ASSERT_TRUE(balance_get_cached(NULL, NULL), "null pointers should work");
  uint64_t u = 999;
  ASSERT_TRUE(balance_get_cached(NULL, &u), "null conf should work");
  ASSERT_EQ(u, 7ULL, "unconf should be 7");
  uint64_t c = 999;
  ASSERT_TRUE(balance_get_cached(&c, NULL), "null unconf should work");
  ASSERT_EQ(c, 42ULL, "conf should be 42");
  PASS();
}

static void test_erase(void) {
  TEST("erase clears cache");
  balance_init();
  balance_set_cached(123, 456);
  ASSERT_TRUE(balance_has_cached(), "should have cached before erase");
  balance_nvs_erase();
  ASSERT_FALSE(balance_has_cached(), "has_cached after erase");
  uint64_t c = 999, u = 999;
  ASSERT_FALSE(balance_get_cached(&c, &u), "get after erase");
  PASS();
}

static void test_last_sync(void) {
  TEST("last sync timestamp");
  balance_init();
  balance_set_cached(100, 0);
  ASSERT_TRUE(balance_has_cached(), "should have cached");
  char buf[32];
  ASSERT_TRUE(balance_get_last_sync(buf, sizeof(buf)), "get_last_sync");
  ASSERT_TRUE(strlen(buf) > 0, "buffer should be nonempty");
  PASS();
}

static void test_last_sync_no_cache(void) {
  TEST("last sync without cache");
  balance_init();
  ASSERT_FALSE(balance_has_cached(), "no cache");
  char buf[32] = "unchanged";
  ASSERT_FALSE(balance_get_last_sync(buf, sizeof(buf)), "get_last_sync should fail");
  ASSERT_STR_EQ(buf, "", "buffer should be empty");
  PASS();
}

static void test_last_sync_null_buf(void) {
  TEST("last sync with null buffer");
  balance_init();
  balance_set_cached(1, 0);
  ASSERT_FALSE(balance_get_last_sync(NULL, 32), "null buf should return false");
  char buf[32];
  ASSERT_FALSE(balance_get_last_sync(buf, 0), "zero len should return false");
  PASS();
}

static void test_large_values(void) {
  TEST("large uint64 values");
  balance_init();
  uint64_t big = 18446744073709551615ULL;
  balance_set_cached(big, big / 2);
  uint64_t c = 0, u = 0;
  ASSERT_TRUE(balance_get_cached(&c, &u), "get large");
  ASSERT_EQ(c, big, "large confirmed");
  ASSERT_EQ(u, big / 2, "large unconfirmed");
  PASS();
}

static void test_zero_values(void) {
  TEST("zero values");
  balance_init();
  balance_set_cached(0, 0);
  ASSERT_TRUE(balance_has_cached(), "zero should be cached");
  uint64_t c = 999, u = 999;
  ASSERT_TRUE(balance_get_cached(&c, &u), "get zeros");
  ASSERT_EQ(c, 0ULL, "confirmed should be 0");
  ASSERT_EQ(u, 0ULL, "unconfirmed should be 0");
  PASS();
}

static void test_overwrite(void) {
  TEST("overwrite cache");
  balance_init();
  balance_set_cached(100, 50);
  uint64_t c, u;
  balance_get_cached(&c, &u);
  ASSERT_EQ(c, 100ULL, "first conf");
  balance_set_cached(200, 75);
  balance_get_cached(&c, &u);
  ASSERT_EQ(c, 200ULL, "overwrite conf");
  ASSERT_EQ(u, 75ULL, "overwrite unconf");
  PASS();
}

static void test_unconfirmed_isolated(void) {
  TEST("unconfirmed value isolated");
  balance_init();
  balance_set_cached(1000, 500);
  uint64_t c = 0, u = 0;
  balance_get_cached(&c, &u);
  ASSERT_EQ(c, 1000ULL, "conf value");
  ASSERT_EQ(u, 500ULL, "unconf value");
  balance_set_cached(1000, 0);
  balance_get_cached(&c, &u);
  ASSERT_EQ(c, 1000ULL, "conf after clearing unconf");
  ASSERT_EQ(u, 0ULL, "unconf cleared");
  PASS();
}

int main(void) {
  printf("=== Balance Tests ===\n\n");

  test_no_cache_after_init();
  test_set_get_roundtrip();
  test_get_with_null();
  test_erase();
  test_last_sync();
  test_last_sync_no_cache();
  test_last_sync_null_buf();
  test_large_values();
  test_zero_values();
  test_overwrite();
  test_unconfirmed_isolated();

  printf("\n=== Results: %d passed, %d failed ===\n",
         tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
