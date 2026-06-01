#include "bip39.h"
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

static void test_prefix_match_basic(void) {
  TEST("prefix 'sta' returns stable/stadium/staff");
  uint16_t indices[3];
  uint8_t count = bip39_prefix_match("sta", indices, 3);
  ASSERT_EQ(count, 3, "should return 3 matches");
  ASSERT_STR_EQ(bip39_wordlist[indices[0]], "stable", "first match");
  ASSERT_STR_EQ(bip39_wordlist[indices[1]], "stadium", "second match");
  ASSERT_STR_EQ(bip39_wordlist[indices[2]], "staff", "third match");
  PASS();
}

static void test_prefix_match_empty(void) {
  TEST("empty prefix returns 0");
  uint16_t indices[3];
  uint8_t count = bip39_prefix_match("", indices, 3);
  ASSERT_EQ(count, 0, "empty prefix should return 0");
  PASS();
}

static void test_prefix_match_null_prefix(void) {
  TEST("NULL prefix returns 0");
  uint16_t indices[3];
  uint8_t count = bip39_prefix_match(NULL, indices, 3);
  ASSERT_EQ(count, 0, "NULL prefix should return 0");
  PASS();
}

static void test_prefix_match_null_indices(void) {
  TEST("NULL indices returns 0");
  uint8_t count = bip39_prefix_match("aba", NULL, 3);
  ASSERT_EQ(count, 0, "NULL indices should return 0");
  PASS();
}

static void test_prefix_match_zero_max(void) {
  TEST("max_results=0 returns 0");
  uint16_t indices[3];
  uint8_t count = bip39_prefix_match("aba", indices, 0);
  ASSERT_EQ(count, 0, "max_results=0 should return 0");
  PASS();
}

static void test_prefix_match_max_clipping(void) {
  TEST("max_results=1 clips to 1");
  uint16_t indices[3];
  uint8_t count = bip39_prefix_match("aba", indices, 1);
  ASSERT_EQ(count, 1, "should return 1 match");
  ASSERT_STR_EQ(bip39_wordlist[indices[0]], "abandon", "first match is abandon");
  PASS();
}

static void test_prefix_match_single_result(void) {
  TEST("prefix 'abou' returns exactly 1 match (about)");
  uint16_t indices[3];
  uint8_t count = bip39_prefix_match("abou", indices, 3);
  ASSERT_EQ(count, 1, "should return exactly 1 match");
  ASSERT_STR_EQ(bip39_wordlist[indices[0]], "about", "should be about");
  PASS();
}

static void test_prefix_match_no_match(void) {
  TEST("prefix 'zzz' returns 0");
  uint16_t indices[3];
  uint8_t count = bip39_prefix_match("zzz", indices, 3);
  ASSERT_EQ(count, 0, "no-match prefix should return 0");
  PASS();
}

static void test_prefix_match_exact_word(void) {
  TEST("exact word 'abandon' returns abandon at index 0");
  uint16_t indices[3];
  uint8_t count = bip39_prefix_match("abandon", indices, 3);
  ASSERT_EQ(count, 1, "should return exactly 1 match");
  ASSERT_STR_EQ(bip39_wordlist[indices[0]], "abandon", "should be abandon");
  PASS();
}

static void test_prefix_match_many_results(void) {
  TEST("prefix 's' returns up to max_results (3)");
  uint16_t indices[3];
  uint8_t count = bip39_prefix_match("s", indices, 3);
  ASSERT_EQ(count, 3, "should return exactly 3 (max_results clip)");
  for (uint8_t i = 0; i < 3; i++) {
    ASSERT_TRUE(bip39_wordlist[indices[i]][0] == 's', "all results start with s");
  }
  PASS();
}

static void test_prefix_match_case_sensitive(void) {
  TEST("uppercase 'STA' returns 0 (case sensitive)");
  uint16_t indices[3];
  uint8_t count = bip39_prefix_match("STA", indices, 3);
  ASSERT_EQ(count, 0, "BIP39 words are lowercase only");
  PASS();
}

int main(void) {
  printf("=== BIP39 Prefix Match Tests ===\n\n");

  test_prefix_match_basic();
  test_prefix_match_empty();
  test_prefix_match_null_prefix();
  test_prefix_match_null_indices();
  test_prefix_match_zero_max();
  test_prefix_match_max_clipping();
  test_prefix_match_single_result();
  test_prefix_match_no_match();
  test_prefix_match_exact_word();
  test_prefix_match_many_results();
  test_prefix_match_case_sensitive();

  printf("\n=== Results: %d pass, %d fail ===\n", tests_passed, tests_failed);
  return tests_failed ? 1 : 0;
}
