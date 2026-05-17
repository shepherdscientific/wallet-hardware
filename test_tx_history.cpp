#include "tx_history.h"
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

static void test_no_cache_after_init(void) {
  TEST("no cache after init");
  tx_history_init();
  ASSERT_FALSE(tx_history_has_cached(), "has_cached should be false");
  ASSERT_EQ(tx_history_get_count(), (uint8_t)0, "count should be 0");
  PASS();
}

static void test_add_get_single(void) {
  TEST("add and get single entry");
  tx_history_nvs_erase();
  tx_history_init();
  uint8_t txid[32];
  for (int i = 0; i < 32; i++) txid[i] = (uint8_t)i;
  tx_history_add_entry(txid, '+', 100000000ULL, 6);
  ASSERT_TRUE(tx_history_has_cached(), "should have cached");
  ASSERT_EQ(tx_history_get_count(), (uint8_t)1, "count should be 1");
  tx_history_entry_t entry;
  ASSERT_TRUE(tx_history_get_entry(0, &entry), "get_entry should succeed");
  ASSERT_EQ(memcmp(entry.txid, txid, 32), 0, "txid mismatch");
  ASSERT_EQ(entry.direction, '+', "direction mismatch");
  ASSERT_EQ(entry.amount_sats, 100000000ULL, "amount mismatch");
  ASSERT_EQ(entry.confirmations, (uint32_t)6, "confirmations mismatch");
  PASS();
}

static void test_add_get_sent(void) {
  TEST("sent transaction entry");
  tx_history_nvs_erase();
  tx_history_init();
  uint8_t txid[32];
  memset(txid, 0xAB, 32);
  tx_history_add_entry(txid, '-', 50000000ULL, 42);
  tx_history_entry_t entry;
  ASSERT_TRUE(tx_history_get_entry(0, &entry), "get_entry should succeed");
  ASSERT_EQ(entry.direction, '-', "direction should be -");
  ASSERT_EQ(entry.amount_sats, 50000000ULL, "amount mismatch");
  PASS();
}

static void test_zero_confirmations(void) {
  TEST("zero confirmations entry");
  tx_history_nvs_erase();
  tx_history_init();
  uint8_t txid[32];
  memset(txid, 0xCC, 32);
  tx_history_add_entry(txid, '+', 200000000ULL, 0);
  tx_history_entry_t entry;
  ASSERT_TRUE(tx_history_get_entry(0, &entry), "get_entry should succeed");
  ASSERT_EQ(entry.confirmations, (uint32_t)0, "confirmations should be 0");
  PASS();
}

static void test_100_plus_confirmations(void) {
  TEST("100+ confirmations");
  tx_history_nvs_erase();
  tx_history_init();
  uint8_t txid[32];
  memset(txid, 0xDD, 32);
  tx_history_add_entry(txid, '+', 10000000ULL, 150);
  tx_history_entry_t entry;
  ASSERT_TRUE(tx_history_get_entry(0, &entry), "get_entry should succeed");
  ASSERT_EQ(entry.confirmations, (uint32_t)150, "confirmations should be 150");
  PASS();
}

static void test_lru_eviction(void) {
  TEST("LRU eviction at max capacity");
  tx_history_nvs_erase();
  tx_history_init();
  for (int i = 0; i < 12; i++) {
    uint8_t txid[32];
    memset(txid, (uint8_t)i, 32);
    tx_history_add_entry(txid, '+', (uint64_t)(i * 1000), (uint32_t)i);
  }
  ASSERT_EQ(tx_history_get_count(), (uint8_t)10, "count should be 10");
  tx_history_entry_t entry;
  ASSERT_TRUE(tx_history_get_entry(0, &entry), "first entry should exist");
  ASSERT_EQ(entry.amount_sats, (uint64_t)2000, "first should be entry 2 after LRU shift");
  ASSERT_TRUE(tx_history_get_entry(9, &entry), "last entry should exist");
  ASSERT_EQ(entry.amount_sats, (uint64_t)11000, "last should be entry 11");
  PASS();
}

static void test_get_null_entry(void) {
  TEST("get_entry with NULL pointer");
  tx_history_nvs_erase();
  tx_history_init();
  uint8_t txid[32];
  memset(txid, 0xEE, 32);
  tx_history_add_entry(txid, '+', 1000, 1);
  ASSERT_FALSE(tx_history_get_entry(0, NULL), "NULL entry should return false");
  PASS();
}

static void test_get_out_of_bounds(void) {
  TEST("get_entry out of bounds");
  tx_history_nvs_erase();
  tx_history_init();
  uint8_t txid[32];
  memset(txid, 0xFF, 32);
  tx_history_add_entry(txid, '+', 1, 1);
  tx_history_entry_t entry;
  ASSERT_FALSE(tx_history_get_entry(5, &entry), "out of bounds should fail");
  ASSERT_FALSE(tx_history_get_entry(255, &entry), "large index should fail");
  PASS();
}

static void test_erase(void) {
  TEST("erase clears all entries");
  tx_history_nvs_erase();
  tx_history_init();
  uint8_t txid[32];
  for (int i = 0; i < 5; i++) {
    memset(txid, (uint8_t)i, 32);
    tx_history_add_entry(txid, '+', (uint64_t)i, (uint32_t)i);
  }
  ASSERT_EQ(tx_history_get_count(), (uint8_t)5, "should have 5 entries");
  tx_history_nvs_erase();
  ASSERT_FALSE(tx_history_has_cached(), "should be empty after erase");
  ASSERT_EQ(tx_history_get_count(), (uint8_t)0, "count should be 0 after erase");
  PASS();
}

static void test_erase_reinit_add(void) {
  TEST("erase then re-add");
  tx_history_nvs_erase();
  tx_history_init();
  uint8_t txid[32];
  memset(txid, 0x11, 32);
  tx_history_add_entry(txid, '-', 999, 3);
  tx_history_nvs_erase();
  tx_history_init();
  memset(txid, 0x22, 32);
  tx_history_add_entry(txid, '+', 888, 5);
  ASSERT_EQ(tx_history_get_count(), (uint8_t)1, "count should be 1 after re-add");
  tx_history_entry_t entry;
  ASSERT_TRUE(tx_history_get_entry(0, &entry), "get_entry should succeed");
  ASSERT_EQ(entry.amount_sats, (uint64_t)888, "should be new entry");
  PASS();
}

static void test_large_values(void) {
  TEST("large uint64 and uint32 values");
  tx_history_nvs_erase();
  tx_history_init();
  uint8_t txid[32];
  memset(txid, 0x99, 32);
  uint64_t big_amount = 18446744073709551615ULL;
  uint32_t big_conf = 4294967295UL;
  tx_history_add_entry(txid, '+', big_amount, big_conf);
  tx_history_entry_t entry;
  ASSERT_TRUE(tx_history_get_entry(0, &entry), "get_entry should succeed");
  ASSERT_EQ(entry.amount_sats, big_amount, "large amount preserved");
  ASSERT_EQ(entry.confirmations, big_conf, "large confirmations preserved");
  PASS();
}

int main(void) {
  printf("=== TX History Tests ===\n\n");

  test_no_cache_after_init();
  test_add_get_single();
  test_add_get_sent();
  test_zero_confirmations();
  test_100_plus_confirmations();
  test_lru_eviction();
  test_get_null_entry();
  test_get_out_of_bounds();
  test_erase();
  test_erase_reinit_add();
  test_large_values();

  printf("\n=== Results: %d passed, %d failed ===\n",
         tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
