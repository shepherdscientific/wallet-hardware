#include "account_manager.h"
#include <cstdio>
#include <cstring>
#include <cassert>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
  printf("  %-50s ", name);
#define PASS() do { printf("PASS\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { FAIL("eq"); return; } } while(0)
#define ASSERT_TRUE(x) do { if (!(x)) { FAIL("true"); return; } } while(0)
#define ASSERT_FALSE(x) do { if (x) { FAIL("false"); return; } } while(0)

void test_init_defaults() {
    TEST("init sets active account to 0");
    account_init();
    ASSERT_EQ(account_get_active(), 0u);
    PASS();
}

void test_set_get_active() {
    TEST("set and get active account");
    account_set_active(3);
    ASSERT_EQ(account_get_active(), 3u);
    account_set_active(0);
    ASSERT_EQ(account_get_active(), 0u);
    PASS();
}

void test_active_clamp() {
    TEST("active account clamped below MAX_ACCOUNTS");
    account_set_active(5);
    ASSERT_EQ(account_get_active(), 5u);
    account_set_active(0);
    PASS();
}

void test_address_index_default() {
    TEST("address index defaults to 0");
    uint32_t idx = 99;
    account_init();
    account_get_address_index(0, &idx);
    ASSERT_EQ(idx, 0u);
    PASS();
}

void test_address_index_per_account() {
    TEST("per-account address indices are independent");
    account_init();
    account_increment_address_index(0);
    account_increment_address_index(0);
    account_increment_address_index(1);
    uint32_t i0 = 99, i1 = 99;
    account_get_address_index(0, &i0);
    account_get_address_index(1, &i1);
    ASSERT_EQ(i0, 2u);
    ASSERT_EQ(i1, 1u);
    PASS();
}

void test_address_index_increment() {
    TEST("address index increments correctly");
    account_init();
    for (int i = 0; i < 5; i++) account_increment_address_index(0);
    uint32_t idx = 99;
    account_get_address_index(0, &idx);
    ASSERT_EQ(idx, 5u);
    PASS();
}

void test_name_default_empty() {
    TEST("account name defaults to empty");
    char buf[ACCOUNT_NAME_LEN];
    account_init();
    ASSERT_FALSE(account_get_name(0, buf, sizeof(buf)));
    PASS();
}

void test_name_set_get() {
    TEST("account name set and get round-trip");
    char buf[ACCOUNT_NAME_LEN];
    account_set_name(2, "Sav");
    ASSERT_TRUE(account_get_name(2, buf, sizeof(buf)));
    ASSERT_EQ(strcmp(buf, "Sav"), 0);
    PASS();
}

void test_name_truncation() {
    TEST("account name truncated at 6 chars");
    char buf[ACCOUNT_NAME_LEN];
    account_set_name(0, "123456789");
    ASSERT_TRUE(account_get_name(0, buf, sizeof(buf)));
    ASSERT_EQ(strlen(buf), 6u);
    PASS();
}

void test_active_account_out_of_range() {
    TEST("set_active rejects out-of-range account");
    account_init();
    account_set_active(0);
    account_set_active(MAX_ACCOUNTS);
    ASSERT_EQ(account_get_active(), 0u);
    PASS();
}

void test_address_index_null_safety() {
    TEST("get_address_index NULL pointer safe");
    account_get_address_index(0, NULL);
    PASS();
}

void test_address_index_out_of_range() {
    TEST("address index ignores out-of-range account");
    account_init();
    account_increment_address_index(99);
    uint32_t idx = 99;
    account_get_address_index(0, &idx);
    ASSERT_EQ(idx, 0u);
    PASS();
}

int main() {
    printf("=== account_manager tests ===\n\n");
    test_init_defaults();
    test_set_get_active();
    test_active_clamp();
    test_address_index_default();
    test_address_index_per_account();
    test_address_index_increment();
    test_name_default_empty();
    test_name_set_get();
    test_name_truncation();
    test_active_account_out_of_range();
    test_address_index_null_safety();
    test_address_index_out_of_range();

    printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
