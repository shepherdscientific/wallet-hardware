// Host-side unit test for fw_integrity_check_hash (US-031 acceptance test).
//
// Uses the deterministic SE stub (se051_hal_stub.cpp): se051_store_key writes
// any object id including SE051_OBJ_FW_HASH, and se051_read_object returns
// those bytes back, so we can simulate the post-provisioning scenario and
// then mutate either side to test mismatch / not-provisioned paths.
//
// Compile from repo root:
//   g++ -DUSE_SE_STUB -std=c++11 -I. se051_hal_stub.cpp fw_integrity.cpp \
//       test_fw_integrity.cpp -o test_fw_integrity
//   ./test_fw_integrity

#include "fw_integrity.h"
#include "se051_hal.h"
#include <cstdio>
#include <cstring>

#define TEST(name)        static void name(void)
#define PASS()            do { printf("  PASS: %s\n", __func__); return; } while (0)
#define FAIL(msg)         do { printf("  FAIL: %s — %s\n", __func__, msg); return; } while (0)
#define ASSERT_EQ(a, b)   do { if ((a) != (b)) FAIL("ASSERT_EQ failed"); } while (0)
#define ASSERT_TRUE(x)    do { if (!(x))        FAIL("ASSERT_TRUE failed"); } while (0)

static void fill_hash(uint8_t out[32], uint8_t pattern) {
    for (int i = 0; i < 32; i++) out[i] = (uint8_t)(pattern + i);
}

// AC: "firmware_integrity_check() returns true when computed matches stored"
TEST(test_match_returns_ok) {
    uint8_t hash[32];
    fill_hash(hash, 0x10);
    ASSERT_EQ(se051_store_key(SE051_OBJ_FW_HASH, hash, 32), SE_OK);

    ASSERT_EQ(fw_integrity_check_hash(hash), FW_INTEGRITY_OK);
    PASS();
}

// AC: "false when they differ"
TEST(test_mismatch_returns_tampered) {
    uint8_t stored[32];
    fill_hash(stored, 0x20);
    ASSERT_EQ(se051_store_key(SE051_OBJ_FW_HASH, stored, 32), SE_OK);

    uint8_t computed[32];
    fill_hash(computed, 0x20);
    computed[17] ^= 0x01;  // flip a single bit in the middle

    ASSERT_EQ(fw_integrity_check_hash(computed), FW_INTEGRITY_TAMPERED);
    PASS();
}

// AC: device "skips gracefully when SE_ERR_NOTFOUND"
TEST(test_unprovisioned_returns_not_provisioned) {
    ASSERT_EQ(se051_delete_key(SE051_OBJ_FW_HASH), SE_OK);

    uint8_t computed[32];
    fill_hash(computed, 0x30);
    ASSERT_EQ(fw_integrity_check_hash(computed), FW_INTEGRITY_NOT_PROVISIONED);
    PASS();
}

// Provisioning-then-tamper round-trip mirrors the factory flow:
// 1. PROVISION_HASH stores the expected hash via se051_store_key
// 2. A subsequent re-flash with a different binary computes a different hash
// 3. fw_integrity_check_hash flags TAMPERED
TEST(test_provisioning_roundtrip_flags_modified_firmware) {
    uint8_t original[32];
    fill_hash(original, 0xA0);
    ASSERT_EQ(se051_store_key(SE051_OBJ_FW_HASH, original, 32), SE_OK);
    ASSERT_EQ(fw_integrity_check_hash(original), FW_INTEGRITY_OK);

    uint8_t modified[32];
    fill_hash(modified, 0xA0);
    modified[0] ^= 0xFF;
    ASSERT_EQ(fw_integrity_check_hash(modified), FW_INTEGRITY_TAMPERED);
    PASS();
}

TEST(test_null_input_is_se_error) {
    ASSERT_EQ(fw_integrity_check_hash(NULL), FW_INTEGRITY_SE_ERROR);
    PASS();
}

int main(void) {
    printf("test_fw_integrity (US-031)\n");
    se051_init();

    test_match_returns_ok();
    test_mismatch_returns_tampered();
    test_unprovisioned_returns_not_provisioned();
    test_provisioning_roundtrip_flags_modified_firmware();
    test_null_input_is_se_error();

    printf("done\n");
    return 0;
}
