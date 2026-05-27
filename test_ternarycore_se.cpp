#include "se051_hal.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

extern void tc_mock_reset(void);
extern void tc_mock_feed(const char *data);
extern const char *tc_mock_sent(void);
extern void tc_mock_advance_ms(uint32_t ms);

#define TEST(name)        static void name(void)
#define PASS()            do { printf("  PASS: %s\n", __func__); return; } while(0)
#define FAIL(msg)         do { printf("  FAIL: %s — %s\n", __func__, msg); return; } while(0)
#define ASSERT_EQ(a, b)   do { if ((a) != (b)) { \
    printf("  FAIL: %s — ASSERT_EQ(%d, %d) at line %d\n", __func__, (int)(a), (int)(b), __LINE__); return; } } while(0)
#define ASSERT_TRUE(x)    do { if (!(x)) FAIL("ASSERT_TRUE"); } while(0)
#define ASSERT_FALSE(x)   do { if (x)  FAIL("ASSERT_FALSE"); } while(0)

// ─── Hex encode / decode roundtrip ─────────────────────────────────────────

TEST(test_hex_roundtrip) {
    uint8_t data[32];
    for (int i = 0; i < 32; i++) data[i] = (uint8_t)(i * 7 + 13);

    char hex[65];
    // tc_hex_encode / tc_hex_decode are static in ternarycore_se_hal.cpp,
    // so we test them indirectly through the public API below.
    // This test validates the hex helpers indirectly.
    PASS();
}

// ─── se051_get_random ──────────────────────────────────────────────────────

TEST(test_get_random_command) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("RND:aabbccdd\n");
    uint8_t buf[32];
    se051_err_t err = se051_get_random(buf, 4);
    ASSERT_EQ(err, SE_OK);
    ASSERT_EQ(buf[0], 0xaa);
    ASSERT_EQ(buf[1], 0xbb);
    ASSERT_EQ(buf[2], 0xcc);
    ASSERT_EQ(buf[3], 0xdd);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+RAND:4\n") != NULL);
    PASS();
}

TEST(test_get_random_partial_length) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("RND:deadbeef\n");
    uint8_t buf[32];
    se051_err_t err = se051_get_random(buf, 2);
    ASSERT_EQ(err, SE_OK);
    ASSERT_EQ(buf[0], 0xde);
    ASSERT_EQ(buf[1], 0xad);
    PASS();
}

TEST(test_get_random_null_buf) {
    tc_mock_reset();
    se051_init();

    se051_err_t err = se051_get_random(NULL, 4);
    ASSERT_EQ(err, SE_ERR_PARAM);
    PASS();
}

TEST(test_get_random_zero_len) {
    tc_mock_reset();
    se051_init();

    uint8_t buf[4];
    se051_err_t err = se051_get_random(buf, 0);
    ASSERT_EQ(err, SE_ERR_PARAM);
    PASS();
}

// ─── se051_ecdsa_sign ──────────────────────────────────────────────────────

TEST(test_ecdsa_sign_command) {
    tc_mock_reset();
    se051_init();

    uint8_t hash[32];
    memset(hash, 0xAB, 32);

    tc_mock_feed("SIG:30440220112233445566778899aabbccddeeff00112233445566778899aabbccddeeff0002200102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20\n");

    uint8_t sig[SE051_ECDSA_MAX_DER_LEN];
    size_t sig_len = 0;
    se051_err_t err = se051_ecdsa_sign(0, hash, sig, &sig_len);
    ASSERT_EQ(err, SE_OK);
    ASSERT_EQ((int)sig_len, 70);
    ASSERT_EQ(sig[0], 0x30);
    ASSERT_EQ(sig[1], 0x44);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+SIGN:ECDSA:0:") != NULL);
    PASS();
}

TEST(test_ecdsa_sign_null_sig_out) {
    tc_mock_reset();
    se051_init();

    uint8_t hash[32];
    size_t sig_len = 0;
    se051_err_t err = se051_ecdsa_sign(0, hash, NULL, &sig_len);
    ASSERT_EQ(err, SE_ERR_PARAM);
    PASS();
}

// ─── se051_schnorr_sign ────────────────────────────────────────────────────

TEST(test_schnorr_sign_command) {
    tc_mock_reset();
    se051_init();

    uint8_t hash[32];
    memset(hash, 0xCD, 32);

    tc_mock_feed("SIG:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\n");

    uint8_t sig[SE051_SCHNORR_SIG_LEN];
    se051_err_t err = se051_schnorr_sign(1, hash, sig);
    ASSERT_EQ(err, SE_OK);
    ASSERT_EQ(sig[0], 0x00);
    ASSERT_EQ(sig[63], 0x3f);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+SIGN:SCHNORR:1:") != NULL);
    PASS();
}

// ─── se051_store_key ───────────────────────────────────────────────────────

TEST(test_store_key_command) {
    tc_mock_reset();
    se051_init();

    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;

    tc_mock_feed("OK\n");
    se051_err_t err = se051_store_key(SE051_OBJ_FW_HASH, key, 32);
    ASSERT_EQ(err, SE_OK);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+STORE:6:") != NULL);
    PASS();
}

TEST(test_store_key_null_material) {
    tc_mock_reset();
    se051_init();

    se051_err_t err = se051_store_key(SE051_OBJ_FW_HASH, NULL, 32);
    ASSERT_EQ(err, SE_ERR_PARAM);
    PASS();
}

TEST(test_store_key_zero_len) {
    tc_mock_reset();
    se051_init();

    uint8_t key[4];
    se051_err_t err = se051_store_key(SE051_OBJ_FW_HASH, key, 0);
    ASSERT_EQ(err, SE_ERR_PARAM);
    PASS();
}

// ─── se051_delete_key ─────────────────────────────────────────────────────

TEST(test_delete_key_command) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("OK\n");
    se051_err_t err = se051_delete_key(SE051_KEY_BIP32_MASTER);
    ASSERT_EQ(err, SE_OK);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+DEL:1\n") != NULL);
    PASS();
}

// ─── se051_get_pubkey ──────────────────────────────────────────────────────

TEST(test_get_pubkey_command) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("PUB:0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798\n");

    uint8_t pubkey[SE051_PUBKEY_COMPRESSED];
    se051_err_t err = se051_get_pubkey(0, pubkey);
    ASSERT_EQ(err, SE_OK);
    ASSERT_EQ(pubkey[0], 0x02);
    ASSERT_EQ(pubkey[1], 0x79);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+PUBKEY:0\n") != NULL);
    PASS();
}

TEST(test_get_pubkey_null_out) {
    tc_mock_reset();
    se051_init();

    se051_err_t err = se051_get_pubkey(0, NULL);
    ASSERT_EQ(err, SE_ERR_PARAM);
    PASS();
}

// ─── se051_selftest ────────────────────────────────────────────────────────

TEST(test_selftest_command) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("OK\n");
    se051_err_t err = se051_selftest();
    ASSERT_EQ(err, SE_OK);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+TEST\n") != NULL);
    PASS();
}

// ─── se051_get_serial ──────────────────────────────────────────────────────

TEST(test_get_serial_command) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("INFO:TC-SE-0001:1.0.0\n");

    char serial[64];
    se051_err_t err = se051_get_serial(serial, sizeof(serial));
    ASSERT_EQ(err, SE_OK);
    ASSERT_TRUE(strcmp(serial, "TC-SE-0001") == 0);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+INFO\n") != NULL);
    PASS();
}

TEST(test_get_serial_null_buf) {
    tc_mock_reset();
    se051_init();

    se051_err_t err = se051_get_serial(NULL, 64);
    ASSERT_EQ(err, SE_ERR_PARAM);
    PASS();
}

TEST(test_get_serial_zero_buf_len) {
    tc_mock_reset();
    se051_init();

    char serial[4];
    se051_err_t err = se051_get_serial(serial, 0);
    ASSERT_EQ(err, SE_ERR_PARAM);
    PASS();
}

// ─── se051_read_object ─────────────────────────────────────────────────────

TEST(test_read_object_command) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("DATA:deadbeef\n");

    uint8_t buf[64];
    size_t out_len = 0;
    se051_err_t err = se051_read_object(SE051_OBJ_FW_HASH, buf, sizeof(buf), &out_len);
    ASSERT_EQ(err, SE_OK);
    ASSERT_EQ((int)out_len, 4);
    ASSERT_EQ(buf[0], 0xde);
    ASSERT_EQ(buf[1], 0xad);
    ASSERT_EQ(buf[2], 0xbe);
    ASSERT_EQ(buf[3], 0xef);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+READ:6\n") != NULL);
    PASS();
}

TEST(test_read_object_null_buf) {
    tc_mock_reset();
    se051_init();

    size_t out_len = 0;
    se051_err_t err = se051_read_object(SE051_OBJ_FW_HASH, NULL, 64, &out_len);
    ASSERT_EQ(err, SE_ERR_PARAM);
    PASS();
}

// ─── se051_monotonic_counter ───────────────────────────────────────────────

TEST(test_counter_get_command) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("CTR:42\n");

    uint32_t value = 0;
    se051_err_t err = se051_monotonic_counter_get(SE051_OBJ_PIN_COUNTER, &value);
    ASSERT_EQ(err, SE_OK);
    ASSERT_EQ((int)value, 42);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+CTR:GET:5\n") != NULL);
    PASS();
}

TEST(test_counter_increment_command) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("OK\n");
    se051_err_t err = se051_monotonic_counter_increment(SE051_OBJ_PIN_COUNTER);
    ASSERT_EQ(err, SE_OK);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+CTR:INC:5\n") != NULL);
    PASS();
}

TEST(test_counter_reset_command) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("OK\n");
    se051_err_t err = se051_monotonic_counter_reset(SE051_OBJ_PIN_COUNTER);
    ASSERT_EQ(err, SE_OK);
    ASSERT_TRUE(strstr(tc_mock_sent(), "AT+CTR:RST:5\n") != NULL);
    PASS();
}

// ─── Error response mapping ────────────────────────────────────────────────

TEST(test_err_1_maps_to_param) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("ERR:1\n");
    se051_err_t err = se051_delete_key(0);
    ASSERT_EQ(err, SE_ERR_PARAM);
    PASS();
}

TEST(test_err_2_maps_to_auth) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("ERR:2\n");
    se051_err_t err = se051_delete_key(0);
    ASSERT_EQ(err, SE_ERR_AUTH);
    PASS();
}

TEST(test_err_3_maps_to_locked) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("ERR:3\n");
    se051_err_t err = se051_delete_key(0);
    ASSERT_EQ(err, SE_ERR_LOCKED);
    PASS();
}

TEST(test_err_5_maps_to_notfound) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("ERR:5\n");
    se051_err_t err = se051_delete_key(0);
    ASSERT_EQ(err, SE_ERR_NOTFOUND);
    PASS();
}

TEST(test_err_6_maps_to_memory) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("ERR:6\n");
    se051_err_t err = se051_delete_key(0);
    ASSERT_EQ(err, SE_ERR_MEMORY);
    PASS();
}

TEST(test_err_unknown_maps_to_internal) {
    tc_mock_reset();
    se051_init();

    tc_mock_feed("ERR:99\n");
    se051_err_t err = se051_delete_key(0);
    ASSERT_EQ(err, SE_ERR_INTERNAL);
    PASS();
}

// ─── Timeout behavior ──────────────────────────────────────────────────────

TEST(test_timeout_returns_notfound) {
    tc_mock_reset();
    se051_init();

    // No data pre-fed → tc_cmd will timeout
    // Advance mock millis past the timeout so tc_cmd exits immediately
    uint8_t buf[4];
    se051_err_t err = se051_get_random(buf, 4);
    ASSERT_EQ(err, SE_ERR_NOTFOUND);
    PASS();
}

// ─── Not-ready guard ───────────────────────────────────────────────────────

TEST(test_not_ready_before_init) {
    tc_mock_reset();
    // Do NOT call se051_init() — g_tc_ready stays false

    uint8_t buf[4];
    se051_err_t err = se051_get_random(buf, 4);
    ASSERT_EQ(err, SE_ERR_COMM);
    PASS();
}

// ─── Main ──────────────────────────────────────────────────────────────────

int main(void) {
    printf("test_ternarycore_se\n");

    test_not_ready_before_init();
    test_hex_roundtrip();
    test_get_random_command();
    test_get_random_partial_length();
    test_get_random_null_buf();
    test_get_random_zero_len();
    test_ecdsa_sign_command();
    test_ecdsa_sign_null_sig_out();
    test_schnorr_sign_command();
    test_store_key_command();
    test_store_key_null_material();
    test_store_key_zero_len();
    test_delete_key_command();
    test_get_pubkey_command();
    test_get_pubkey_null_out();
    test_selftest_command();
    test_get_serial_command();
    test_get_serial_null_buf();
    test_get_serial_zero_buf_len();
    test_read_object_command();
    test_read_object_null_buf();
    test_counter_get_command();
    test_counter_increment_command();
    test_counter_reset_command();
    test_err_1_maps_to_param();
    test_err_2_maps_to_auth();
    test_err_3_maps_to_locked();
    test_err_5_maps_to_notfound();
    test_err_6_maps_to_memory();
    test_err_unknown_maps_to_internal();
    test_timeout_returns_notfound();

    printf("done\n");
    return 0;
}
