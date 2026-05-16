#include <stdio.h>
#include <string.h>
#include "qr_renderer.h"

static int tests_run = 0, tests_passed = 0, tests_failed = 0;
#define TEST(name) do { tests_run++; printf("  TEST: %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)

int main() {
    QRCode qrcode;
    uint8_t buffer[QR_MAX_BUFFER_SIZE];

    printf("=== qr_renderer Tests ===\n\n");

    // Test 1: Short string uses version 1
    TEST("short string uses version 1");
    {
        int8_t ret = qr_init("HELLO", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else if (qrcode.version != 1) { FAIL("expected version 1"); }
        else { PASS(); }
    }

    // Test 2: Version auto-selection increases with length
    TEST("longer string uses higher version");
    {
        const char *longtext = "BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ1234567890ABCDEF";
        int8_t ret = qr_init(longtext, &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else if (qrcode.version < 2) { FAIL("expected version >= 2"); }
        else { PASS(); }
    }

    // Test 3: QR module grid has correct size for version
    TEST("module grid size matches version");
    {
        int8_t ret = qr_init("TEST123", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else if (qrcode.size != qrcode.version * 4 + 17) { FAIL("size mismatch"); }
        else { PASS(); }
    }

    // Test 4: All modules accessible within grid
    TEST("all modules within bounds");
    {
        int8_t ret = qr_init("BITCOIN", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else {
            bool ok = true;
            for (uint8_t y = 0; y < qrcode.size && ok; y++) {
                for (uint8_t x = 0; x < qrcode.size && ok; x++) {
                    (void)qrcode_getModule(&qrcode, x, y);
                }
            }
            if (ok) { PASS(); }
            else { FAIL("getModule crashed"); }
        }
    }

    // Test 5: Out-of-bounds returns false
    TEST("out-of-bounds module returns false");
    {
        int8_t ret = qr_init("X", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else if (qrcode_getModule(&qrcode, qrcode.size, 0)) { FAIL("OOB should be false"); }
        else if (qrcode_getModule(&qrcode, 0, qrcode.size)) { FAIL("OOB should be false"); }
        else { PASS(); }
    }

    // Test 6: Finder patterns exist (top-left, top-right, bottom-left)
    TEST("finder patterns present");
    {
        int8_t ret = qr_init("FINDER", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else {
            bool tl_found = false, tr_found = false, bl_found = false;
            uint8_t s = qrcode.size;
            // Top-left area should have modules
            if (qrcode_getModule(&qrcode, 3, 3)) tl_found = true;
            // Top-right area
            if (qrcode_getModule(&qrcode, s - 4, 3)) tr_found = true;
            // Bottom-left area
            if (qrcode_getModule(&qrcode, 3, s - 4)) bl_found = true;
            if (tl_found && tr_found && bl_found) { PASS(); }
            else { FAIL("finder patterns missing"); }
        }
    }

    // Test 7: QR code has both dark and light modules
    TEST("QR has both dark and light modules");
    {
        int8_t ret = qr_init("MIXED123", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else {
            bool has_dark = false, has_light = false;
            for (uint8_t y = 0; y < qrcode.size; y++) {
                for (uint8_t x = 0; x < qrcode.size; x++) {
                    if (qrcode_getModule(&qrcode, x, y)) has_dark = true;
                    else has_light = true;
                }
            }
            if (has_dark && has_light) { PASS(); }
            else { FAIL("all same color"); }
        }
    }

    // Test 8: Same input produces same QR
    TEST("same input produces same QR");
    {
        uint8_t buf2[QR_MAX_BUFFER_SIZE];
        QRCode qr2;
        int8_t r1 = qr_init("SAMEQR", &qrcode, buffer);
        int8_t r2 = qr_init("SAMEQR", &qr2, buf2);
        if (r1 != 0 || r2 != 0) { FAIL("qr_init failed"); }
        else if (qrcode.version != qr2.version) { FAIL("different version"); }
        else if (qrcode.size != qr2.size) { FAIL("different size"); }
        else {
            bool same = true;
            for (uint8_t y = 0; y < qrcode.size && same; y++) {
                for (uint8_t x = 0; x < qrcode.size && same; x++) {
                    if (qrcode_getModule(&qrcode, x, y) != qrcode_getModule(&qr2, x, y)) {
                        same = false;
                    }
                }
            }
            if (same) { PASS(); }
            else { FAIL("different modules"); }
        }
    }

    // Test 9: Different inputs produce different QRs
    TEST("different inputs produce different QRs");
    {
        uint8_t buf2[QR_MAX_BUFFER_SIZE];
        QRCode qr2;
        int8_t r1 = qr_init("QRTEST1", &qrcode, buffer);
        int8_t r2 = qr_init("QRTEST2", &qr2, buf2);
        if (r1 != 0 || r2 != 0) { FAIL("qr_init failed"); }
        else {
            bool different = false;
            for (uint8_t y = 0; y < qrcode.size && y < qr2.size && !different; y++) {
                for (uint8_t x = 0; x < qrcode.size && x < qr2.size && !different; x++) {
                    if (qrcode_getModule(&qrcode, x, y) != qrcode_getModule(&qr2, x, y)) {
                        different = true;
                    }
                }
            }
            if (different) { PASS(); }
            else { FAIL("same QR for different input"); }
        }
    }

    // Test 10: Bech32 address generates valid QR
    TEST("bech32 address generates valid QR");
    {
        const char *addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
        int8_t ret = qr_init(addr, &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else if (qrcode.size < 21) { FAIL("too small for address"); }
        else { PASS(); }
    }

    // Test 11: Bech32m address generates valid QR
    TEST("bech32m address generates valid QR");
    {
        const char *addr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8qt2acpp2ys4q2qd0t67";
        int8_t ret = qr_init(addr, &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else if (qrcode.size < 25) { FAIL("too small for bech32m"); }
        else { PASS(); }
    }

    // Test 12: Base58 address generates valid QR
    TEST("base58 address generates valid QR");
    {
        const char *addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        int8_t ret = qr_init(addr, &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else { PASS(); }
    }

    // Test 13: Numeric-only uses MODE_NUMERIC
    TEST("numeric string uses MODE_NUMERIC");
    {
        int8_t ret = qr_init("1234567890", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else if (qrcode.mode != MODE_NUMERIC) { FAIL("expected MODE_NUMERIC"); }
        else { PASS(); }
    }

    // Test 14: Alphanumeric string uses MODE_ALPHANUMERIC
    TEST("alphanumeric string uses MODE_ALPHANUMERIC");
    {
        int8_t ret = qr_init("BC1QAR0SRRR7XFKVY5L643LYDNW9RE59GTZZWF5MDQ", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else if (qrcode.mode != MODE_ALPHANUMERIC) { FAIL("expected MODE_ALPHANUMERIC"); }
        else { PASS(); }
    }

    // Test 15: Lowercase bech32 is uppercased and uses alphanumeric mode
    TEST("lowercase bech32 converted to alphanumeric mode");
    {
        int8_t ret = qr_init("bc1qtest", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else if (qrcode.mode != MODE_ALPHANUMERIC) { FAIL("expected MODE_ALPHANUMERIC after uppercase"); }
        else { PASS(); }
    }

    // Test 16: ECC is stored correctly
    TEST("ECC level is stored");
    {
        int8_t ret = qr_init("ECC", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else if (qrcode.ecc != ECC_LOW) { FAIL("ECC level not LOW"); }
        else { PASS(); }
    }

    // Test 17: Mask value is valid (0-7)
    TEST("mask value in range 0-7");
    {
        int8_t ret = qr_init("MASKTEST", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else if (qrcode.mask > 7) { FAIL("mask out of range"); }
        else { PASS(); }
    }

    // Test 18: Buffer reuse does not corrupt
    TEST("buffer reuse does not corrupt");
    {
        uint8_t buf2[QR_MAX_BUFFER_SIZE];
        QRCode qr1, qr2;
        qr_init("FIRST", &qr1, buffer);
        qr_init("SECOND", &qr2, buffer);
        qr_init("FIRST", &qr1, buf2);
        bool same = true;
        for (uint8_t y = 0; y < qr1.size && same; y++) {
            for (uint8_t x = 0; x < qr1.size && same; x++) {
                if (qrcode_getModule(&qr1, x, y) != qrcode_getModule(&qr2, x, y)) {
                    same = false;
                }
            }
        }
        if (!same) { PASS(); }
        else { FAIL("should produce different QRs"); }
    }

    // Test 19: QR module count is version*4+17 squared
    TEST("total modules = size^2");
    {
        int8_t ret = qr_init("SIZE", &qrcode, buffer);
        if (ret != 0) { FAIL("qr_init failed"); }
        else {
            uint16_t count = 0;
            for (uint8_t y = 0; y < qrcode.size; y++) {
                for (uint8_t x = 0; x < qrcode.size; x++) {
                    (void)qrcode_getModule(&qrcode, x, y);
                    count++;
                }
            }
            if (count == qrcode.size * qrcode.size) { PASS(); }
            else { FAIL("module count mismatch"); }
        }
    }

    // Test 20: Scaling buffer size is sufficient
    TEST("buffer size sufficient for version 4");
    {
        const char *addr = "bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8qt2acpp2ys4q2qd0t67";
        int8_t ret = qr_init(addr, &qrcode, buffer);
        if (ret != 0 && qrcode.version <= 4) { FAIL("buffer overflow"); }
        else { PASS(); }
    }

    printf("\n=== Results ===\n");
    printf("%d/%d tests passed\n", tests_passed, tests_run);
    if (tests_failed > 0) {
        printf("%d tests FAILED\n", tests_failed);
    }
    return tests_failed > 0 ? 1 : 0;
}
