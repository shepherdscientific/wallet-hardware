#ifdef USE_SE_STUB

#include "serial_transport.h"
#include "base64.h"
#include <cstdio>
#include <cstring>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  TEST: %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)

int main(void) {
    printf("=== Serial Transport Unit Tests ===\n\n");

    serial_init();

    TEST("poll returns NONE when no data");
    {
        serial_msg_t msg = serial_poll();
        if (msg.cmd == SERIAL_CMD_NONE) PASS();
        else FAIL("should return NONE");
    }

    TEST("inject PSBT line and poll returns PSBT cmd");
    {
        uint8_t raw_data[] = {0x70, 0x73, 0x62, 0x74, 0xff, 0x00};
        char b64[16];
        size_t b64_len = base64_encode(raw_data, sizeof(raw_data), b64, sizeof(b64));

        char line[256];
        snprintf(line, sizeof(line), "PSBT:%s", b64);

        serial_inject_line(line);
        serial_msg_t msg = serial_poll();

        if (msg.cmd != SERIAL_CMD_PSBT) FAIL("expected PSBT cmd");
        else if (msg.data_len != sizeof(raw_data)) FAIL("wrong data length");
        else if (memcmp(msg.data, raw_data, sizeof(raw_data)) != 0)
            FAIL("data mismatch");
        else PASS();
    }

    TEST("poll returns NONE after consuming injected line");
    {
        serial_msg_t msg = serial_poll();
        if (msg.cmd == SERIAL_CMD_NONE) PASS();
        else FAIL("should return NONE");
    }

    TEST("inject VERIFY line and poll returns VERIFY cmd");
    {
        serial_inject_line("VERIFY:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq");
        serial_msg_t msg = serial_poll();

        if (msg.cmd != SERIAL_CMD_VERIFY) FAIL("expected VERIFY cmd");
        else if (strcmp((const char *)msg.data,
                        "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") != 0)
            FAIL("address mismatch");
        else PASS();
    }

    TEST("inject unknown line returns NONE");
    {
        serial_inject_line("UNKNOWN:something");
        serial_msg_t msg = serial_poll();
        if (msg.cmd == SERIAL_CMD_NONE) PASS();
        else FAIL("should return NONE for unknown cmd");
    }

    TEST("inject NULL line handled safely");
    {
        serial_inject_line(NULL);
        serial_msg_t msg = serial_poll();
        if (msg.cmd == SERIAL_CMD_NONE) PASS();
        else FAIL("should return NONE");
    }

    TEST("inject empty line returns NONE");
    {
        serial_inject_line("");
        serial_msg_t msg = serial_poll();
        if (msg.cmd == SERIAL_CMD_NONE) PASS();
        else FAIL("should return NONE");
    }

    TEST("PSBT base64 roundtrip through transport");
    {
        uint8_t psbt_raw[256] = {
            0x70, 0x73, 0x62, 0x74, 0xff,
            0x01, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00, 0x01, 0x02,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0xFF, 0xFF, 0xFF, 0xFF,
            0x01, 0x00, 0x10, 0x27, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x16, 0x00, 0x14,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
            0xAA, 0xAA, 0xAA, 0xAA,
            0x00, 0x00, 0x00, 0x00,
            0x00
        };
        size_t raw_len = 65;

        char b64[512];
        size_t b64_len = base64_encode(psbt_raw, raw_len, b64, sizeof(b64));

        char line[640];
        snprintf(line, sizeof(line), "PSBT:%s", b64);

        serial_inject_line(line);
        serial_msg_t msg = serial_poll();

        if (msg.cmd != SERIAL_CMD_PSBT) FAIL("expected PSBT cmd");
        else if (msg.data_len != raw_len)
            { char m[64]; snprintf(m, 64, "len mismatch %zu vs %zu", msg.data_len, raw_len); FAIL(m); }
        else if (memcmp(msg.data, psbt_raw, raw_len) != 0)
            FAIL("PSBT data mismatch");
        else PASS();
    }

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}

#else
#include <cstdio>
int main(void) {
    printf("Serial transport tests require USE_SE_STUB.\n");
    return 0;
}
#endif
