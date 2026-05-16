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
    printf("=== Base64 Codec Unit Tests ===\n\n");

    TEST("encode empty string");
    {
        char out[4];
        size_t len = base64_encode(NULL, 0, out, sizeof(out));
        if (len == 0) PASS();
        else FAIL("null input should return 0");
    }

    TEST("encode single byte");
    {
        const uint8_t data[] = {0x00};
        char out[8];
        size_t len = base64_encode(data, 1, out, sizeof(out));
        if (len == 4 && strcmp(out, "AA==") == 0) PASS();
        else { char msg[64]; snprintf(msg, 64, "got '%s' len=%zu", out, len); FAIL(msg); }
    }

    TEST("encode 'f'");
    {
        const uint8_t data[] = {'f'};
        char out[8];
        base64_encode(data, 1, out, sizeof(out));
        if (strcmp(out, "Zg==") == 0) PASS();
        else { char msg[64]; snprintf(msg, 64, "got '%s'", out); FAIL(msg); }
    }

    TEST("encode 'fo'");
    {
        const uint8_t data[] = {'f', 'o'};
        char out[8];
        base64_encode(data, 2, out, sizeof(out));
        if (strcmp(out, "Zm8=") == 0) PASS();
        else { char msg[64]; snprintf(msg, 64, "got '%s'", out); FAIL(msg); }
    }

    TEST("encode 'foo'");
    {
        const uint8_t data[] = {'f', 'o', 'o'};
        char out[8];
        base64_encode(data, 3, out, sizeof(out));
        if (strcmp(out, "Zm9v") == 0) PASS();
        else { char msg[64]; snprintf(msg, 64, "got '%s'", out); FAIL(msg); }
    }

    TEST("encode/decode roundtrip 256 bytes");
    {
        uint8_t original[256];
        for (int i = 0; i < 256; i++) original[i] = (uint8_t)i;

        char encoded[512];
        size_t elen = base64_encode(original, 256, encoded, sizeof(encoded));
        if (elen == 0) { FAIL("encode failed"); }
        else {
            uint8_t decoded[256];
            size_t dlen = base64_decode(encoded, elen, decoded, sizeof(decoded));
            if (dlen != 256) { FAIL("wrong decoded length"); }
            else if (memcmp(original, decoded, 256) != 0) { FAIL("data mismatch"); }
            else PASS();
        }
    }

    TEST("encode/decode roundtrip 32 bytes (random-like)");
    {
        uint8_t original[32];
        for (int i = 0; i < 32; i++) original[i] = (uint8_t)((i * 17 + 13) & 0xFF);

        char encoded[64];
        size_t elen = base64_encode(original, 32, encoded, sizeof(encoded));
        if (elen == 0) { FAIL("encode failed"); }
        else {
            uint8_t decoded[32];
            size_t dlen = base64_decode(encoded, elen, decoded, sizeof(decoded));
            if (dlen != 32) { FAIL("wrong decoded length"); }
            else if (memcmp(original, decoded, 32) != 0) { FAIL("data mismatch"); }
            else PASS();
        }
    }

    TEST("decode invalid char fails");
    {
        uint8_t out[4];
        size_t len = base64_decode("####", 4, out, sizeof(out));
        if (len == 0) PASS();
        else FAIL("should reject invalid chars");
    }

    TEST("decode odd length fails");
    {
        uint8_t out[4];
        size_t len = base64_decode("ABC", 3, out, sizeof(out));
        if (len == 0) PASS();
        else FAIL("should reject odd length");
    }

    TEST("encode output buffer too small");
    {
        const uint8_t data[] = {1, 2, 3};
        char out[3];
        size_t len = base64_encode(data, 3, out, sizeof(out));
        if (len == 0) PASS();
        else FAIL("should reject small buffer");
    }

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
