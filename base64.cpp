#include "base64.h"
#include <cstring>

static const char B64_ALPHABET[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static uint8_t b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return (uint8_t)(c - 'A');
    if (c >= 'a' && c <= 'z') return (uint8_t)(c - 'a' + 26);
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0' + 52);
    if (c == '+') return 62;
    if (c == '/') return 63;
    return 255;
}

size_t base64_encode(const uint8_t *data, size_t len, char *out, size_t out_max) {
    if (!data || !out || out_max < 4) return 0;

    size_t out_len = ((len + 2) / 3) * 4;
    if (out_len > out_max - 1) return 0;

    size_t opos = 0;
    for (size_t i = 0; i < len; i += 3) {
        uint32_t triple = ((uint32_t)data[i]) << 16;
        if (i + 1 < len) triple |= ((uint32_t)data[i + 1]) << 8;
        if (i + 2 < len) triple |= ((uint32_t)data[i + 2]);

        out[opos++] = B64_ALPHABET[(triple >> 18) & 0x3F];
        out[opos++] = B64_ALPHABET[(triple >> 12) & 0x3F];

        if (i + 1 < len)
            out[opos++] = B64_ALPHABET[(triple >> 6) & 0x3F];
        else
            out[opos++] = '=';

        if (i + 2 < len)
            out[opos++] = B64_ALPHABET[triple & 0x3F];
        else
            out[opos++] = '=';
    }

    out[opos] = '\0';
    return opos;
}

size_t base64_decode(const char *in, size_t len, uint8_t *out, size_t out_max) {
    if (!in || !out || len % 4 != 0) return 0;

    size_t pad = 0;
    if (len >= 1 && in[len - 1] == '=') pad++;
    if (len >= 2 && in[len - 2] == '=') pad++;

    size_t out_len = (len / 4) * 3 - pad;
    if (out_len > out_max) return 0;

    size_t opos = 0;
    for (size_t i = 0; i < len; i += 4) {
        uint8_t a = b64_decode_char(in[i]);
        uint8_t b = b64_decode_char(in[i + 1]);
        uint8_t c = b64_decode_char(in[i + 2]);
        uint8_t d = b64_decode_char(in[i + 3]);

        if (a == 255 || b == 255 || (c == 255 && in[i + 2] != '=') || (d == 255 && in[i + 3] != '='))
            return 0;

        uint32_t triple = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                          ((uint32_t)(c == 255 ? 0 : c) << 6) |
                          (uint32_t)(d == 255 ? 0 : d);

        out[opos++] = (uint8_t)((triple >> 16) & 0xFF);
        if (opos < out_len && in[i + 2] != '=')
            out[opos++] = (uint8_t)((triple >> 8) & 0xFF);
        if (opos < out_len && in[i + 3] != '=')
            out[opos++] = (uint8_t)(triple & 0xFF);
    }

    return out_len;
}
