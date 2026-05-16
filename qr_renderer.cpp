#include "qr_renderer.h"
#include <string.h>

static bool is_alphanumeric(const char *text, uint16_t len) {
    for (uint16_t i = 0; i < len; i++) {
        char c = text[i];
        bool ok = (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') ||
                  c == ' ' || c == '$' || c == '%' || c == '*' ||
                  c == '+' || c == '-' || c == '.' || c == '/' || c == ':';
        if (!ok) return false;
    }
    return true;
}

int8_t qr_init(const char *text, QRCode *qrcode, uint8_t *buffer) {
    uint16_t len = strlen(text);

    char upper[200];
    if (len >= sizeof(upper)) return -1;
    for (uint16_t i = 0; i <= len; i++) {
        char c = text[i];
        if (c >= 'a' && c <= 'z') c -= 32;
        upper[i] = c;
    }

    bool is_alnum = is_alphanumeric(upper, len);
    uint8_t min_version = 1;

    if (is_alnum) {
        if (len <= 25) min_version = 1;
        else if (len <= 47) min_version = 2;
        else if (len <= 77) min_version = 3;
        else if (len <= 114) min_version = 4;
        else return -1;
    } else {
        if (len <= 17) min_version = 1;
        else if (len <= 32) min_version = 2;
        else if (len <= 53) min_version = 3;
        else if (len <= 78) min_version = 4;
        else return -1;
    }

    return qrcode_initText(qrcode, buffer, min_version, ECC_LOW, upper);
}
