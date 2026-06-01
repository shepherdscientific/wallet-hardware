#include "serial_transport.h"
#include "base64.h"
#include <cstring>
#include <cstdio>
#include <cstdlib>

#if defined(ARDUINO) && defined(ESP32)
#include <Arduino.h>
#if defined(USB_CDC_ENABLED)
#define SERIAL_PORT USBSerial
#else
#define SERIAL_PORT Serial
#endif
#endif

static char recv_buf[SERIAL_RECV_BUF_SIZE];
static size_t recv_pos = 0;
static bool recv_has_line = false;

void serial_init(void) {
    recv_pos = 0;
    recv_has_line = false;
    memset(recv_buf, 0, sizeof(recv_buf));
#if defined(ARDUINO) && defined(ESP32) && defined(USB_CDC_ENABLED)
    USBSerial.begin(115200);
#endif
}

void serial_send_ready(void) {
#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.println("READY");
#else
    printf("READY\n");
#endif
}

void serial_send_signed(const uint8_t *psbt, size_t len) {
    if (!psbt || len == 0) return;

    size_t b64_max = ((len + 2) / 3) * 4 + 1;
    char *b64_out = (char *)malloc(b64_max);
    if (!b64_out) return;

    size_t b64_len = base64_encode(psbt, len, b64_out, b64_max);
    if (b64_len == 0) {
        free(b64_out);
        return;
    }

#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.print("SIGNED:");
    SERIAL_PORT.write((const uint8_t *)b64_out, b64_len);
    SERIAL_PORT.write('\n');
#else
    printf("SIGNED:%s\n", b64_out);
#endif

    free(b64_out);
}

void serial_send_error(int code) {
    char buf[32];
    snprintf(buf, sizeof(buf), "ERROR:%d", code);
#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.println(buf);
#else
    printf("%s\n", buf);
#endif
}

void serial_send_rejected(void) {
#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.println("REJECTED");
#else
    printf("REJECTED\n");
#endif
}

void serial_send_verified(void) {
#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.println("VERIFIED");
#else
    printf("VERIFIED\n");
#endif
}

void serial_send_mismatch(void) {
#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.println("MISMATCH");
#else
    printf("MISMATCH\n");
#endif
}

void serial_send_pairing(const char *words) {
    if (!words) return;
#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.print("PAIRING:");
    SERIAL_PORT.println(words);
#else
    printf("PAIRING:%s\n", words);
#endif
}

void serial_send_balance_request(const char *address) {
    if (!address) return;
#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.print("BALANCE_REQUEST:");
    SERIAL_PORT.println(address);
#else
    printf("BALANCE_REQUEST:%s\n", address);
#endif
}

void serial_send_tx_history_request(const char *address) {
    if (!address) return;
#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.print("TX_HISTORY:");
    SERIAL_PORT.println(address);
#else
    printf("TX_HISTORY:%s\n", address);
#endif
}

void serial_send_hash_ok(void) {
#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.println("HASH_OK");
#else
    printf("HASH_OK\n");
#endif
}

void serial_send_hash_err(void) {
#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.println("HASH_ERR");
#else
    printf("HASH_ERR\n");
#endif
}

void serial_send_xpub(const char *xpub_str) {
    if (!xpub_str) return;
#if defined(ARDUINO) && defined(ESP32)
    SERIAL_PORT.print("XPUB:");
    SERIAL_PORT.println(xpub_str);
#else
    printf("XPUB:%s\n", xpub_str);
#endif
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

/* parse_line_into — out-param version of the former parse_line().
 * Writing into *out (which lives in the caller's static buffer) means no
 * 8 KB serial_msg_t is ever placed on the call stack.                       */
static void parse_line_into(const char *line, size_t line_len,
                             serial_msg_t *out) {
    memset(out, 0, sizeof(*out));

    if (!line || line_len == 0) return;

    if (strncmp(line, "PSBT:", 5) == 0) {
        size_t decoded = base64_decode(line + 5, line_len - 5,
                                       out->data, sizeof(out->data));
        if (decoded > 0) {
            out->cmd      = SERIAL_CMD_PSBT;
            out->data_len = decoded;
        }
    } else if (strncmp(line, "VERIFY:", 7) == 0) {
        size_t addr_len = line_len - 7;
        if (addr_len < sizeof(out->data)) {
            memcpy(out->data, line + 7, addr_len);
            out->data[addr_len] = '\0';
            out->cmd      = SERIAL_CMD_VERIFY;
            out->data_len = addr_len;
        }
    } else if (strncmp(line, "PAIRING:", 8) == 0) {
        size_t words_len = line_len - 8;
        if (words_len < sizeof(out->data)) {
            memcpy(out->data, line + 8, words_len);
            out->data[words_len] = '\0';
            out->cmd      = SERIAL_CMD_PAIRING;
            out->data_len = words_len;
        }
    } else if (strncmp(line, "BALANCE:", 8) == 0) {
        uint64_t conf = 0, unconf = 0;
        int n = sscanf(line + 8, "%llu:%llu",
                       (unsigned long long *)&conf,
                       (unsigned long long *)&unconf);
        if (n >= 1) {
            memcpy(out->data,     &conf,   8);
            memcpy(out->data + 8, &unconf, 8);
            out->cmd      = SERIAL_CMD_BALANCE;
            out->data_len = 16;
        }
    } else if (strncmp(line, "PROVISION_HASH:", 15) == 0) {
        /* Factory-only: PROVISION_HASH:<64-hex-chars>
         * The caller enforces the "wallet must be uninitialized" gate.       */
        size_t hex_len = line_len - 15;
        if (hex_len == 64) {
            uint8_t ok = 1;
            for (size_t i = 0; i < 32; i++) {
                int hi = hex_nibble(line[15 + 2 * i]);
                int lo = hex_nibble(line[15 + 2 * i + 1]);
                if (hi < 0 || lo < 0) { ok = 0; break; }
                out->data[i] = (uint8_t)((hi << 4) | lo);
            }
            if (ok) {
                out->cmd      = SERIAL_CMD_PROVISION_HASH;
                out->data_len = 32;
            }
        }
    } else if (strncmp(line, "GET_INFO", 8) == 0 && line_len == 8) {
        out->cmd      = SERIAL_CMD_GET_INFO;
        out->data_len = 0;
    } else if (strncmp(line, "GET_XPUB:", 9) == 0) {
        // Store the path string (e.g. "m/84'/0'/0'") in data.
        size_t path_len = line_len - 9;
        if (path_len < sizeof(out->data)) {
            memcpy(out->data, line + 9, path_len);
            out->data[path_len] = '\0';
            out->cmd      = SERIAL_CMD_GET_XPUB;
            out->data_len = path_len;
        }
    } else if (strncmp(line, "TX:", 3) == 0) {
        const char *p   = line + 3;
        const char *end = line + line_len;
        uint8_t txid_bytes[32];
        int txid_pos = 0;
        while (p < end && *p != ':' && txid_pos < 64) {
            char hex_byte[3] = {0};
            if (p + 1 < end && *p != ':') {
                hex_byte[0] = *p;
                hex_byte[1] = (p + 1 < end && *(p + 1) != ':') ? *(p + 1) : 0;
                if (hex_byte[1]) {
                    txid_bytes[txid_pos++] = (uint8_t)strtol(hex_byte, NULL, 16);
                    p += 2;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        if (txid_pos == 32 && p < end && *p == ':') {
            p++;
            if (p < end) {
                char dir = *p;
                p++;
                if (p < end && *p == ':') {
                    p++;
                    uint64_t amount = strtoull(p, NULL, 10);
                    while (p < end && *p != ':') p++;
                    if (p < end && *p == ':') {
                        p++;
                        uint32_t conf = (uint32_t)strtoul(p, NULL, 10);
                        memcpy(out->data,      txid_bytes, 32);
                        out->data[32] = (uint8_t)dir;
                        memcpy(out->data + 33, &amount, 8);
                        memcpy(out->data + 41, &conf,   4);
                        out->cmd      = SERIAL_CMD_TX_ENTRY;
                        out->data_len = 45;
                    }
                }
            }
        }
    }
}

/* serial_poll_into — preferred, stack-safe API for use from loop().
 * The caller supplies *out (typically a file-scope static); no serial_msg_t
 * (8 KB) is allocated on the stack anywhere in this call chain.             */
void serial_poll_into(serial_msg_t *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));

    if (recv_has_line) {
        recv_has_line = false;
        parse_line_into(recv_buf, recv_pos, out);
        return;
    }

#if defined(ARDUINO) && defined(ESP32)
    while (SERIAL_PORT.available() > 0 && recv_pos < sizeof(recv_buf) - 1) {
        char c = (char)SERIAL_PORT.read();
        if (c == '\n' || c == '\r') {
            if (recv_pos == 0) continue;
            recv_buf[recv_pos] = '\0';
            size_t line_len = recv_pos;
            recv_pos = 0;
            parse_line_into(recv_buf, line_len, out);
            return;
        }
        recv_buf[recv_pos++] = c;
    }
#else
    if (fgets(recv_buf, (int)sizeof(recv_buf), stdin)) {
        recv_pos = strlen(recv_buf);
        while (recv_pos > 0 &&
               (recv_buf[recv_pos - 1] == '\n' || recv_buf[recv_pos - 1] == '\r'))
            recv_buf[--recv_pos] = '\0';
        size_t line_len = recv_pos;
        recv_pos = 0;
        parse_line_into(recv_buf, line_len, out);
    }
#endif
}

/* serial_poll — kept for backward compatibility with host-based unit tests
 * that call serial_inject_line() + serial_poll().  The static s_result lives
 * in BSS (not on the stack) so only a shallow copy lands in the caller.
 * New production code should call serial_poll_into() instead.               */
serial_msg_t serial_poll(void) {
    static serial_msg_t s_result;
    serial_poll_into(&s_result);
    return s_result;
}

void serial_inject_line(const char *line) {
    if (!line) return;
    size_t len = strlen(line);
    if (len >= sizeof(recv_buf)) len = sizeof(recv_buf) - 1;
    memcpy(recv_buf, line, len);
    recv_buf[len] = '\0';
    recv_pos = len;
    recv_has_line = true;
}
