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

static serial_msg_t parse_line(const char *line, size_t line_len) {
    serial_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    if (!line || line_len == 0) return msg;

    if (strncmp(line, "PSBT:", 5) == 0) {
        size_t decoded = base64_decode(line + 5, line_len - 5,
                                       msg.data, sizeof(msg.data));
        if (decoded > 0) {
            msg.cmd = SERIAL_CMD_PSBT;
            msg.data_len = decoded;
        }
    } else if (strncmp(line, "VERIFY:", 7) == 0) {
        size_t addr_len = line_len - 7;
        if (addr_len < sizeof(msg.data)) {
            memcpy(msg.data, line + 7, addr_len);
            msg.data[addr_len] = '\0';
            msg.cmd = SERIAL_CMD_VERIFY;
            msg.data_len = addr_len;
        }
    } else if (strncmp(line, "PAIRING:", 8) == 0) {
        size_t words_len = line_len - 8;
        if (words_len < sizeof(msg.data)) {
            memcpy(msg.data, line + 8, words_len);
            msg.data[words_len] = '\0';
            msg.cmd = SERIAL_CMD_PAIRING;
            msg.data_len = words_len;
        }
    } else if (strncmp(line, "BALANCE:", 8) == 0) {
        uint64_t conf = 0, unconf = 0;
        int n = sscanf(line + 8, "%llu:%llu",
                       (unsigned long long *)&conf,
                       (unsigned long long *)&unconf);
        if (n >= 1) {
            memcpy(msg.data, &conf, 8);
            memcpy(msg.data + 8, &unconf, 8);
            msg.cmd = SERIAL_CMD_BALANCE;
            msg.data_len = 16;
        }
    }

    return msg;
}

serial_msg_t serial_poll(void) {
    serial_msg_t msg;
    memset(&msg, 0, sizeof(msg));

    if (recv_has_line) {
        recv_has_line = false;
        return parse_line(recv_buf, recv_pos);
    }

#if defined(ARDUINO) && defined(ESP32)
    while (SERIAL_PORT.available() > 0 && recv_pos < sizeof(recv_buf) - 1) {
        char c = (char)SERIAL_PORT.read();
        if (c == '\n' || c == '\r') {
            if (recv_pos == 0) continue;
            recv_buf[recv_pos] = '\0';
            size_t line_len = recv_pos;
            recv_pos = 0;
            return parse_line(recv_buf, line_len);
        }
        recv_buf[recv_pos++] = c;
    }
#else
    if (fgets(recv_buf, (int)sizeof(recv_buf), stdin)) {
        recv_pos = strlen(recv_buf);
        while (recv_pos > 0 && (recv_buf[recv_pos - 1] == '\n' || recv_buf[recv_pos - 1] == '\r'))
            recv_buf[--recv_pos] = '\0';
        size_t line_len = recv_pos;
        recv_pos = 0;
        return parse_line(recv_buf, line_len);
    }
#endif

    return msg;
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
