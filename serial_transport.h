#ifndef SERIAL_TRANSPORT_H
#define SERIAL_TRANSPORT_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SERIAL_RECV_BUF_SIZE 8192

typedef enum {
    SERIAL_CMD_NONE    = 0,
    SERIAL_CMD_PSBT    = 1,
    SERIAL_CMD_VERIFY  = 2,
    SERIAL_CMD_PAIRING = 3,
    SERIAL_CMD_BALANCE = 4,
} serial_cmd_t;

typedef struct {
    serial_cmd_t cmd;
    uint8_t      data[SERIAL_RECV_BUF_SIZE];
    size_t       data_len;
} serial_msg_t;

void serial_init(void);

void serial_send_ready(void);

void serial_send_signed(const uint8_t *psbt, size_t len);

void serial_send_error(int code);

void serial_send_rejected(void);

void serial_send_verified(void);

void serial_send_mismatch(void);

void serial_send_pairing(const char *words);

void serial_send_balance_request(const char *address);

serial_msg_t serial_poll(void);

void serial_inject_line(const char *line);

#ifdef __cplusplus
}
#endif

#endif
