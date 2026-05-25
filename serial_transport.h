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
    SERIAL_CMD_NONE             = 0,
    SERIAL_CMD_PSBT             = 1,
    SERIAL_CMD_VERIFY           = 2,
    SERIAL_CMD_PAIRING          = 3,
    SERIAL_CMD_BALANCE          = 4,
    SERIAL_CMD_TX_HISTORY       = 5,
    SERIAL_CMD_TX_ENTRY         = 6,
    SERIAL_CMD_PROVISION_HASH   = 7,
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

void serial_send_tx_history_request(const char *address);

void serial_send_hash_ok(void);

void serial_send_hash_err(void);

serial_msg_t serial_poll(void);

/* Stack-safe variant: writes directly into *out instead of returning 8 KB by
 * value.  Prefer this in loop() to avoid placing a serial_msg_t (8 KB) on the
 * loopTask stack (default only 8 KB).  *out is always zeroed on entry.       */
void serial_poll_into(serial_msg_t *out);

void serial_inject_line(const char *line);

#ifdef __cplusplus
}
#endif

#endif
