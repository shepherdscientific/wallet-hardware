#ifndef TX_HISTORY_H
#define TX_HISTORY_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TX_HISTORY_MAX_ENTRIES 10
#define TX_HISTORY_TXID_LEN    32

typedef struct {
    uint8_t  txid[TX_HISTORY_TXID_LEN];
    char     direction;
    uint64_t amount_sats;
    uint32_t confirmations;
} tx_history_entry_t;

void tx_history_init(void);

bool tx_history_has_cached(void);

uint8_t tx_history_get_count(void);

bool tx_history_get_entry(uint8_t index, tx_history_entry_t *entry);

void tx_history_add_entry(const uint8_t txid[TX_HISTORY_TXID_LEN],
                          char direction, uint64_t amount_sats,
                          uint32_t confirmations);

void tx_history_nvs_erase(void);

#ifdef __cplusplus
}
#endif

#endif
