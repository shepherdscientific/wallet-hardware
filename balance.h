#ifndef BALANCE_H
#define BALANCE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

void balance_init(void);

bool balance_has_cached(void);

bool balance_get_cached(uint64_t *confirmed_sats, uint64_t *unconfirmed_sats);

void balance_set_cached(uint64_t confirmed_sats, uint64_t unconfirmed_sats);

bool balance_get_last_sync(char *buf, size_t buf_len);

void balance_nvs_erase(void);

#ifdef __cplusplus
}
#endif

#endif
