#include "fw_integrity.h"
#include "se051_hal.h"
#include <string.h>

fw_integrity_status_t fw_integrity_check_hash(const uint8_t computed[FW_INTEGRITY_HASH_LEN]) {
    if (!computed) return FW_INTEGRITY_SE_ERROR;

    uint8_t stored[FW_INTEGRITY_HASH_LEN];
    size_t  stored_len = 0;
    se051_err_t rc = se051_read_object(SE051_OBJ_FW_HASH,
                                       stored, sizeof(stored),
                                       &stored_len);

    if (rc == SE_ERR_NOTFOUND) return FW_INTEGRITY_NOT_PROVISIONED;
    if (rc != SE_OK)           return FW_INTEGRITY_SE_ERROR;
    if (stored_len != FW_INTEGRITY_HASH_LEN) return FW_INTEGRITY_NOT_PROVISIONED;

    // Variable-time memcmp is acceptable here: the comparison is between two
    // public values (a stored hash and the device's own firmware hash) so
    // timing leakage reveals nothing an attacker cannot already compute.
    uint8_t diff = 0;
    for (size_t i = 0; i < FW_INTEGRITY_HASH_LEN; i++) {
        diff |= (uint8_t)(computed[i] ^ stored[i]);
    }
    return diff == 0 ? FW_INTEGRITY_OK : FW_INTEGRITY_TAMPERED;
}
