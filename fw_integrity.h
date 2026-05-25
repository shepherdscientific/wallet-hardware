#ifndef FW_INTEGRITY_H
#define FW_INTEGRITY_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define FW_INTEGRITY_HASH_LEN 32

typedef enum {
    FW_INTEGRITY_OK              = 0,  // computed == stored
    FW_INTEGRITY_TAMPERED        = 1,  // computed != stored
    FW_INTEGRITY_NOT_PROVISIONED = 2,  // SE slot is blank
    FW_INTEGRITY_SE_ERROR        = 3,  // SE read failed for another reason
} fw_integrity_status_t;

// Reads SE051_OBJ_FW_HASH from the secure element and compares it to the
// supplied computed SHA-256 digest of the running firmware image.  The caller
// is responsible for hashing the partition; this function only handles the
// SE-side fetch and the constant-time-ish comparison.
fw_integrity_status_t fw_integrity_check_hash(const uint8_t computed[FW_INTEGRITY_HASH_LEN]);

#ifdef __cplusplus
}
#endif

#endif // FW_INTEGRITY_H
