#ifndef ACCOUNT_MANAGER_H
#define ACCOUNT_MANAGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ACCOUNTS      10
#define ACCOUNT_NAME_LEN   7    // 6 chars + NUL

void account_init(void);
uint32_t account_get_active(void);
void account_set_active(uint32_t idx);
void account_get_address_index(uint32_t account, uint32_t *idx);
void account_increment_address_index(uint32_t account);
bool account_get_name(uint32_t account, char *buf, size_t len);
void account_set_name(uint32_t account, const char *name);

#ifdef __cplusplus
}
#endif

#endif
