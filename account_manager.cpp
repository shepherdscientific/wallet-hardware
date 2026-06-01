#include "account_manager.h"
#include <cstring>
#include <cstdio>

#if defined(ARDUINO) && defined(ESP32)
#include <Preferences.h>
#endif

#define NVS_NAMESPACE    "accounts"
#define KEY_ACTIVE       "active"
#define KEY_ADDR_PREFIX  "addr_idx_"
#define KEY_NAME_PREFIX  "name_"

#if defined(ARDUINO) && defined(ESP32)

static Preferences prefs;

void account_init(void) {
    prefs.begin(NVS_NAMESPACE, false);
    if (!prefs.isKey(KEY_ACTIVE)) {
        prefs.putUInt(KEY_ACTIVE, 0);
    }
}

uint32_t account_get_active(void) {
    uint32_t v = prefs.getUInt(KEY_ACTIVE, 0);
    if (v >= MAX_ACCOUNTS) v = 0;
    return v;
}

void account_set_active(uint32_t idx) {
    if (idx >= MAX_ACCOUNTS) return;
    prefs.putUInt(KEY_ACTIVE, idx);
}

void account_get_address_index(uint32_t account, uint32_t *idx) {
    if (!idx || account >= MAX_ACCOUNTS) return;
    char key[32];
    snprintf(key, sizeof(key), "%s%u", KEY_ADDR_PREFIX, (unsigned)account);
    *idx = prefs.getUInt(key, 0);
}

void account_increment_address_index(uint32_t account) {
    if (account >= MAX_ACCOUNTS) return;
    char key[32];
    snprintf(key, sizeof(key), "%s%u", KEY_ADDR_PREFIX, (unsigned)account);
    uint32_t val = prefs.getUInt(key, 0);
    prefs.putUInt(key, val + 1);
}

bool account_get_name(uint32_t account, char *buf, size_t len) {
    if (!buf || len == 0 || account >= MAX_ACCOUNTS) return false;
    char key[32];
    snprintf(key, sizeof(key), "%s%u", KEY_NAME_PREFIX, (unsigned)account);
    size_t ret = prefs.getString(key, buf, len);
    return ret > 0;
}

void account_set_name(uint32_t account, const char *name) {
    if (!name || account >= MAX_ACCOUNTS) return;
    char key[32];
    snprintf(key, sizeof(key), "%s%u", KEY_NAME_PREFIX, (unsigned)account);
    prefs.putString(key, name);
}

#else

// Host-based stub using in-memory store
static uint32_t g_active_account = 0;
static uint32_t g_addr_indices[MAX_ACCOUNTS] = {0};
static char g_names[MAX_ACCOUNTS][ACCOUNT_NAME_LEN] = {{0}};

void account_init(void) {
    g_active_account = 0;
    for (int i = 0; i < MAX_ACCOUNTS; i++) {
        g_addr_indices[i] = 0;
        g_names[i][0] = '\0';
    }
}

uint32_t account_get_active(void) {
    if (g_active_account >= MAX_ACCOUNTS) g_active_account = 0;
    return g_active_account;
}

void account_set_active(uint32_t idx) {
    if (idx >= MAX_ACCOUNTS) return;
    g_active_account = idx;
}

void account_get_address_index(uint32_t account, uint32_t *idx) {
    if (!idx || account >= MAX_ACCOUNTS) {
        if (idx) *idx = 0;
        return;
    }
    *idx = g_addr_indices[account];
}

void account_increment_address_index(uint32_t account) {
    if (account >= MAX_ACCOUNTS) return;
    g_addr_indices[account]++;
}

bool account_get_name(uint32_t account, char *buf, size_t len) {
    if (!buf || len == 0 || account >= MAX_ACCOUNTS) return false;
    if (g_names[account][0] == '\0') return false;
    strncpy(buf, g_names[account], len);
    buf[len - 1] = '\0';
    return true;
}

void account_set_name(uint32_t account, const char *name) {
    if (!name || account >= MAX_ACCOUNTS) return;
    strncpy(g_names[account], name, ACCOUNT_NAME_LEN);
    g_names[account][ACCOUNT_NAME_LEN - 1] = '\0';
}

#endif

void account_nvs_erase(void) {
#if defined(ARDUINO) && defined(ESP32)
    prefs.begin(NVS_NAMESPACE, false);
    prefs.clear();
    prefs.end();
#endif
}
