#include "balance.h"
#include <cstring>
#include <cstdio>

#if defined(ARDUINO) && defined(ESP32)
#include <Preferences.h>
#endif

#define NVS_NAMESPACE     "balance"
#define KEY_CONF_SATS     "conf_sats"
#define KEY_UNCONF_SATS   "unconf_sats"
#define KEY_LAST_SYNC     "last_sync"

#if defined(ARDUINO) && defined(ESP32)

static Preferences prefs;

void balance_init(void) {
    prefs.begin(NVS_NAMESPACE, false);
}

bool balance_has_cached(void) {
    return prefs.isKey(KEY_CONF_SATS);
}

bool balance_get_cached(uint64_t *confirmed_sats, uint64_t *unconfirmed_sats) {
    if (!prefs.isKey(KEY_CONF_SATS)) return false;
    if (confirmed_sats) *confirmed_sats = prefs.getULong64(KEY_CONF_SATS, 0);
    if (unconfirmed_sats) *unconfirmed_sats = prefs.getULong64(KEY_UNCONF_SATS, 0);
    return true;
}

void balance_set_cached(uint64_t confirmed_sats, uint64_t unconfirmed_sats) {
    prefs.putULong64(KEY_CONF_SATS, confirmed_sats);
    prefs.putULong64(KEY_UNCONF_SATS, unconfirmed_sats);
    prefs.putUInt(KEY_LAST_SYNC, (uint32_t)(millis() / 1000));
}

bool balance_get_last_sync(char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) return false;
    if (!prefs.isKey(KEY_LAST_SYNC)) {
        buf[0] = '\0';
        return false;
    }
    uint32_t ts = prefs.getUInt(KEY_LAST_SYNC, 0);
    snprintf(buf, buf_len, "%u", (unsigned)ts);
    return true;
}

void balance_nvs_erase(void) {
    prefs.begin(NVS_NAMESPACE, false);
    prefs.clear();
    prefs.end();
}

#else

static uint64_t g_conf_sats   = 0;
static uint64_t g_unconf_sats = 0;
static bool     g_has_cached  = false;
static uint32_t g_last_sync   = 0;

void balance_init(void) {
    g_conf_sats   = 0;
    g_unconf_sats = 0;
    g_has_cached  = false;
    g_last_sync   = 0;
}

bool balance_has_cached(void) {
    return g_has_cached;
}

bool balance_get_cached(uint64_t *confirmed_sats, uint64_t *unconfirmed_sats) {
    if (!g_has_cached) return false;
    if (confirmed_sats)   *confirmed_sats   = g_conf_sats;
    if (unconfirmed_sats) *unconfirmed_sats = g_unconf_sats;
    return true;
}

void balance_set_cached(uint64_t confirmed_sats, uint64_t unconfirmed_sats) {
    g_conf_sats   = confirmed_sats;
    g_unconf_sats = unconfirmed_sats;
    g_last_sync   = 1000000000;
    g_has_cached  = true;
}

bool balance_get_last_sync(char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) return false;
    if (!g_has_cached) {
        buf[0] = '\0';
        return false;
    }
    snprintf(buf, buf_len, "%u", (unsigned)g_last_sync);
    return true;
}

void balance_nvs_erase(void) {
    g_conf_sats   = 0;
    g_unconf_sats = 0;
    g_has_cached  = false;
    g_last_sync   = 0;
}

#endif
