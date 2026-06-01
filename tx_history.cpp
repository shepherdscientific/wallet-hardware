#include "tx_history.h"
#include <cstring>
#include <cstdio>

#if defined(ARDUINO) && defined(ESP32)
#include <Preferences.h>
#endif

#define NVS_NAMESPACE    "txhistory"
#define KEY_COUNT        "count"

#if defined(ARDUINO) && defined(ESP32)

static Preferences prefs;

static void make_key(char *buf, size_t buf_size, const char *field, uint8_t idx) {
    snprintf(buf, buf_size, "%s_%u", field, (unsigned)idx);
}

void tx_history_init(void) {
    prefs.begin(NVS_NAMESPACE, false);
}

bool tx_history_has_cached(void) {
    return prefs.isKey(KEY_COUNT) && prefs.getUChar(KEY_COUNT, 0) > 0;
}

uint8_t tx_history_get_count(void) {
    if (!prefs.isKey(KEY_COUNT)) return 0;
    uint8_t count = prefs.getUChar(KEY_COUNT, 0);
    return (count > TX_HISTORY_MAX_ENTRIES) ? TX_HISTORY_MAX_ENTRIES : count;
}

bool tx_history_get_entry(uint8_t index, tx_history_entry_t *entry) {
    if (!entry) return false;
    memset(entry, 0, sizeof(*entry));
    uint8_t count = tx_history_get_count();
    if (index >= count) return false;
    char key[32];
    size_t len;
    make_key(key, sizeof(key), "txid", index);
    len = prefs.getBytesLength(key);
    if (len != TX_HISTORY_TXID_LEN) return false;
    prefs.getBytes(key, entry->txid, TX_HISTORY_TXID_LEN);
    make_key(key, sizeof(key), "dir", index);
    entry->direction = (char)prefs.getUChar(key, 0);
    make_key(key, sizeof(key), "amount", index);
    entry->amount_sats = prefs.getULong64(key, 0);
    make_key(key, sizeof(key), "conf", index);
    entry->confirmations = prefs.getUInt(key, 0);
    return true;
}

void tx_history_add_entry(const uint8_t txid[TX_HISTORY_TXID_LEN],
                          char direction, uint64_t amount_sats,
                          uint32_t confirmations) {
    if (!txid) return;
    uint8_t count = tx_history_get_count();
    uint8_t idx;
    if (count < TX_HISTORY_MAX_ENTRIES) {
        idx = count;
        count++;
    } else {
        for (uint8_t i = 0; i < TX_HISTORY_MAX_ENTRIES - 1; i++) {
            tx_history_entry_t next;
            if (tx_history_get_entry(i + 1, &next)) {
                char key[32];
                make_key(key, sizeof(key), "txid", i);
                prefs.putBytes(key, next.txid, TX_HISTORY_TXID_LEN);
                make_key(key, sizeof(key), "dir", i);
                prefs.putUChar(key, (uint8_t)next.direction);
                make_key(key, sizeof(key), "amount", i);
                prefs.putULong64(key, next.amount_sats);
                make_key(key, sizeof(key), "conf", i);
                prefs.putUInt(key, next.confirmations);
            }
        }
        idx = TX_HISTORY_MAX_ENTRIES - 1;
    }
    char key[32];
    make_key(key, sizeof(key), "txid", idx);
    prefs.putBytes(key, txid, TX_HISTORY_TXID_LEN);
    make_key(key, sizeof(key), "dir", idx);
    prefs.putUChar(key, (uint8_t)direction);
    make_key(key, sizeof(key), "amount", idx);
    prefs.putULong64(key, amount_sats);
    make_key(key, sizeof(key), "conf", idx);
    prefs.putUInt(key, confirmations);
    prefs.putUChar(KEY_COUNT, count);
}

void tx_history_nvs_erase(void) {
    prefs.begin(NVS_NAMESPACE, false);
    prefs.clear();
    prefs.end();
}

#else

static tx_history_entry_t g_entries[TX_HISTORY_MAX_ENTRIES];
static uint8_t            g_count    = 0;
static bool               g_inited   = false;

void tx_history_init(void) {
    if (!g_inited) {
        memset(g_entries, 0, sizeof(g_entries));
        g_count  = 0;
        g_inited = true;
    }
}

bool tx_history_has_cached(void) {
    tx_history_init();
    return g_count > 0;
}

uint8_t tx_history_get_count(void) {
    tx_history_init();
    return g_count;
}

bool tx_history_get_entry(uint8_t index, tx_history_entry_t *entry) {
    tx_history_init();
    if (!entry) return false;
    memset(entry, 0, sizeof(*entry));
    if (index >= g_count) return false;
    memcpy(entry, &g_entries[index], sizeof(*entry));
    return true;
}

void tx_history_add_entry(const uint8_t txid[TX_HISTORY_TXID_LEN],
                          char direction, uint64_t amount_sats,
                          uint32_t confirmations) {
    tx_history_init();
    if (!txid) return;
    uint8_t idx;
    if (g_count < TX_HISTORY_MAX_ENTRIES) {
        idx = g_count;
        g_count++;
    } else {
        for (uint8_t i = 0; i < TX_HISTORY_MAX_ENTRIES - 1; i++) {
            memcpy(&g_entries[i], &g_entries[i + 1], sizeof(tx_history_entry_t));
        }
        idx = TX_HISTORY_MAX_ENTRIES - 1;
    }
    memcpy(g_entries[idx].txid, txid, TX_HISTORY_TXID_LEN);
    g_entries[idx].direction     = direction;
    g_entries[idx].amount_sats   = amount_sats;
    g_entries[idx].confirmations = confirmations;
}

void tx_history_nvs_erase(void) {
    tx_history_init();
    memset(g_entries, 0, sizeof(g_entries));
    g_count = 0;
}

#endif
