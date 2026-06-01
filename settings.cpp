#include "settings.h"
#include <cstring>
#include <cstdio>

#if defined(ARDUINO) && defined(ESP32)
#include <Preferences.h>
#endif

#define NVS_NAMESPACE      "settings"
#define KEY_DISP_TIMEOUT   "disp_timeout"
#define KEY_AUTO_LOCK      "auto_lock"
#define KEY_CONTRAST       "contrast"

// ---------------------------------------------------------------------------
// ESP32 NVS (Preferences) backend
// ---------------------------------------------------------------------------
#if defined(ARDUINO) && defined(ESP32)

static Preferences prefs;

void settings_init(void) {
    prefs.begin(NVS_NAMESPACE, false);
    if (!prefs.isKey(KEY_DISP_TIMEOUT)) {
        prefs.putUChar(KEY_DISP_TIMEOUT, (uint8_t)SETTINGS_DISP_TIMEOUT_30S);
    }
    if (!prefs.isKey(KEY_AUTO_LOCK)) {
        prefs.putUChar(KEY_AUTO_LOCK, (uint8_t)SETTINGS_AUTOLOCK_1M);
    }
    if (!prefs.isKey(KEY_CONTRAST)) {
        prefs.putUChar(KEY_CONTRAST, SETTINGS_CONTRAST_DEFAULT);
    }
}

uint8_t settings_get_display_timeout(void) {
    uint8_t v = prefs.getUChar(KEY_DISP_TIMEOUT, SETTINGS_DISP_TIMEOUT_30S);
    if (v >= SETTINGS_DISP_TIMEOUT_COUNT) v = SETTINGS_DISP_TIMEOUT_30S;
    return v;
}

void settings_set_display_timeout(uint8_t val) {
    if (val >= SETTINGS_DISP_TIMEOUT_COUNT) return;
    prefs.putUChar(KEY_DISP_TIMEOUT, val);
}

uint8_t settings_get_auto_lock(void) {
    uint8_t v = prefs.getUChar(KEY_AUTO_LOCK, SETTINGS_AUTOLOCK_1M);
    if (v >= SETTINGS_AUTOLOCK_COUNT) v = SETTINGS_AUTOLOCK_1M;
    return v;
}

void settings_set_auto_lock(uint8_t val) {
    if (val >= SETTINGS_AUTOLOCK_COUNT) return;
    prefs.putUChar(KEY_AUTO_LOCK, val);
}

uint8_t settings_get_contrast(void) {
    return prefs.getUChar(KEY_CONTRAST, SETTINGS_CONTRAST_DEFAULT);
}

void settings_set_contrast(uint8_t val) {
    prefs.putUChar(KEY_CONTRAST, val);
}

// ---------------------------------------------------------------------------
// Host / CI stub backend (in-memory store)
// ---------------------------------------------------------------------------
#else

static uint8_t g_disp_timeout = SETTINGS_DISP_TIMEOUT_30S;
static uint8_t g_auto_lock    = SETTINGS_AUTOLOCK_1M;
static uint8_t g_contrast     = SETTINGS_CONTRAST_DEFAULT;

void settings_init(void) {
    g_disp_timeout = SETTINGS_DISP_TIMEOUT_30S;
    g_auto_lock    = SETTINGS_AUTOLOCK_1M;
    g_contrast     = SETTINGS_CONTRAST_DEFAULT;
}

uint8_t settings_get_display_timeout(void) {
    if (g_disp_timeout >= SETTINGS_DISP_TIMEOUT_COUNT) g_disp_timeout = SETTINGS_DISP_TIMEOUT_30S;
    return g_disp_timeout;
}

void settings_set_display_timeout(uint8_t val) {
    if (val >= SETTINGS_DISP_TIMEOUT_COUNT) return;
    g_disp_timeout = val;
}

uint8_t settings_get_auto_lock(void) {
    if (g_auto_lock >= SETTINGS_AUTOLOCK_COUNT) g_auto_lock = SETTINGS_AUTOLOCK_1M;
    return g_auto_lock;
}

void settings_set_auto_lock(uint8_t val) {
    if (val >= SETTINGS_AUTOLOCK_COUNT) return;
    g_auto_lock = val;
}

uint8_t settings_get_contrast(void) {
    return g_contrast;
}

void settings_set_contrast(uint8_t val) {
    g_contrast = val;
}

#endif

// ---------------------------------------------------------------------------
// Shared utilities (no NVS / Preferences dependency)
// ---------------------------------------------------------------------------
uint32_t settings_disp_timeout_ms(uint8_t val) {
    switch (val) {
        case SETTINGS_DISP_TIMEOUT_30S:   return 30000;
        case SETTINGS_DISP_TIMEOUT_1M:    return 60000;
        case SETTINGS_DISP_TIMEOUT_2M:    return 120000;
        case SETTINGS_DISP_TIMEOUT_5M:    return 300000;
        case SETTINGS_DISP_TIMEOUT_NEVER: return 0;
        default:                          return 30000;
    }
}

uint32_t settings_auto_lock_ms(uint8_t val) {
    switch (val) {
        case SETTINGS_AUTOLOCK_1M:    return 60000;
        case SETTINGS_AUTOLOCK_5M:    return 300000;
        case SETTINGS_AUTOLOCK_15M:   return 900000;
        case SETTINGS_AUTOLOCK_30M:   return 1800000;
        case SETTINGS_AUTOLOCK_NEVER: return 0;
        default:                      return 60000;
    }
}

const char *settings_disp_timeout_label(uint8_t val) {
    switch (val) {
        case SETTINGS_DISP_TIMEOUT_30S:   return "30s";
        case SETTINGS_DISP_TIMEOUT_1M:    return "1m";
        case SETTINGS_DISP_TIMEOUT_2M:    return "2m";
        case SETTINGS_DISP_TIMEOUT_5M:    return "5m";
        case SETTINGS_DISP_TIMEOUT_NEVER: return "Never";
        default:                          return "?";
    }
}

const char *settings_auto_lock_label(uint8_t val) {
    switch (val) {
        case SETTINGS_AUTOLOCK_1M:    return "1m";
        case SETTINGS_AUTOLOCK_5M:    return "5m";
        case SETTINGS_AUTOLOCK_15M:   return "15m";
        case SETTINGS_AUTOLOCK_30M:   return "30m";
        case SETTINGS_AUTOLOCK_NEVER: return "Never";
        default:                      return "?";
    }
}

void settings_nvs_erase(void) {
#if defined(ARDUINO) && defined(ESP32)
    prefs.begin(NVS_NAMESPACE, false);
    prefs.clear();
    prefs.end();
#endif
}
