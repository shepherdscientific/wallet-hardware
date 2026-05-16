#include "watchdog.h"
#include <cstring>
#include <cstdio>

#if defined(ARDUINO) && defined(ESP32)
#include <esp_task_wdt.h>
#include <esp_system.h>
#include <Preferences.h>
#endif

#define NVS_NAMESPACE         "watchdog"
#define KEY_SIGNING_ACTIVE    "signing_active"
#define KEY_LAST_CRASH        "last_crash"

// ---------------------------------------------------------------------------
// ESP32 backend
// ---------------------------------------------------------------------------
#if defined(ARDUINO) && defined(ESP32)

static Preferences wd_prefs;
static bool wd_initialized = false;

void watchdog_init(void) {
    wd_prefs.begin(NVS_NAMESPACE, false);

    if (!wd_prefs.isKey(KEY_SIGNING_ACTIVE)) {
        wd_prefs.putUChar(KEY_SIGNING_ACTIVE, 0);
    }
    if (!wd_prefs.isKey(KEY_LAST_CRASH)) {
        wd_prefs.putString(KEY_LAST_CRASH, "");
    }

    esp_task_wdt_init(WATCHDOG_TIMEOUT_SEC, true);
    esp_task_wdt_add(NULL);

    const char *reset_str = watchdog_last_reset_reason();
    if (reset_str) {
        wd_prefs.putString(KEY_LAST_CRASH, reset_str);
    }

    wd_initialized = true;
}

void watchdog_feed(void) {
    if (wd_initialized) {
        esp_task_wdt_reset();
    }
}

static esp_reset_reason_t cached_reset_reason = ESP_RST_UNKNOWN;
static bool reset_reason_cached = false;

static esp_reset_reason_t get_cached_reset_reason(void) {
    if (!reset_reason_cached) {
        cached_reset_reason = esp_reset_reason();
        reset_reason_cached = true;
    }
    return cached_reset_reason;
}

bool watchdog_last_reset_was_wdt(void) {
    esp_reset_reason_t reason = get_cached_reset_reason();
    return (reason == ESP_RST_WDT ||
            reason == ESP_RST_TASK_WDT ||
            reason == ESP_RST_INT_WDT);
}

const char *watchdog_last_reset_reason(void) {
    esp_reset_reason_t reason = get_cached_reset_reason();
    switch (reason) {
        case ESP_RST_UNKNOWN:    return "Unknown reset";
        case ESP_RST_POWERON:    return nullptr;
        case ESP_RST_EXT:        return nullptr;
        case ESP_RST_SW:         return "Software reset";
        case ESP_RST_PANIC:      return "Panic: unrecoverable error";
        case ESP_RST_INT_WDT:    return "WDT: interrupt watchdog reset";
        case ESP_RST_TASK_WDT:   return "WDT: task watchdog reset";
        case ESP_RST_WDT:        return "WDT: hardware watchdog reset";
        case ESP_RST_DEEPSLEEP:  return nullptr;
        case ESP_RST_BROWNOUT:   return "Brownout reset";
        case ESP_RST_SDIO:       return "SDIO reset";
        default:                 return "Unknown reset reason";
    }
}

void watchdog_set_signing_active(bool active) {
    wd_prefs.putUChar(KEY_SIGNING_ACTIVE, active ? 1 : 0);
}

bool watchdog_is_signing_active(void) {
    return wd_prefs.getUChar(KEY_SIGNING_ACTIVE, 0) == 1;
}

void watchdog_clear_signing_active(void) {
    wd_prefs.putUChar(KEY_SIGNING_ACTIVE, 0);
}

const char *watchdog_get_last_crash(void) {
    static char crash_buf[WATCHDOG_CRASH_LOG_LEN + 1];
    String val = wd_prefs.getString(KEY_LAST_CRASH, "");
    if (val.length() > 0) {
        strncpy(crash_buf, val.c_str(), WATCHDOG_CRASH_LOG_LEN);
        crash_buf[WATCHDOG_CRASH_LOG_LEN] = '\0';
        return crash_buf;
    }
    return nullptr;
}

// ---------------------------------------------------------------------------
// Host / CI stub backend (in-memory store)
// ---------------------------------------------------------------------------
#else

static uint8_t g_signing_active  = 0;
static char    g_last_crash[WATCHDOG_CRASH_LOG_LEN + 1] = "";
static bool    g_was_wdt_reset   = false;

void watchdog_init(void) {
    g_signing_active = 0;
    g_last_crash[0]  = '\0';
    g_was_wdt_reset  = false;
}

void watchdog_feed(void) {
}

bool watchdog_last_reset_was_wdt(void) {
    return g_was_wdt_reset;
}

const char *watchdog_last_reset_reason(void) {
    if (g_was_wdt_reset) return "WDT: task watchdog reset";
    return nullptr;
}

void watchdog_set_signing_active(bool active) {
    g_signing_active = active ? 1 : 0;
}

bool watchdog_is_signing_active(void) {
    return g_signing_active == 1;
}

void watchdog_clear_signing_active(void) {
    g_signing_active = 0;
}

const char *watchdog_get_last_crash(void) {
    if (g_last_crash[0] != '\0') return g_last_crash;
    return nullptr;
}

#endif
