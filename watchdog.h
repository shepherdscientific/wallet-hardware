#ifndef WATCHDOG_H
#define WATCHDOG_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WATCHDOG_TIMEOUT_SEC  10
#define WATCHDOG_CRASH_LOG_LEN 128

void watchdog_init(void);
void watchdog_feed(void);

bool watchdog_last_reset_was_wdt(void);
const char *watchdog_last_reset_reason(void);

void watchdog_set_signing_active(bool active);
bool watchdog_is_signing_active(void);
void watchdog_clear_signing_active(void);

const char *watchdog_get_last_crash(void);

#ifdef __cplusplus
}
#endif

#endif
