#ifndef SETTINGS_H
#define SETTINGS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  SETTINGS_DISP_TIMEOUT_30S  = 0,
  SETTINGS_DISP_TIMEOUT_1M   = 1,
  SETTINGS_DISP_TIMEOUT_2M   = 2,
  SETTINGS_DISP_TIMEOUT_5M   = 3,
  SETTINGS_DISP_TIMEOUT_NEVER = 4,
  SETTINGS_DISP_TIMEOUT_COUNT = 5
} settings_disp_timeout_t;

typedef enum {
  SETTINGS_AUTOLOCK_1M    = 0,
  SETTINGS_AUTOLOCK_5M    = 1,
  SETTINGS_AUTOLOCK_15M   = 2,
  SETTINGS_AUTOLOCK_30M   = 3,
  SETTINGS_AUTOLOCK_NEVER = 4,
  SETTINGS_AUTOLOCK_COUNT = 5
} settings_autolock_t;

#define SETTINGS_CONTRAST_MIN     0
#define SETTINGS_CONTRAST_MAX     255
#define SETTINGS_CONTRAST_STEP    32
#define SETTINGS_CONTRAST_DEFAULT 128

void settings_init(void);

uint8_t settings_get_display_timeout(void);
void    settings_set_display_timeout(uint8_t val);

uint8_t settings_get_auto_lock(void);
void    settings_set_auto_lock(uint8_t val);

uint8_t settings_get_contrast(void);
void    settings_set_contrast(uint8_t val);

uint32_t    settings_disp_timeout_ms(uint8_t val);
uint32_t    settings_auto_lock_ms(uint8_t val);
const char *settings_disp_timeout_label(uint8_t val);
const char *settings_auto_lock_label(uint8_t val);

#ifdef __cplusplus
}
#endif

#endif
