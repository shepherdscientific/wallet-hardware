#ifndef PIN_MANAGER_H
#define PIN_MANAGER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define PIN_LEN 6
#define PIN_MAX_ATTEMPTS 5

bool pin_is_set(void);

bool pin_setup(const uint8_t pin[PIN_LEN]);

bool pin_verify(const uint8_t pin[PIN_LEN]);

bool pin_change(const uint8_t old_pin[PIN_LEN],
                const uint8_t new_pin[PIN_LEN]);

void pin_reset(void);

uint8_t pin_get_attempts(void);

void pin_increment_attempts(void);

void pin_reset_attempts(void);

void pin_get_device_uid(uint8_t uid[8]);

void wallet_factory_reset(void);

#ifdef __cplusplus
}
#endif

#endif
