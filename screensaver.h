#ifndef SCREENSAVER_H
#define SCREENSAVER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef SCREENSAVER_TIMEOUT_MS
#define SCREENSAVER_TIMEOUT_MS 30000UL
#endif

#define SCREENSAVER_BLOCK_W  48
#define SCREENSAVER_BLOCK_H  49
#define SCREENSAVER_BITMAP_W 40
#define SCREENSAVER_BITMAP_H 40

#define SCREENSAVER_FRAME_MS 50

void screensaver_reset(void);
bool screensaver_should_activate(unsigned long idle_ms);
bool screensaver_update_position(int16_t canvas_w, int16_t canvas_h, unsigned long now_ms);
void screensaver_get_position(int16_t *x, int16_t *y);
int8_t screensaver_get_dx(void);
int8_t screensaver_get_dy(void);

#ifdef __cplusplus
}
#endif

#endif
