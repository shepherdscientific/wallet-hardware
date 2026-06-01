#include "screensaver.h"

static int16_t   s_x         = 44;
static int16_t   s_y         = 7;
static int8_t    s_dx        = 1;
static int8_t    s_dy        = 1;
static unsigned long s_last_ms = 0;
static unsigned long s_prev_ms = 0;

void screensaver_reset(void) {
  s_x  = 44;
  s_y  = 7;
  s_dx = 1;
  s_dy = 1;
  s_last_ms = 0;
  s_prev_ms = 0;
}

bool screensaver_should_activate(unsigned long idle_ms) {
  return idle_ms >= SCREENSAVER_TIMEOUT_MS;
}

bool screensaver_update_position(int16_t canvas_w, int16_t canvas_h, unsigned long now_ms) {
  if (now_ms - s_last_ms < SCREENSAVER_FRAME_MS) {
    return false;
  }
  s_last_ms = now_ms;

  int16_t max_x = canvas_w - SCREENSAVER_BLOCK_W;
  int16_t max_y = canvas_h - SCREENSAVER_BLOCK_H;

  int16_t new_x = s_x + s_dx;
  int16_t new_y = s_y + s_dy;

  bool bounced = false;

  if (new_x <= 0) {
    new_x = 0;
    s_dx  = 1;
    bounced = true;
  } else if (new_x >= max_x) {
    new_x = max_x;
    s_dx  = -1;
    bounced = true;
  }

  if (new_y <= 0) {
    new_y = 0;
    s_dy  = 1;
    bounced = true;
  } else if (new_y >= max_y) {
    new_y = max_y;
    s_dy  = -1;
    bounced = true;
  }

  bool moved = (new_x != s_x || new_y != s_y);
  s_x = new_x;
  s_y = new_y;

  s_prev_ms = now_ms;

  return moved;
}

void screensaver_get_position(int16_t *x, int16_t *y) {
  *x = s_x;
  *y = s_y;
}

int8_t screensaver_get_dx(void) { return s_dx; }
int8_t screensaver_get_dy(void) { return s_dy; }
