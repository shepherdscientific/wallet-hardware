#include "screensaver.h"
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
  printf("  %s ... ", (name)); fflush(stdout); \
} while(0)

#define PASS() do { \
  printf("PASS\n"); fflush(stdout); tests_passed++; \
} while(0)

#define FAIL(msg) do { \
  printf("FAIL: %s\n", (msg)); fflush(stdout); tests_failed++; \
} while(0)

#define ASSERT_EQ(a, b, msg) do { \
  if ((a) != (b)) { FAIL(msg); return; } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
  if (!(cond)) { FAIL(msg); return; } \
} while(0)

#define ASSERT_FALSE(cond, msg) do { \
  if (cond) { FAIL(msg); return; } \
} while(0)

static void test_initial_position(void) {
  TEST("initial position after reset");
  screensaver_reset();
  int16_t x = 0, y = 0;
  screensaver_get_position(&x, &y);
  ASSERT_EQ(x, 44, "initial x should be 44");
  ASSERT_EQ(y, 7, "initial y should be 7");
  PASS();
}

static void test_initial_velocity(void) {
  TEST("initial velocity after reset");
  screensaver_reset();
  ASSERT_EQ(screensaver_get_dx(), 1, "dx should be 1");
  ASSERT_EQ(screensaver_get_dy(), 1, "dy should be 1");
  PASS();
}

static void test_timeout_activation(void) {
  TEST("timeout detection");
  screensaver_reset();
  ASSERT_FALSE(screensaver_should_activate(29999), "29999 ms should not activate");
  ASSERT_TRUE(screensaver_should_activate(30000), "30000 ms should activate");
  ASSERT_TRUE(screensaver_should_activate(100000), "100000 ms should activate");
  PASS();
}

static void test_position_update_basic(void) {
  TEST("position update with velocity");
  screensaver_reset();

  int16_t x = 0, y = 0;
  bool moved = screensaver_update_position(128, 64, 50UL);
  ASSERT_TRUE(moved, "should move at t=50");
  screensaver_get_position(&x, &y);
  ASSERT_EQ(x, 45, "x should advance by 1");
  ASSERT_EQ(y, 8, "y should advance by 1");
  PASS();
}

static void test_frame_rate_limiting(void) {
  TEST("frame rate limiting");
  screensaver_reset();

  bool moved = screensaver_update_position(128, 64, 30UL);
  ASSERT_FALSE(moved, "should not move at t=30 (< 50 ms)");
  PASS();
}

static void test_position_unchanged_on_skip(void) {
  TEST("position unchanged when frame skipped");
  screensaver_reset();

  int16_t x = 0, y = 0;
  screensaver_update_position(128, 64, 50UL);
  screensaver_get_position(&x, &y);
  ASSERT_EQ(x, 45, "x=45 after first frame");

  screensaver_update_position(128, 64, 55UL);
  screensaver_get_position(&x, &y);
  ASSERT_EQ(x, 45, "x should not change (5ms since last frame)");

  screensaver_update_position(128, 64, 105UL);
  screensaver_get_position(&x, &y);
  ASSERT_EQ(x, 46, "x should advance at t=105 (>50ms since last)");
  PASS();
}

static void test_left_boundary_bounce(void) {
  TEST("left boundary bounce");
  screensaver_reset();
  int16_t x = 0, y = 0;

  bool dx_seen_positive = false;
  unsigned long t = 0;
  for (int i = 0; i < 200; i++) {
    t += 50;
    screensaver_update_position(128, 64, t);
    if (screensaver_get_dx() == 1) dx_seen_positive = true;
  }

  screensaver_get_position(&x, &y);
  ASSERT_TRUE(x >= 0, "x should be >= 0");
  ASSERT_TRUE(x <= 80, "x should be <= 80");
  ASSERT_TRUE(dx_seen_positive, "dx should have been 1 at some point");
  PASS();
}

static void test_top_boundary_bounce(void) {
  TEST("top boundary bounce");
  screensaver_reset();
  int16_t x = 0, y = 0;

  for (int i = 0; i < 60; i++) {
    screensaver_update_position(128, 64, (unsigned long)((i + 1) * 50));
  }

  screensaver_get_position(&x, &y);
  ASSERT_TRUE(y >= 0, "y should be >= 0");
  ASSERT_TRUE(y <= 15, "y should be <= 15");
  PASS();
}

static void test_right_boundary_bounce(void) {
  TEST("right boundary bounce");
  screensaver_reset();

  int16_t x = 0, y = 0;
  unsigned long t = 0;
  for (int i = 0; i < 100; i++) {
    t += 50;
    screensaver_update_position(128, 64, t);
    screensaver_get_position(&x, &y);
    if (x >= 80) break;
  }

  ASSERT_EQ(x, 80, "should hit right boundary at 80");
  ASSERT_EQ(screensaver_get_dx(), -1, "dx should flip to -1 at right edge");
  PASS();
}

static void test_bottom_boundary_bounce(void) {
  TEST("bottom boundary bounce");
  screensaver_reset();

  int16_t x = 0, y = 0;
  unsigned long t = 0;
  for (int i = 0; i < 30; i++) {
    t += 50;
    screensaver_update_position(128, 64, t);
    screensaver_get_position(&x, &y);
    if (y >= 15) break;
  }

  ASSERT_EQ(y, 15, "should hit bottom boundary at 15");
  ASSERT_EQ(screensaver_get_dy(), -1, "dy should flip to -1 at bottom edge");
  PASS();
}

static void test_multiple_bounces(void) {
  TEST("survives multiple bounces");
  screensaver_reset();

  int16_t x = 0, y = 0;
  unsigned long t = 0;

  for (int i = 0; i < 500; i++) {
    t += 50;
    screensaver_update_position(128, 64, t);
    screensaver_get_position(&x, &y);
    ASSERT_TRUE(x >= 0 && x <= 80, "x out of bounds");
    ASSERT_TRUE(y >= 0 && y <= 15, "y out of bounds");
  }
  PASS();
}

static void test_reset_clears_state(void) {
  TEST("reset returns to initial state");
  screensaver_reset();

  for (int i = 0; i < 10; i++) {
    screensaver_update_position(128, 64, (unsigned long)((i + 1) * 50));
  }

  screensaver_reset();
  int16_t x = 0, y = 0;
  screensaver_get_position(&x, &y);
  ASSERT_EQ(x, 44, "x should reset to 44");
  ASSERT_EQ(y, 7, "y should reset to 7");
  ASSERT_EQ(screensaver_get_dx(), 1, "dx should reset to 1");
  ASSERT_EQ(screensaver_get_dy(), 1, "dy should reset to 1");
  PASS();
}

static void test_custom_canvas_size(void) {
  TEST("custom canvas size support");
  screensaver_reset();

  bool moved = screensaver_update_position(200, 120, 50UL);
  ASSERT_TRUE(moved, "should move on 200x120 canvas");
  int16_t x = 0, y = 0;
  screensaver_get_position(&x, &y);
  ASSERT_EQ(x, 45, "x should advance by 1");
  ASSERT_EQ(y, 8, "y should advance by 1");
  PASS();
}

static void test_inserted(void) {
  TEST("seeds no x assertion");
  screensaver_reset();
  int16_t initX = 0, initY = 0;
  screensaver_get_position(&initX, &initY);
  ASSERT_EQ(initX, 44, "x should be 44");
  ASSERT_EQ(initY, 7, "y should be 7");
  PASS();
}

int main(void) {
  printf("\n=== Screensaver Tests ===\n\n");

  test_initial_position();
  test_initial_velocity();
  test_timeout_activation();
  test_position_update_basic();
  test_frame_rate_limiting();
  test_position_unchanged_on_skip();
  test_left_boundary_bounce();
  test_top_boundary_bounce();
  test_right_boundary_bounce();
  test_bottom_boundary_bounce();
  test_multiple_bounces();
  test_reset_clears_state();
  test_custom_canvas_size();
  test_inserted();

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
