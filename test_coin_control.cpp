#include "psbt.h"
#include "psbt_signer.h"
#include "se051_hal.h"
#include "bip32.h"
#include "sha256.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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

static void setup_se_keys(void) {
  se051_init();
  uint8_t key[32]; memset(key, 0x01, sizeof(key));
  se051_store_key(SE051_KEY_BIP32_MASTER, key, sizeof(key));
  uint8_t chain[32]; memset(chain, 0x02, sizeof(chain));
  se051_store_key(SE051_KEY_CHAIN_CODE, chain, sizeof(chain));
}

static void teardown_se_keys(void) {
  se051_delete_key(SE051_KEY_BIP32_MASTER);
  se051_delete_key(SE051_KEY_CHAIN_CODE);
}

static void setup_multi_input_psbt_hardened(psbt_t *psbt, uint32_t input_count) {
  memset(psbt, 0, sizeof(*psbt));
  psbt->version = 0;
  psbt->input_count = input_count;
  psbt->output_count = 1;
  psbt->tx_version = 1;
  psbt->locktime = 0;

  for (uint32_t i = 0; i < input_count; i++) {
    psbt_input_t *inp = &psbt->inputs[i];

    memset(inp->txid, (int)i, 32);
    inp->vout = i;
    inp->sequence = 0xFFFFFFFE;

    inp->witness_utxo.present = true;
    inp->witness_utxo.amount = 100000000ULL + i * 10000000ULL;

    inp->witness_utxo.script_pubkey_len = 22;
    inp->witness_utxo.script_pubkey[0] = 0x00;
    inp->witness_utxo.script_pubkey[1] = 0x14;
    for (int j = 0; j < 20; j++)
      inp->witness_utxo.script_pubkey[2 + j] = (uint8_t)(i * 20 + j);

    inp->bip32_derivation.present = true;
    inp->bip32_derivation.fingerprint[0] = 0xaa;
    inp->bip32_derivation.fingerprint[1] = 0xbb;
    inp->bip32_derivation.fingerprint[2] = 0xcc;
    inp->bip32_derivation.fingerprint[3] = 0xdd;

    inp->bip32_derivation.path[0] = 0x80000054;
    inp->bip32_derivation.path[1] = 0x80000000;
    inp->bip32_derivation.path[2] = 0x80000000;
    inp->bip32_derivation.path[3] = 0x80000000;
    inp->bip32_derivation.path[4] = 0x80000000 | i;
    inp->bip32_derivation.path_len = 5;

    for (int j = 0; j < 33; j++)
      inp->bip32_derivation.pubkey[j] = (uint8_t)(i * 33 + j + 10);
  }

  psbt->outputs[0].amount = 50000000ULL;
  psbt->outputs[0].script_pubkey[0] = 0x00;
  psbt->outputs[0].script_pubkey[1] = 0x14;
  for (int j = 0; j < 20; j++)
    psbt->outputs[0].script_pubkey[2 + j] = (uint8_t)j;
  psbt->outputs[0].script_pubkey_len = 22;
}

#define CHECK_SIGNED(n) (psbt.inputs[(n)].has_partial_sig)

static void test_sign_all_selected(void) {
  TEST("psbt_sign with all inputs selected");
  setup_se_keys();

  psbt_t psbt;
  setup_multi_input_psbt_hardened(&psbt, 3);

  bool selected[4] = {true, true, true, false};
  int result = psbt_sign(&psbt, selected);
  ASSERT_EQ(result, 3, "expected 3 signatures");
  ASSERT_TRUE(CHECK_SIGNED(0), "input 0 not signed");
  ASSERT_TRUE(CHECK_SIGNED(1), "input 1 not signed");
  ASSERT_TRUE(CHECK_SIGNED(2), "input 2 not signed");

  teardown_se_keys();
  PASS();
}

static void test_sign_subset(void) {
  TEST("psbt_sign with subset of inputs selected");
  setup_se_keys();

  psbt_t psbt;
  setup_multi_input_psbt_hardened(&psbt, 3);

  bool selected[4] = {true, false, true, false};
  int result = psbt_sign(&psbt, selected);
  ASSERT_EQ(result, 2, "expected 2 signatures");
  ASSERT_TRUE(CHECK_SIGNED(0), "input 0 not signed");
  ASSERT_TRUE(!CHECK_SIGNED(1), "input 1 should NOT be signed");
  ASSERT_TRUE(CHECK_SIGNED(2), "input 2 not signed");

  teardown_se_keys();
  PASS();
}

static void test_sign_none_selected(void) {
  TEST("psbt_sign with no inputs selected");
  setup_se_keys();

  psbt_t psbt;
  setup_multi_input_psbt_hardened(&psbt, 3);

  bool selected[4] = {false, false, false, false};
  int result = psbt_sign(&psbt, selected);
  ASSERT_EQ(result, 0, "expected 0 signatures");
  ASSERT_TRUE(!CHECK_SIGNED(0), "input 0 should NOT be signed");
  ASSERT_TRUE(!CHECK_SIGNED(1), "input 1 should NOT be signed");
  ASSERT_TRUE(!CHECK_SIGNED(2), "input 2 should NOT be signed");

  teardown_se_keys();
  PASS();
}

static void test_sign_single_input(void) {
  TEST("psbt_sign single input with all selected");
  setup_se_keys();

  psbt_t psbt;
  setup_multi_input_psbt_hardened(&psbt, 1);

  bool selected[4] = {true, false, false, false};
  int result = psbt_sign(&psbt, selected);
  ASSERT_EQ(result, 1, "expected 1 signature");
  ASSERT_TRUE(CHECK_SIGNED(0), "input 0 not signed");

  teardown_se_keys();
  PASS();
}

static void test_sign_first_only(void) {
  TEST("psbt_sign with only first input selected");
  setup_se_keys();

  psbt_t psbt;
  setup_multi_input_psbt_hardened(&psbt, 3);

  bool selected[4] = {true, false, false, false};
  int result = psbt_sign(&psbt, selected);
  ASSERT_EQ(result, 1, "expected 1 signature");
  ASSERT_TRUE(CHECK_SIGNED(0), "input 0 not signed");
  ASSERT_TRUE(!CHECK_SIGNED(1), "input 1 should NOT be signed");
  ASSERT_TRUE(!CHECK_SIGNED(2), "input 2 should NOT be signed");

  teardown_se_keys();
  PASS();
}

static void test_sign_last_only(void) {
  TEST("psbt_sign with only last input selected");
  setup_se_keys();

  psbt_t psbt;
  setup_multi_input_psbt_hardened(&psbt, 3);

  bool selected[4] = {false, false, true, false};
  int result = psbt_sign(&psbt, selected);
  ASSERT_EQ(result, 1, "expected 1 signature");
  ASSERT_TRUE(!CHECK_SIGNED(0), "input 0 should NOT be signed");
  ASSERT_TRUE(!CHECK_SIGNED(1), "input 1 should NOT be signed");
  ASSERT_TRUE(CHECK_SIGNED(2), "input 2 not signed");

  teardown_se_keys();
  PASS();
}

static void test_sign_null_psbt(void) {
  TEST("psbt_sign with NULL psbt");
  bool selected[4] = {true, false, false, false};
  int result = psbt_sign(NULL, selected);
  ASSERT_EQ(result, PSBT_SIGN_ERR_PARAM, "expected error for NULL psbt");
  PASS();
}

static void test_sign_null_selected(void) {
  TEST("psbt_sign with NULL selected (signs all)");
  setup_se_keys();

  psbt_t psbt;
  setup_multi_input_psbt_hardened(&psbt, 2);

  int result = psbt_sign(&psbt, NULL);
  ASSERT_EQ(result, 2, "NULL selected should sign all inputs");
  ASSERT_TRUE(CHECK_SIGNED(0), "input 0 not signed");
  ASSERT_TRUE(CHECK_SIGNED(1), "input 1 not signed");

  teardown_se_keys();
  PASS();
}

int main(void) {
  printf("Coin Control Unit Tests (psbt_sign selected array)\n\n");

  test_sign_all_selected();
  test_sign_subset();
  test_sign_none_selected();
  test_sign_single_input();
  test_sign_first_only();
  test_sign_last_only();
  test_sign_null_psbt();
  test_sign_null_selected();

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
