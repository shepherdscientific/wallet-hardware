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

#define ASSERT_FALSE(cond, msg) do { \
  if (cond) { FAIL(msg); return; } \
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

static void write_u8(uint8_t *buf, size_t *pos, uint8_t v) {
  buf[(*pos)++] = v;
}

static void write_u32le(uint8_t *buf, size_t *pos, uint32_t v) {
  buf[(*pos)++] = (uint8_t)(v & 0xFF);
  buf[(*pos)++] = (uint8_t)((v >> 8) & 0xFF);
  buf[(*pos)++] = (uint8_t)((v >> 16) & 0xFF);
  buf[(*pos)++] = (uint8_t)((v >> 24) & 0xFF);
}

static void write_u64le(uint8_t *buf, size_t *pos, uint64_t v) {
  for (int i = 0; i < 8; i++) {
    buf[(*pos)++] = (uint8_t)((v >> (i * 8)) & 0xFF);
  }
}

static void write_u16le(uint8_t *buf, size_t *pos, uint16_t v) {
  buf[(*pos)++] = (uint8_t)(v & 0xFF);
  buf[(*pos)++] = (uint8_t)((v >> 8) & 0xFF);
}

static void write_varint(uint8_t *buf, size_t *pos, uint64_t v) {
  if (v < 0xFD) {
    buf[(*pos)++] = (uint8_t)v;
  } else if (v <= 0xFFFF) {
    buf[(*pos)++] = 0xFD;
    write_u16le(buf, pos, (uint16_t)v);
  } else if (v <= 0xFFFFFFFF) {
    buf[(*pos)++] = 0xFE;
    write_u32le(buf, pos, (uint32_t)v);
  } else {
    buf[(*pos)++] = 0xFF;
    write_u64le(buf, pos, v);
  }
}

static void build_multisig_witness_script(uint8_t *out, size_t *len,
                                           uint8_t m, uint8_t n) {
  size_t pos = 0;
  out[pos++] = 0x50 + m;
  for (uint8_t j = 0; j < n; j++) {
    out[pos++] = 0x21;
    for (int k = 0; k < 33; k++)
      out[pos++] = (uint8_t)(0x10 + j * 33 + k);
  }
  out[pos++] = 0x50 + n;
  out[pos++] = 0xAE;
  *len = pos;
}

static void build_wit_utxo_with_script(uint8_t *wit_utxo, size_t *wpos,
                                        uint64_t amount,
                                        const uint8_t *spk, uint8_t spk_len) {
  *wpos = 0;
  write_u64le(wit_utxo, wpos, amount);
  write_u8(wit_utxo, wpos, spk_len);
  memcpy(wit_utxo + *wpos, spk, spk_len);
  *wpos += spk_len;
}

static uint8_t test_pubkey[33] = {
  0x02, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
  0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
  0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
  0x10, 0x10, 0x10
};

static void test_parse_multisig_witness_script(void) {
  TEST("PSBT parse: 2-of-3 P2WSH multisig witness script");

  psbt_input_t input;
  memset(&input, 0, sizeof(input));

  uint8_t script[256];
  size_t script_len;
  build_multisig_witness_script(script, &script_len, 2, 3);
  input.has_witness_script = true;
  memcpy(input.witness_script, script, script_len);
  input.witness_script_len = (uint8_t)script_len;

  psbt_analyze_multisig_input(&input);

  ASSERT_TRUE(input.is_multisig, "should detect multisig");
  ASSERT_EQ(input.multisig_m, 2, "M should be 2");
  ASSERT_EQ(input.multisig_n, 3, "N should be 3");
  ASSERT_EQ(input.multisig_existing_sigs, 0, "no existing sigs");
  PASS();
}

static void test_parse_multisig_2of2(void) {
  TEST("PSBT parse: 2-of-2 P2WSH multisig");

  psbt_input_t input;
  memset(&input, 0, sizeof(input));

  uint8_t script[256];
  size_t script_len;
  build_multisig_witness_script(script, &script_len, 2, 2);
  input.has_witness_script = true;
  memcpy(input.witness_script, script, script_len);
  input.witness_script_len = (uint8_t)script_len;

  psbt_analyze_multisig_input(&input);

  ASSERT_TRUE(input.is_multisig, "should detect 2-of-2 multisig");
  ASSERT_EQ(input.multisig_m, 2, "M should be 2");
  ASSERT_EQ(input.multisig_n, 2, "N should be 2");
  PASS();
}

static void test_parse_not_multisig_no_script(void) {
  TEST("PSBT parse: no script => not multisig");

  psbt_input_t input;
  memset(&input, 0, sizeof(input));

  psbt_analyze_multisig_input(&input);

  ASSERT_FALSE(input.is_multisig, "should not be multisig");
  PASS();
}

static void test_parse_not_multisig_bad_script(void) {
  TEST("PSBT parse: random bytes => not multisig");

  psbt_input_t input;
  memset(&input, 0, sizeof(input));
  input.has_witness_script = true;
  uint8_t bad[10] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
  memcpy(input.witness_script, bad, 10);
  input.witness_script_len = 10;

  psbt_analyze_multisig_input(&input);
  ASSERT_FALSE(input.is_multisig, "junk bytes should not be multisig");
  PASS();
}

static void test_parse_multisig_1of3(void) {
  TEST("PSBT parse: 1-of-3 P2WSH multisig");

  psbt_input_t input;
  memset(&input, 0, sizeof(input));

  uint8_t script[256];
  size_t script_len;
  build_multisig_witness_script(script, &script_len, 1, 3);
  input.has_witness_script = true;
  memcpy(input.witness_script, script, script_len);
  input.witness_script_len = (uint8_t)script_len;

  psbt_analyze_multisig_input(&input);

  ASSERT_TRUE(input.is_multisig, "should detect multisig");
  ASSERT_EQ(input.multisig_m, 1, "M should be 1");
  ASSERT_EQ(input.multisig_n, 3, "N should be 3");
  PASS();
}

static void test_multisig_participant_match(void) {
  TEST("psbt_multisig_is_participant: matching pubkey in script");

  psbt_input_t input;
  memset(&input, 0, sizeof(input));

  uint8_t script[256];
  size_t script_len;
  build_multisig_witness_script(script, &script_len, 2, 3);
  input.has_witness_script = true;
  memcpy(input.witness_script, script, script_len);
  input.witness_script_len = (uint8_t)script_len;
  input.is_multisig = true;

  uint8_t matching_key[33];
  for (int i = 0; i < 33; i++) matching_key[i] = (uint8_t)(0x10 + 1 * 33 + i);

  ASSERT_TRUE(psbt_multisig_is_participant(&input, matching_key),
              "should match second pubkey in script");
  PASS();
}

static void test_multisig_participant_no_match(void) {
  TEST("psbt_multisig_is_participant: non-matching pubkey");

  psbt_input_t input;
  memset(&input, 0, sizeof(input));

  uint8_t script[256];
  size_t script_len;
  build_multisig_witness_script(script, &script_len, 2, 3);
  input.has_witness_script = true;
  memcpy(input.witness_script, script, script_len);
  input.witness_script_len = (uint8_t)script_len;
  input.is_multisig = true;

  uint8_t non_matching_key[33];
  memset(non_matching_key, 0xFF, 33);
  non_matching_key[0] = 0x02;

  ASSERT_FALSE(psbt_multisig_is_participant(&input, non_matching_key),
               "should not match random pubkey");
  PASS();
}

static void test_multisig_participant_null(void) {
  TEST("psbt_multisig_is_participant: NULL safety");

  psbt_input_t input;
  memset(&input, 0, sizeof(input));
  input.is_multisig = true;

  ASSERT_FALSE(psbt_multisig_is_participant(&input, NULL), "NULL pubkey => false");
  ASSERT_FALSE(psbt_multisig_is_participant(NULL, test_pubkey), "NULL input => false");
  PASS();
}

static void test_multisig_participant_not_multisig(void) {
  TEST("psbt_multisig_is_participant: non-multisig input");

  psbt_input_t input;
  memset(&input, 0, sizeof(input));
  input.is_multisig = false;

  uint8_t script[256];
  size_t script_len;
  build_multisig_witness_script(script, &script_len, 2, 3);
  input.has_witness_script = true;
  memcpy(input.witness_script, script, script_len);
  input.witness_script_len = (uint8_t)script_len;

  ASSERT_FALSE(psbt_multisig_is_participant(&input, test_pubkey),
               "non-multisig input => false");
  PASS();
}

static void test_psbt_parse_v0_with_multisig(void) {
  TEST("PSBT v0 parse: P2WSH multisig input with witness script");

  static uint8_t txid[32]; memset(txid, 0xCC, 32);
  const uint8_t *txids[1] = { txid };
  uint32_t vouts[1] = { 0 };
  uint32_t sequences[1] = { 0xFFFFFFFF };
  uint64_t out_amounts[1] = { 50000 };

  uint8_t p2wsh_spk[34];
  p2wsh_spk[0] = 0x00; p2wsh_spk[1] = 0x20;
  memset(p2wsh_spk + 2, 0xDD, 32);
  const uint8_t *out_spks[1] = { p2wsh_spk };
  uint8_t out_spk_lens[1] = { 34 };

  uint8_t utx[512];
  size_t utx_pos = 0;
  write_u32le(utx, &utx_pos, 1);
  write_varint(utx, &utx_pos, 1);
  memcpy(utx + utx_pos, txids[0], 32); utx_pos += 32;
  write_u32le(utx, &utx_pos, vouts[0]);
  write_varint(utx, &utx_pos, 0);
  write_u32le(utx, &utx_pos, sequences[0]);
  write_varint(utx, &utx_pos, 1);
  write_u64le(utx, &utx_pos, out_amounts[0]);
  write_u8(utx, &utx_pos, 34);
  memcpy(utx + utx_pos, p2wsh_spk, 34); utx_pos += 34;
  write_u32le(utx, &utx_pos, 0);

  uint8_t wit_script[256];
  size_t wit_script_len;
  build_multisig_witness_script(wit_script, &wit_script_len, 2, 3);

  uint8_t wit_utxo[64];
  size_t wup = 0;
  write_u64le(wit_utxo, &wup, 100000000ULL);
  write_u8(wit_utxo, &wup, 34);
  memcpy(wit_utxo + wup, p2wsh_spk, 34); wup += 34;

  uint8_t psbt_buf[2048];
  size_t pos = 0;
  psbt_buf[pos++] = 0x70; psbt_buf[pos++] = 0x73;
  psbt_buf[pos++] = 0x62; psbt_buf[pos++] = 0x74;
  psbt_buf[pos++] = 0xFF;
  write_varint(psbt_buf, &pos, 1);
  write_u8(psbt_buf, &pos, 0x00);
  write_varint(psbt_buf, &pos, utx_pos);
  memcpy(psbt_buf + pos, utx, utx_pos); pos += utx_pos;
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 1);
  write_u8(psbt_buf, &pos, 0x01);
  write_varint(psbt_buf, &pos, wup);
  memcpy(psbt_buf + pos, wit_utxo, wup); pos += wup;
  write_varint(psbt_buf, &pos, 1);
  write_u8(psbt_buf, &pos, 0x05);
  write_varint(psbt_buf, &pos, wit_script_len);
  memcpy(psbt_buf + pos, wit_script, wit_script_len); pos += wit_script_len;
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 0);

  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt_err_t err = psbt_parse(psbt_buf, pos, &psbt);
  ASSERT_EQ(err, PSBT_OK, "parse should succeed");
  ASSERT_EQ(psbt.input_count, 1u, "should have 1 input");
  ASSERT_TRUE(psbt.inputs[0].is_multisig, "input should be multisig");
  ASSERT_EQ(psbt.inputs[0].multisig_m, 2, "M should be 2");
  ASSERT_EQ(psbt.inputs[0].multisig_n, 3, "N should be 3");
  ASSERT_TRUE(psbt.inputs[0].has_witness_script, "should have witness script");
  ASSERT_EQ(psbt.inputs[0].witness_script_len, (uint8_t)wit_script_len,
            "witness script length correct");
  PASS();
}

static void test_multisig_sign_no_participant(void) {
  TEST("psbt_sign: multisig input, key not a participant => NO_PARTICIPANT");

  setup_se_keys();

  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt.version = 0;
  psbt.input_count = 1;
  psbt.output_count = 1;
  psbt.tx_version = 1;
  psbt.locktime = 0;

  psbt_input_t *inp = &psbt.inputs[0];
  memset(inp->txid, 0xCC, 32);
  inp->vout = 0;
  inp->sequence = 0xFFFFFFFF;

  inp->witness_utxo.present = true;
  inp->witness_utxo.amount = 100000000ULL;
  inp->witness_utxo.script_pubkey_len = 22;
  inp->witness_utxo.script_pubkey[0] = 0x00;
  inp->witness_utxo.script_pubkey[1] = 0x14;
  for (int k = 0; k < 20; k++)
    inp->witness_utxo.script_pubkey[2 + k] = (uint8_t)k;

  uint8_t script[256];
  size_t script_len;
  build_multisig_witness_script(script, &script_len, 2, 3);
  inp->has_witness_script = true;
  memcpy(inp->witness_script, script, script_len);
  inp->witness_script_len = (uint8_t)script_len;
  inp->is_multisig = true;
  inp->multisig_m = 2;
  inp->multisig_n = 3;

  inp->bip32_derivation.present = true;
  inp->bip32_derivation.fingerprint[0] = 0xAA;
  inp->bip32_derivation.fingerprint[1] = 0xBB;
  inp->bip32_derivation.fingerprint[2] = 0xCC;
  inp->bip32_derivation.fingerprint[3] = 0xDD;
  inp->bip32_derivation.path[0] = 0x80000054;
  inp->bip32_derivation.path[1] = 0x80000000;
  inp->bip32_derivation.path[2] = 0x80000000;
  inp->bip32_derivation.path[3] = 0x80000000;
  inp->bip32_derivation.path[4] = 0x80000000;
  inp->bip32_derivation.path_len = 5;

  psbt.outputs[0].amount = 50000000ULL;
  psbt.outputs[0].script_pubkey[0] = 0x00;
  psbt.outputs[0].script_pubkey[1] = 0x14;
  psbt.outputs[0].script_pubkey_len = 22;

  bool selected[4] = {true, false, false, false};
  int result = psbt_sign(&psbt, selected);
  ASSERT_EQ(result, PSBT_SIGN_ERR_NO_PARTICIPANT,
            "no matching key => NO_PARTICIPANT");

  teardown_se_keys();
  PASS();
}

static void test_multisig_no_bip32_path(void) {
  TEST("psbt_sign: multisig input without BIP32 path => skipped");

  setup_se_keys();

  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt.version = 0;
  psbt.input_count = 1;
  psbt.output_count = 1;
  psbt.tx_version = 1;
  psbt.locktime = 0;

  psbt_input_t *inp = &psbt.inputs[0];
  memset(inp->txid, 0xDD, 32);
  inp->vout = 0;
  inp->sequence = 0xFFFFFFFF;
  inp->witness_utxo.present = true;
  inp->witness_utxo.amount = 100000000ULL;
  inp->witness_utxo.script_pubkey_len = 22;
  inp->witness_utxo.script_pubkey[0] = 0x00;
  inp->witness_utxo.script_pubkey[1] = 0x14;

  uint8_t script[256];
  size_t script_len;
  build_multisig_witness_script(script, &script_len, 2, 2);
  inp->has_witness_script = true;
  memcpy(inp->witness_script, script, script_len);
  inp->witness_script_len = (uint8_t)script_len;
  inp->is_multisig = true;
  inp->multisig_m = 2;
  inp->multisig_n = 2;

  psbt.outputs[0].amount = 50000000ULL;
  psbt.outputs[0].script_pubkey_len = 22;

  bool selected[4] = {true, false, false, false};
  int result = psbt_sign(&psbt, selected);
  ASSERT_EQ(result, 0, "no owned inputs => 0");

  teardown_se_keys();
  PASS();
}

int main(void) {
  printf("Multisig PSBT Co-Signing Unit Tests\n\n");

  test_parse_multisig_witness_script();
  test_parse_multisig_2of2();
  test_parse_not_multisig_no_script();
  test_parse_not_multisig_bad_script();
  test_parse_multisig_1of3();
  test_multisig_participant_match();
  test_multisig_participant_no_match();
  test_multisig_participant_null();
  test_multisig_participant_not_multisig();
  test_psbt_parse_v0_with_multisig();
  test_multisig_sign_no_participant();
  test_multisig_no_bip32_path();

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
