#include "psbt.h"
#include "se051_hal.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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

static bool tx_detect_rbf(const psbt_t *psbt) {
  for (uint32_t i = 0; i < psbt->input_count; i++) {
    if (psbt->inputs[i].sequence < 0xFFFFFFFE) return true;
  }
  return false;
}

static const char* get_input_segwit_label(const psbt_input_t *input) {
  if (!input->witness_utxo.present) return "Legacy";
  const uint8_t *spk = input->witness_utxo.script_pubkey;
  uint8_t len = input->witness_utxo.script_pubkey_len;
  if (len > 1 && spk[0] < 0xFD && (uint8_t)(spk[0] + 1) == len) {
    spk++;
    len = spk[-1];
  }
  if (len >= 2 && spk[0] == 0x00 && spk[1] == 0x14) return "SegWit v0";
  if (len >= 2 && spk[0] == 0x00 && spk[1] == 0x20) return "SegWit v0 (P2WSH)";
  if (len >= 2 && spk[0] == 0x51 && spk[1] == 0x20) return "Taproot v1";
  return "Legacy";
}

static void format_locktime(uint32_t locktime, char *buf, size_t len) {
  if (locktime == 0) {
    snprintf(buf, len, "Locktime: none");
    return;
  }
  if (locktime < 500000000) {
    snprintf(buf, len, "Locktime: Block %u", (unsigned)locktime);
  } else {
    time_t t = (time_t)locktime;
    struct tm *tm_info = gmtime(&t);
    snprintf(buf, len, "Locktime: %04d-%02d-%02d",
             tm_info->tm_year + 1900, tm_info->tm_mon + 1, tm_info->tm_mday);
  }
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

#define KV(buf, pos, kt, val_data, val_len) do { \
  write_varint((buf), (pos), 1); \
  write_u8((buf), (pos), (kt)); \
  write_varint((buf), (pos), (val_len)); \
  memcpy((buf) + *(pos), (val_data), (val_len)); \
  *(pos) += (val_len); \
} while(0)

#define KV_BLANK(buf, pos, kt, vbuf, vpos) do { \
  write_varint((buf), (pos), 1); \
  write_u8((buf), (pos), (kt)); \
  write_varint((buf), (pos), *(vpos)); \
  memcpy((buf) + *(pos), (vbuf), *(vpos)); \
  *(pos) += *(vpos); \
} while(0)

static size_t build_unsigned_tx(uint8_t *buf,
                                uint32_t version,
                                const uint8_t *txids[PSBT_MAX_INPUTS],
                                const uint32_t vouts[PSBT_MAX_INPUTS],
                                const uint32_t sequences[PSBT_MAX_INPUTS],
                                uint32_t input_count,
                                const uint64_t out_amounts[PSBT_MAX_OUTPUTS],
                                const uint8_t *out_spks[PSBT_MAX_OUTPUTS],
                                const uint8_t out_spk_lens[PSBT_MAX_OUTPUTS],
                                uint32_t output_count,
                                uint32_t locktime) {
  size_t pos = 0;
  write_u32le(buf, &pos, version);
  write_varint(buf, &pos, input_count);
  for (uint32_t i = 0; i < input_count; i++) {
    memcpy(buf + pos, txids[i], 32); pos += 32;
    write_u32le(buf, &pos, vouts[i]);
    write_varint(buf, &pos, 0);
    write_u32le(buf, &pos, sequences[i]);
  }
  write_varint(buf, &pos, output_count);
  for (uint32_t i = 0; i < output_count; i++) {
    write_u64le(buf, &pos, out_amounts[i]);
    write_u8(buf, &pos, out_spk_lens[i]);
    memcpy(buf + pos, out_spks[i], out_spk_lens[i]); pos += out_spk_lens[i];
  }
  write_u32le(buf, &pos, locktime);
  return pos;
}

static void test_rbf_sequence_detect(void) {
  TEST("RBF detection: nSequence < 0xFFFFFFFE");
  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt.input_count = 1;
  psbt.inputs[0].sequence = 0xFFFFFFFD;
  ASSERT_TRUE(tx_detect_rbf(&psbt), "should detect RBF with sequence 0xFFFFFFFD");
  PASS();
}

static void test_no_rbf_final_sequence(void) {
  TEST("RBF detection: nSequence == 0xFFFFFFFF");
  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt.input_count = 1;
  psbt.inputs[0].sequence = 0xFFFFFFFF;
  ASSERT_FALSE(tx_detect_rbf(&psbt), "should NOT detect RBF with sequence 0xFFFFFFFF");
  PASS();
}

static void test_no_rbf_max_replaceable(void) {
  TEST("RBF detection: nSequence == 0xFFFFFFFE");
  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt.input_count = 1;
  psbt.inputs[0].sequence = 0xFFFFFFFE;
  ASSERT_FALSE(tx_detect_rbf(&psbt), "sequence 0xFFFFFFFE should NOT be RBF");
  PASS();
}

static void test_rbf_first_of_two(void) {
  TEST("RBF detection: first of two inputs has RBF sequence");
  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt.input_count = 2;
  psbt.inputs[0].sequence = 0xFFFFFFFD;
  psbt.inputs[1].sequence = 0xFFFFFFFF;
  ASSERT_TRUE(tx_detect_rbf(&psbt), "should detect RBF if any input has low sequence");
  PASS();
}

static void test_no_rbf_both_final(void) {
  TEST("RBF detection: both inputs final sequence");
  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt.input_count = 2;
  psbt.inputs[0].sequence = 0xFFFFFFFF;
  psbt.inputs[1].sequence = 0xFFFFFFFE;
  ASSERT_FALSE(tx_detect_rbf(&psbt), "no RBF when both sequences >= 0xFFFFFFFE");
  PASS();
}

static void test_segwit_label_p2wpkh(void) {
  TEST("SegWit label: P2WPKH witness UTXO");
  psbt_input_t inp;
  memset(&inp, 0, sizeof(inp));
  inp.witness_utxo.present = true;
  inp.witness_utxo.script_pubkey_len = 22;
  inp.witness_utxo.script_pubkey[0] = 0x00;
  inp.witness_utxo.script_pubkey[1] = 0x14;
  const char *label = get_input_segwit_label(&inp);
  ASSERT_EQ(strcmp(label, "SegWit v0"), 0, "P2WPKH should be SegWit v0");
  PASS();
}

static void test_segwit_label_p2tr(void) {
  TEST("SegWit label: P2TR witness UTXO");
  psbt_input_t inp;
  memset(&inp, 0, sizeof(inp));
  inp.witness_utxo.present = true;
  inp.witness_utxo.script_pubkey_len = 34;
  inp.witness_utxo.script_pubkey[0] = 0x51;
  inp.witness_utxo.script_pubkey[1] = 0x20;
  const char *label = get_input_segwit_label(&inp);
  ASSERT_EQ(strcmp(label, "Taproot v1"), 0, "P2TR should be Taproot v1");
  PASS();
}

static void test_segwit_label_p2wsh(void) {
  TEST("SegWit label: P2WSH witness UTXO");
  psbt_input_t inp;
  memset(&inp, 0, sizeof(inp));
  inp.witness_utxo.present = true;
  inp.witness_utxo.script_pubkey_len = 34;
  inp.witness_utxo.script_pubkey[0] = 0x00;
  inp.witness_utxo.script_pubkey[1] = 0x20;
  const char *label = get_input_segwit_label(&inp);
  ASSERT_EQ(strcmp(label, "SegWit v0 (P2WSH)"), 0, "P2WSH should be SegWit v0 (P2WSH)");
  PASS();
}

static void test_segwit_label_no_witness(void) {
  TEST("SegWit label: no witness UTXO present");
  psbt_input_t inp;
  memset(&inp, 0, sizeof(inp));
  inp.witness_utxo.present = false;
  const char *label = get_input_segwit_label(&inp);
  ASSERT_EQ(strcmp(label, "Legacy"), 0, "no witness should be Legacy");
  PASS();
}

static void test_segwit_label_junk_spk(void) {
  TEST("SegWit label: unrecognized scriptPubKey");
  psbt_input_t inp;
  memset(&inp, 0, sizeof(inp));
  inp.witness_utxo.present = true;
  inp.witness_utxo.script_pubkey_len = 25;
  inp.witness_utxo.script_pubkey[0] = 0x76;
  inp.witness_utxo.script_pubkey[1] = 0xa9;
  const char *label = get_input_segwit_label(&inp);
  ASSERT_EQ(strcmp(label, "Legacy"), 0, "junk SPK should be Legacy");
  PASS();
}

static void test_locktime_none(void) {
  TEST("Locktime format: zero locktime");
  char buf[64];
  format_locktime(0, buf, sizeof(buf));
  ASSERT_EQ(strcmp(buf, "Locktime: none"), 0, "zero locktime should show none");
  PASS();
}

static void test_locktime_block(void) {
  TEST("Locktime format: block height");
  char buf[64];
  format_locktime(500000, buf, sizeof(buf));
  ASSERT_TRUE(strstr(buf, "Block 500000") != NULL, "should show block height");
  PASS();
}

static void test_locktime_timestamp(void) {
  TEST("Locktime format: unix timestamp >= 500000000");
  char buf[64];
  format_locktime(1700000000, buf, sizeof(buf));
  ASSERT_TRUE(strstr(buf, "Locktime: 20") != NULL, "should show date YYYY-MM-DD");
  ASSERT_TRUE(strlen(buf) > 15, "date format should be long enough");
  PASS();
}

static void test_locktime_block_boundary(void) {
  TEST("Locktime format: block height at boundary");
  char buf[64];
  format_locktime(499999999, buf, sizeof(buf));
  ASSERT_TRUE(strstr(buf, "Block") != NULL, "499,999,999 should be block height");
  PASS();
}

static void test_psbt_parse_rbf_field(void) {
  TEST("PSBT parse: RBF nSequence extracted from unsigned TX");

  static uint8_t txid_buf[32]; memset(txid_buf, 0xAB, 32);
  const uint8_t *txids[1] = { txid_buf };
  uint32_t vouts[1] = { 0 };
  uint32_t sequences[1] = { 0xFFFFFFFD };
  uint64_t out_amounts[1] = { 100000 };

  uint8_t p2wpkh_spk[22];
  p2wpkh_spk[0] = 0x00; p2wpkh_spk[1] = 0x14;
  memset(p2wpkh_spk + 2, 0x0A, 20);
  const uint8_t *out_spks[1] = { p2wpkh_spk };
  uint8_t out_spk_lens[1] = { 22 };

  uint8_t utx[512];
  size_t utx_len = build_unsigned_tx(utx, 1, txids, vouts, sequences, 1,
                                     out_amounts, out_spks, out_spk_lens, 1, 0);

  uint8_t psbt_buf[1024];
  size_t pos = 0;
  psbt_buf[pos++] = 0x70; psbt_buf[pos++] = 0x73;
  psbt_buf[pos++] = 0x62; psbt_buf[pos++] = 0x74;
  psbt_buf[pos++] = 0xFF;
  KV_BLANK(psbt_buf, &pos, 0x00, utx, &utx_len);
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 0);

  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt_err_t err = psbt_parse(psbt_buf, pos, &psbt);
  ASSERT_EQ(err, PSBT_OK, "parse should succeed");
  ASSERT_EQ(psbt.input_count, 1u, "should have 1 input");
  ASSERT_EQ(psbt.inputs[0].sequence, 0xFFFFFFFDu, "sequence should be 0xFFFFFFFD");
  ASSERT_TRUE(tx_detect_rbf(&psbt), "parsed PSBT should detect RBF");
  PASS();
}

static void test_psbt_parse_locktime_field(void) {
  TEST("PSBT parse: locktime extracted from unsigned TX");

  static uint8_t txid_buf[32]; memset(txid_buf, 0xAB, 32);
  const uint8_t *txids[1] = { txid_buf };
  uint32_t vouts[1] = { 0 };
  uint32_t sequences[1] = { 0xFFFFFFFF };
  uint64_t out_amounts[1] = { 50000 };

  uint8_t p2wpkh_spk[22];
  p2wpkh_spk[0] = 0x00; p2wpkh_spk[1] = 0x14;
  memset(p2wpkh_spk + 2, 0x0C, 20);
  const uint8_t *out_spks[1] = { p2wpkh_spk };
  uint8_t out_spk_lens[1] = { 22 };

  uint8_t utx[512];
  size_t utx_len = build_unsigned_tx(utx, 1, txids, vouts, sequences, 1,
                                     out_amounts, out_spks, out_spk_lens, 1,
                                     700000);

  uint8_t psbt_buf[1024];
  size_t pos = 0;
  psbt_buf[pos++] = 0x70; psbt_buf[pos++] = 0x73;
  psbt_buf[pos++] = 0x62; psbt_buf[pos++] = 0x74;
  psbt_buf[pos++] = 0xFF;
  KV_BLANK(psbt_buf, &pos, 0x00, utx, &utx_len);
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 0);

  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt_err_t err = psbt_parse(psbt_buf, pos, &psbt);
  ASSERT_EQ(err, PSBT_OK, "parse should succeed");
  ASSERT_EQ(psbt.locktime, 700000u, "locktime should be 700000");
  char lt_buf[64];
  format_locktime(psbt.locktime, lt_buf, sizeof(lt_buf));
  ASSERT_TRUE(strstr(lt_buf, "Block 700000") != NULL, "locktime should format as block");
  PASS();
}

static void test_psbt_parse_locktime_zero(void) {
  TEST("PSBT parse: locktime=0 extracted");

  static uint8_t txid_buf[32]; memset(txid_buf, 0xAB, 32);
  const uint8_t *txids[1] = { txid_buf };
  uint32_t vouts[1] = { 0 };
  uint32_t sequences[1] = { 0xFFFFFFFF };
  uint64_t out_amounts[1] = { 1000 };

  uint8_t p2wpkh_spk[22];
  p2wpkh_spk[0] = 0x00; p2wpkh_spk[1] = 0x14;
  memset(p2wpkh_spk + 2, 0x0E, 20);
  const uint8_t *out_spks[1] = { p2wpkh_spk };
  uint8_t out_spk_lens[1] = { 22 };

  uint8_t utx[512];
  size_t utx_len = build_unsigned_tx(utx, 1, txids, vouts, sequences, 1,
                                     out_amounts, out_spks, out_spk_lens, 1, 0);

  uint8_t psbt_buf[1024];
  size_t pos = 0;
  psbt_buf[pos++] = 0x70; psbt_buf[pos++] = 0x73;
  psbt_buf[pos++] = 0x62; psbt_buf[pos++] = 0x74;
  psbt_buf[pos++] = 0xFF;
  KV_BLANK(psbt_buf, &pos, 0x00, utx, &utx_len);
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 0);

  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt_err_t err = psbt_parse(psbt_buf, pos, &psbt);
  ASSERT_EQ(err, PSBT_OK, "parse should succeed");
  ASSERT_EQ(psbt.locktime, 0u, "locktime should be 0");
  PASS();
}

static void test_psbt_parse_witness_utxo_segwit(void) {
  TEST("PSBT parse: witness UTXO with P2WPKH scriptPubKey");

  static uint8_t txid_buf[32]; memset(txid_buf, 0xAB, 32);
  const uint8_t *txids[1] = { txid_buf };
  uint32_t vouts[1] = { 0 };
  uint32_t sequences[1] = { 0xFFFFFFFF };
  uint64_t out_amounts[1] = { 75000 };

  uint8_t p2wpkh_spk[22];
  p2wpkh_spk[0] = 0x00; p2wpkh_spk[1] = 0x14;
  memset(p2wpkh_spk + 2, 0x10, 20);
  const uint8_t *out_spks[1] = { p2wpkh_spk };
  uint8_t out_spk_lens[1] = { 22 };

  uint8_t utx[512];
  size_t utx_len = build_unsigned_tx(utx, 1, txids, vouts, sequences, 1,
                                     out_amounts, out_spks, out_spk_lens, 1, 0);

  uint8_t wit_utxo_raw[64];
  size_t wpos = 0;
  write_u64le(wit_utxo_raw, &wpos, 100000000ULL);
  write_u8(wit_utxo_raw, &wpos, 22);
  memcpy(wit_utxo_raw + wpos, p2wpkh_spk, 22); wpos += 22;

  uint8_t psbt_buf[1024];
  size_t pos = 0;
  psbt_buf[pos++] = 0x70; psbt_buf[pos++] = 0x73;
  psbt_buf[pos++] = 0x62; psbt_buf[pos++] = 0x74;
  psbt_buf[pos++] = 0xFF;
  KV_BLANK(psbt_buf, &pos, 0x00, utx, &utx_len);
  write_varint(psbt_buf, &pos, 0);
  KV_BLANK(psbt_buf, &pos, 0x01, wit_utxo_raw, &wpos);
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 0);

  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt_err_t err = psbt_parse(psbt_buf, pos, &psbt);
  ASSERT_EQ(err, PSBT_OK, "parse should succeed");
  ASSERT_EQ(psbt.input_count, 1u, "should have 1 input");
  ASSERT_TRUE(psbt.inputs[0].witness_utxo.present, "witness UTXO should be present");
  ASSERT_EQ(psbt.inputs[0].witness_utxo.amount, 100000000ULL, "amount should be 100M sats");
  ASSERT_EQ(psbt.inputs[0].witness_utxo.script_pubkey_len, 23u, "SPK len should be 23 (22+compactSize)");
  ASSERT_EQ(psbt.inputs[0].witness_utxo.script_pubkey[0], 0x16u, "SPK[0] should be compactSize 0x16");
  ASSERT_EQ(psbt.inputs[0].witness_utxo.script_pubkey[1], 0x00u, "SPK[1] should be 0x00");
  ASSERT_EQ(psbt.inputs[0].witness_utxo.script_pubkey[2], 0x14u, "SPK[2] should be 0x14");
  const char *label = get_input_segwit_label(&psbt.inputs[0]);
  ASSERT_EQ(strcmp(label, "SegWit v0"), 0, "witness UTXO should be SegWit v0");
  PASS();
}

static void test_psbt_parse_multiple_inputs(void) {
  TEST("PSBT parse: two inputs with different nSequence");
  static uint8_t txid1[32], txid2[32];
  memset(txid1, 0x01, 32); memset(txid2, 0x02, 32);
  const uint8_t *txids[2] = { txid1, txid2 };
  uint32_t vouts[2] = { 0, 0 };
  uint32_t sequences[2] = { 0xFFFFFFFD, 0xFFFFFFFF };
  uint64_t out_amounts[1] = { 50000 };

  uint8_t p2wpkh_spk[22];
  p2wpkh_spk[0] = 0x00; p2wpkh_spk[1] = 0x14;
  memset(p2wpkh_spk + 2, 0x20, 20);
  const uint8_t *out_spks[1] = { p2wpkh_spk };
  uint8_t out_spk_lens[1] = { 22 };

  uint8_t utx[512];
  size_t utx_len = build_unsigned_tx(utx, 1, txids, vouts, sequences, 2,
                                     out_amounts, out_spks, out_spk_lens, 1, 0);

  uint8_t psbt_buf[1024];
  size_t pos = 0;
  psbt_buf[pos++] = 0x70; psbt_buf[pos++] = 0x73;
  psbt_buf[pos++] = 0x62; psbt_buf[pos++] = 0x74;
  psbt_buf[pos++] = 0xFF;
  KV_BLANK(psbt_buf, &pos, 0x00, utx, &utx_len);
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 0);
  write_varint(psbt_buf, &pos, 0);

  psbt_t psbt;
  memset(&psbt, 0, sizeof(psbt));
  psbt_err_t err = psbt_parse(psbt_buf, pos, &psbt);
  ASSERT_EQ(err, PSBT_OK, "parse should succeed");
  ASSERT_EQ(psbt.input_count, 2u, "should have 2 inputs");
  ASSERT_EQ(psbt.inputs[0].sequence, 0xFFFFFFFDu, "input 0 sequence should be 0xFFFFFFFD");
  ASSERT_EQ(psbt.inputs[1].sequence, 0xFFFFFFFFu, "input 1 sequence should be 0xFFFFFFFF");
  ASSERT_TRUE(tx_detect_rbf(&psbt), "should detect RBF from input 0");
  PASS();
}

int main(void) {
  printf("Transaction Metadata Unit Tests (RBF, Locktime, SegWit version)\n\n");

  test_rbf_sequence_detect();
  test_no_rbf_final_sequence();
  test_no_rbf_max_replaceable();
  test_rbf_first_of_two();
  test_no_rbf_both_final();
  test_segwit_label_p2wpkh();
  test_segwit_label_p2tr();
  test_segwit_label_p2wsh();
  test_segwit_label_no_witness();
  test_segwit_label_junk_spk();
  test_locktime_none();
  test_locktime_block();
  test_locktime_timestamp();
  test_locktime_block_boundary();
  test_psbt_parse_rbf_field();
  test_psbt_parse_locktime_field();
  test_psbt_parse_locktime_zero();
  test_psbt_parse_witness_utxo_segwit();
  test_psbt_parse_multiple_inputs();

  printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
  return tests_failed > 0 ? 1 : 0;
}
