#ifdef USE_SE_STUB

#include "psbt.h"
#include "address.h"
#include "bech32.h"
#include "bip32.h"
#include "se051_hal.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  TEST: %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)

// Demo PSBT: 1 input (100M sats) -> 2 outputs (51.2M send + 48.75M change)
// Fee: 50,000 sats, RBF enabled (nSequence=0xFFFFFFFD)
static const uint8_t DEMO_PSBT[] = {
  0x70, 0x73, 0x62, 0x74, 0xff, 0x01, 0x00, 0x71, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
  0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
  0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x00, 0x00, 0x00,
  0x00, 0x00, 0xfd, 0xff, 0xff, 0xff, 0x02, 0x00, 0x40, 0x0d, 0x03, 0x00,
  0x00, 0x00, 0x00, 0x16, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
  0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
  0x13, 0x14, 0xb0, 0xdd, 0xe7, 0x02, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00,
  0x14, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
  0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x01, 0x01, 0x1f, 0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00,
  0x00, 0x16, 0x00, 0x14, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
  0x01, 0x03, 0x04, 0x01, 0x00, 0x00, 0x00, 0x19, 0x06, 0xaa, 0xbb, 0xcc,
  0xdd, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x02, 0x10,
  0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
  0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
  0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x00, 0x19, 0x02, 0xaa, 0xbb,
  0xcc, 0xdd, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00,
  0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21, 0x02,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
  0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x00, 0x19, 0x02, 0xaa,
  0xbb, 0xcc, 0xdd, 0x54, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x80, 0x00,
  0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x21,
  0x02, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
  0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
  0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x00
};

bool is_output_change(const psbt_output_t *output) {
  if (!output->bip32_derivation.present) return false;
  if (output->bip32_derivation.path_len < 5) return false;
  return output->bip32_derivation.path[3] == 1;
}

bool tx_detect_rbf(const psbt_t *psbt) {
  for (uint32_t i = 0; i < psbt->input_count; i++) {
    if (psbt->inputs[i].sequence < 0xFFFFFFFE) return true;
  }
  return false;
}

uint32_t tx_estimate_vsize(const psbt_t *psbt) {
  uint32_t base_size = 10 + psbt->input_count * 41 + psbt->output_count * 31;
  uint32_t witness_size = psbt->input_count * 107;
  return (base_size * 4 + witness_size + 3) / 4;
}

static bool hex_to_bytes(const char *hex, uint8_t *buf, size_t buf_len) {
  size_t hex_len = strlen(hex);
  if (hex_len % 2 != 0) return false;
  if (hex_len / 2 > buf_len) return false;
  for (size_t i = 0; i < hex_len; i += 2) {
    unsigned int byte;
    if (sscanf(hex + i, "%2x", &byte) != 1) return false;
    buf[i / 2] = (uint8_t)byte;
  }
  return true;
}

int main(void) {
  printf("=== Transaction Review Unit Tests ===\n\n");

  se051_init();

  // Store BIP32 test keys in SE stub for address generation
  {
    const char *chain_hex =
      "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508";
    uint8_t chain_code[32];
    hex_to_bytes(chain_hex, chain_code, 32);
    se051_store_key(SE051_KEY_CHAIN_CODE, chain_code, 32);
    se051_store_key(SE051_KEY_BIP32_MASTER, (const uint8_t *)"dummy", 5);
  }

  // ── Test 1: Parse demo PSBT ────────────────────────────────────────
  TEST("parse demo PSBT v0 with 1 input, 2 outputs");
  {
    psbt_t psbt;
    if (psbt_parse(DEMO_PSBT, sizeof(DEMO_PSBT), &psbt) != PSBT_OK)
      FAIL("parse failed");
    else if (psbt.version != 0) FAIL("wrong version");
    else if (psbt.input_count != 1) FAIL("wrong input count");
    else if (psbt.output_count != 2) FAIL("wrong output count");
    else PASS();
  }

  // ── Test 2: RBF detection ──────────────────────────────────────────
  TEST("RBF detection returns true for nSequence < 0xFFFFFFFE");
  {
    psbt_t psbt;
    psbt_parse(DEMO_PSBT, sizeof(DEMO_PSBT), &psbt);
    if (!tx_detect_rbf(&psbt)) FAIL("expected RBF=true");
    else PASS();
  }

  // ── Test 3: RBF detection false ────────────────────────────────────
  TEST("RBF detection returns false for nSequence=0xFFFFFFFF");
  {
    psbt_t psbt;
    memset(&psbt, 0, sizeof(psbt));
    psbt.input_count = 1;
    psbt.inputs[0].sequence = 0xFFFFFFFF;
    if (tx_detect_rbf(&psbt)) FAIL("expected RBF=false");
    else PASS();
  }

  // ── Test 4: Change detection ───────────────────────────────────────
  TEST("change detection returns true for path[3]==1");
  {
    psbt_t psbt;
    psbt_parse(DEMO_PSBT, sizeof(DEMO_PSBT), &psbt);
    if (psbt.output_count < 2) FAIL("not enough outputs");
    else if (is_output_change(&psbt.outputs[0])) FAIL("output 0 should NOT be change");
    else if (!is_output_change(&psbt.outputs[1])) FAIL("output 1 should be change");
    else PASS();
  }

  // ── Test 5: Witness UTXO amount ────────────────────────────────────
  TEST("witness UTXO amount parsed correctly");
  {
    psbt_t psbt;
    psbt_parse(DEMO_PSBT, sizeof(DEMO_PSBT), &psbt);
    if (!psbt.inputs[0].witness_utxo.present) FAIL("no witness utxo");
    else if (psbt.inputs[0].witness_utxo.amount != 100000000)
      FAIL("wrong amount");
    else PASS();
  }

  // ── Test 6: Output amounts from raw tx ─────────────────────────────
  TEST("output amounts parsed from global unsigned tx");
  {
    psbt_t psbt;
    psbt_parse(DEMO_PSBT, sizeof(DEMO_PSBT), &psbt);
    if (psbt.outputs[0].amount != 51200000) {
      char msg[64];
      snprintf(msg, 64, "got %llu", (unsigned long long)psbt.outputs[0].amount);
      FAIL(msg);
    } else if (psbt.outputs[1].amount != 48750000) {
      char msg[64];
      snprintf(msg, 64, "got %llu", (unsigned long long)psbt.outputs[1].amount);
      FAIL(msg);
    } else PASS();
  }

  // ── Test 7: Fee calculation ────────────────────────────────────────
  TEST("fee = total_input - total_output = 50000");
  {
    psbt_t psbt;
    psbt_parse(DEMO_PSBT, sizeof(DEMO_PSBT), &psbt);
    uint64_t in = psbt_get_total_input_value(&psbt);
    uint64_t out = psbt_get_total_output_value(&psbt);
    int64_t fee = psbt_get_fee(&psbt);
    if (in != 100000000) FAIL("wrong total in");
    else if (out != 99950000) FAIL("wrong total out");
    else if (fee != 50000) {
      char msg[64];
      snprintf(msg, 64, "got %lld", (long long)fee);
      FAIL(msg);
    }
    else PASS();
  }

  // ── Test 8: vsize estimation ───────────────────────────────────────
  TEST("vsize estimation produces reasonable value");
  {
    psbt_t psbt;
    psbt_parse(DEMO_PSBT, sizeof(DEMO_PSBT), &psbt);
    uint32_t vsize = tx_estimate_vsize(&psbt);
    if (vsize < 50) FAIL("vsize too small");
    else if (vsize > 500) FAIL("vsize too large");
    else {
      printf("%u", vsize);
      PASS();
    }
  }

  // ── Test 9: BIP32 derivation parsed ────────────────────────────────
  TEST("BIP32 derivation path m/84'/0'/0'/0/0 parsed for input");
  {
    psbt_t psbt;
    psbt_parse(DEMO_PSBT, sizeof(DEMO_PSBT), &psbt);
    if (!psbt.inputs[0].bip32_derivation.present) FAIL("no derivation");
    else if (psbt.inputs[0].bip32_derivation.path_len != 5)
      FAIL("wrong path len");
    else if (psbt.inputs[0].bip32_derivation.path[0] != 0x80000054)
      FAIL("wrong purpose");
    else PASS();
  }

  // ── Test 10: Address generation for different types ────────────────
  TEST("address_generate P2WPKH returns bech32 address");
  {
    char addr[MAX_ADDRESS_LEN];
    if (!address_generate(ADDRESS_P2WPKH, 0, addr)) FAIL("gen failed");
    else if (strncmp(addr, "bc1", 3) != 0) {
      char msg[72];
      snprintf(msg, 72, "got %s", addr);
      FAIL(msg);
    } else PASS();
  }

  // ── Test 11: Address generation P2PKH ──────────────────────────────
  TEST("address_generate P2PKH returns base58 address");
  {
    char addr[MAX_ADDRESS_LEN];
    if (!address_generate(ADDRESS_P2PKH, 5, addr)) FAIL("gen failed");
    else if (addr[0] != '1') {
      char msg[72];
      snprintf(msg, 72, "got %s", addr);
      FAIL(msg);
    } else PASS();
  }

  // ── Test 12: Change address with path ──────────────────────────────
  TEST("address_generate_with_path for change gives valid bech32");
  {
    char addr[MAX_ADDRESS_LEN];
    if (!address_generate_with_path(ADDRESS_P2WPKH, 1, 0, addr))
      FAIL("gen failed");
    else if (strncmp(addr, "bc1", 3) != 0) FAIL("not bech32");
    else PASS();
  }

  // ── Test 13: Bech32 encode from script pubkey ──────────────────────
  TEST("bech32_encode produces valid address from hash160");
  {
    uint8_t hash160[20];
    memset(hash160, 0x42, 20);
    char bech[128];
    if (!bech32_encode("bc", 0, hash160, 20, bech))
      FAIL("encode failed");
    else if (strncmp(bech, "bc1", 3) != 0)
      FAIL("not bech32 format");
    else if (strlen(bech) < 10)
      FAIL("too short");
    else PASS();
  }

  // ── Test 14: Bech32m encode ────────────────────────────────────────
  TEST("bech32m_encode produces valid address");
  {
    uint8_t xonly[32];
    memset(xonly, 0x99, 32);
    char bech[128];
    if (!bech32m_encode("bc", 1, xonly, 32, bech))
      FAIL("encode failed");
    else if (strncmp(bech, "bc1", 3) != 0)
      FAIL("not bech32m format");
    else PASS();
  }

  // ── Summary ────────────────────────────────────────────────────────
  printf("\n=== Results: %d/%d passed, %d failed ===\n",
         tests_passed, tests_run, tests_failed);

  return tests_failed > 0 ? 1 : 0;
}

#else
#include <cstdio>
int main(void) {
  printf("Transaction review tests require USE_SE_STUB.\n");
  return 0;
}
#endif
