#ifdef USE_SE_STUB

#include "psbt.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  TEST: %s ... ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)

static void write_varint(uint8_t *buf, size_t *pos, uint64_t val) {
    if (val < 0xFD) {
        buf[(*pos)++] = (uint8_t)val;
    } else if (val <= 0xFFFF) {
        buf[(*pos)++] = 0xFD;
        buf[(*pos)++] = (uint8_t)(val & 0xFF);
        buf[(*pos)++] = (uint8_t)((val >> 8) & 0xFF);
    } else if (val <= 0xFFFFFFFF) {
        buf[(*pos)++] = 0xFE;
        for (int i = 0; i < 4; i++)
            buf[(*pos)++] = (uint8_t)((val >> (i * 8)) & 0xFF);
    } else {
        buf[(*pos)++] = 0xFF;
        for (int i = 0; i < 8; i++)
            buf[(*pos)++] = (uint8_t)((val >> (i * 8)) & 0xFF);
    }
}

static void write_u32le(uint8_t *buf, size_t *pos, uint32_t val) {
    for (int i = 0; i < 4; i++)
        buf[(*pos)++] = (uint8_t)((val >> (i * 8)) & 0xFF);
}

static void write_u64le(uint8_t *buf, size_t *pos, uint64_t val) {
    for (int i = 0; i < 8; i++)
        buf[(*pos)++] = (uint8_t)((val >> (i * 8)) & 0xFF);
}

static void write_kv(uint8_t *buf, size_t *pos, uint8_t key_type,
                     const uint8_t *key_data, size_t key_data_len,
                     const uint8_t *value, size_t value_len) {
    size_t total_key_len = 1 + key_data_len;
    write_varint(buf, pos, total_key_len);
    buf[(*pos)++] = key_type;
    if (key_data_len > 0)
        memcpy(buf + *pos, key_data, key_data_len);
    *pos += key_data_len;
    write_varint(buf, pos, value_len);
    if (value_len > 0)
        memcpy(buf + *pos, value, value_len);
    *pos += value_len;
}

static void write_separator(uint8_t *buf, size_t *pos) {
    buf[(*pos)++] = 0x00;
}

static size_t build_v0_psbt(uint8_t *buf, size_t buf_max) {
    memset(buf, 0, buf_max);
    size_t pos = 0;

    memcpy(buf + pos, "\x70\x73\x62\x74\xff", 5);
    pos += 5;

    uint8_t tx[256];
    size_t tx_pos = 0;
    write_u32le(tx, &tx_pos, 1);
    tx[tx_pos++] = 0x01;
    for (int i = 0; i < 32; i++) tx[tx_pos++] = (uint8_t)(0xAB + i);
    write_u32le(tx, &tx_pos, 0);
    tx[tx_pos++] = 0x00;
    write_u32le(tx, &tx_pos, 0xFFFFFFFF);
    tx[tx_pos++] = 0x01;
    write_u64le(tx, &tx_pos, 100000ULL);
    tx[tx_pos++] = 0x16;
    tx[tx_pos++] = 0x00;
    tx[tx_pos++] = 0x14;
    for (int i = 0; i < 20; i++) tx[tx_pos++] = (uint8_t)(0xCC + i);
    write_u32le(tx, &tx_pos, 0);

    write_kv(buf, &pos, 0x00, NULL, 0, tx, tx_pos);
    write_separator(buf, &pos);

    uint8_t wit_utxo[256];
    size_t wu_pos = 0;
    write_u64le(wit_utxo, &wu_pos, 100000ULL);
    wit_utxo[wu_pos++] = 0x16;
    wit_utxo[wu_pos++] = 0x00;
    wit_utxo[wu_pos++] = 0x14;
    for (int i = 0; i < 20; i++) wit_utxo[wu_pos++] = (uint8_t)(0xCC + i);

    write_kv(buf, &pos, PSBT_IN_WITNESS_UTXO, NULL, 0, wit_utxo, wu_pos);

    uint8_t sighash_val[4];
    size_t sh_pos = 0;
    write_u32le(sighash_val, &sh_pos, 0x01);
    write_kv(buf, &pos, PSBT_IN_SIGHASH_TYPE, NULL, 0, sighash_val, sh_pos);

    uint8_t deriv_key[16];
    size_t dk_pos = 0;
    write_u32le(deriv_key, &dk_pos, 0xAABBCCDD);
    write_u32le(deriv_key, &dk_pos, 0x80000054);
    write_u32le(deriv_key, &dk_pos, 0x80000000);
    write_u32le(deriv_key, &dk_pos, 0x80000000);

    uint8_t pubkey[33];
    pubkey[0] = 0x02;
    for (int i = 1; i < 33; i++) pubkey[i] = (uint8_t)(0x10 + i);

    write_kv(buf, &pos, PSBT_IN_BIP32_DERIVATION, deriv_key, dk_pos, pubkey, 33);
    write_separator(buf, &pos);

    write_kv(buf, &pos, PSBT_OUT_BIP32_DERIVATION, deriv_key, dk_pos, pubkey, 33);
    write_separator(buf, &pos);

    return pos;
}

static size_t build_v2_psbt(uint8_t *buf, size_t buf_max) {
    memset(buf, 0, buf_max);
    size_t pos = 0;

    memcpy(buf + pos, "\x70\x73\x62\x74\xfe", 5);
    pos += 5;

    uint8_t version_val[4];
    size_t vp = 0;
    write_u32le(version_val, &vp, 2);
    write_kv(buf, &pos, PSBT_GLOBAL_VERSION, NULL, 0, version_val, vp);
    write_separator(buf, &pos);

    uint8_t txid[32];
    for (int i = 0; i < 32; i++) txid[i] = (uint8_t)(0xFE - i);
    write_kv(buf, &pos, PSBT_IN_PREVIOUS_TXID, NULL, 0, txid, 32);

    uint8_t vout[4];
    size_t vp2 = 0;
    write_u32le(vout, &vp2, 1);
    write_kv(buf, &pos, PSBT_IN_OUTPUT_INDEX, NULL, 0, vout, vp2);

    uint8_t seq[4];
    size_t sp = 0;
    write_u32le(seq, &sp, 0xFFFFFFFD);
    write_kv(buf, &pos, PSBT_IN_SEQUENCE, NULL, 0, seq, sp);

    uint8_t wit_utxo[256];
    size_t wu_pos = 0;
    write_u64le(wit_utxo, &wu_pos, 200000ULL);
    wit_utxo[wu_pos++] = 0x16;
    wit_utxo[wu_pos++] = 0x00;
    wit_utxo[wu_pos++] = 0x14;
    for (int i = 0; i < 20; i++) wit_utxo[wu_pos++] = (uint8_t)(0xAA + i);
    write_kv(buf, &pos, PSBT_IN_WITNESS_UTXO, NULL, 0, wit_utxo, wu_pos);

    uint8_t sighash_val[4];
    size_t sh_pos = 0;
    write_u32le(sighash_val, &sh_pos, 0x01);
    write_kv(buf, &pos, PSBT_IN_SIGHASH_TYPE, NULL, 0, sighash_val, sh_pos);

    write_separator(buf, &pos);

    uint8_t amount[8];
    size_t ap = 0;
    write_u64le(amount, &ap, 150000ULL);
    write_kv(buf, &pos, PSBT_OUT_AMOUNT, NULL, 0, amount, ap);

    uint8_t script[22];
    script[0] = 0x00; script[1] = 0x14;
    for (int i = 2; i < 22; i++) script[i] = (uint8_t)(0xBB + i);
    write_kv(buf, &pos, PSBT_OUT_SCRIPT, NULL, 0, script, 22);

    write_separator(buf, &pos);

    return pos;
}

int main(void) {
    printf("=== PSBT Parser Unit Tests ===\n\n");

    // ── Test 1: Parse valid v0 PSBT ──────────────────────────────────────
    TEST("psbt_parse v0 with 1 input, 1 output");
    {
        uint8_t pbuf[512];
        size_t plen = build_v0_psbt(pbuf, sizeof(pbuf));
        psbt_t psbt;
        if (psbt_parse(pbuf, plen, &psbt) != PSBT_OK) FAIL("parse failed");
        else if (psbt.version != 0) FAIL("wrong version");
        else if (psbt.input_count != 1) FAIL("wrong input count");
        else if (psbt.output_count != 1) FAIL("wrong output count");
        else if (!psbt.inputs[0].witness_utxo.present) FAIL("no witness utxo");
        else if (psbt.inputs[0].witness_utxo.amount != 100000)
            FAIL("wrong witness utxo amount");
        else if (psbt.inputs[0].sighash_type != 1)
            FAIL("wrong sighash type");
        else if (!psbt.inputs[0].bip32_derivation.present)
            FAIL("no bip32 derivation");
        else if (psbt.inputs[0].bip32_derivation.path_len != 3) FAIL("wrong path len");
        else if (psbt.inputs[0].bip32_derivation.path[0] != 0x80000054)
            FAIL("wrong first path element");
        else PASS();
    }

    // ── Test 2: Parse valid v2 PSBT ──────────────────────────────────────
    TEST("psbt_parse v2 with 1 input, 1 output");
    {
        uint8_t pbuf[512];
        size_t plen = build_v2_psbt(pbuf, sizeof(pbuf));
        psbt_t psbt;
        if (psbt_parse(pbuf, plen, &psbt) != PSBT_OK) FAIL("parse failed");
        else if (psbt.version != 2) FAIL("wrong version");
        else if (psbt.input_count != 1) FAIL("wrong input count");
        else if (psbt.output_count != 1) FAIL("wrong output count");
        else if (!psbt.inputs[0].witness_utxo.present) FAIL("no witness utxo");
        else if (psbt.inputs[0].witness_utxo.amount != 200000)
            FAIL("wrong witness utxo amount");
        else if (psbt.inputs[0].sequence != 0xFFFFFFFD)
            FAIL("wrong sequence");
        else if (psbt.outputs[0].amount != 150000)
            FAIL("wrong output amount");
        else PASS();
    }

    // ── Test 3: Magic bytes validation ───────────────────────────────────
    TEST("reject bad magic bytes");
    {
        uint8_t buf[10] = {0x00,0x00,0x00,0x00,0x00};
        psbt_t psbt;
        if (psbt_parse(buf, 5, &psbt) == PSBT_ERR_MAGIC) PASS();
        else FAIL("did not reject bad magic");
    }

    // ── Test 4: Too short buffer ─────────────────────────────────────────
    TEST("reject buffer too short");
    {
        uint8_t buf[3] = {0x70, 0x73, 0x62};
        psbt_t psbt;
        if (psbt_parse(buf, 3, &psbt) == PSBT_ERR_MAGIC) PASS();
        else FAIL("did not reject short buffer");
    }

    // ── Test 5: NULL buffer ──────────────────────────────────────────────
    TEST("reject NULL buffer");
    {
        psbt_t psbt;
        if (psbt_parse(NULL, 100, &psbt) == PSBT_ERR_INVALID) PASS();
        else FAIL("did not reject NULL buffer");
    }

    // ── Test 6: NULL psbt_out ────────────────────────────────────────────
    TEST("reject NULL psbt_out");
    {
        uint8_t buf[10] = {0};
        if (psbt_parse(buf, 10, NULL) == PSBT_ERR_INVALID) PASS();
        else FAIL("did not reject NULL output");
    }

    // ── Test 7: Total input value ────────────────────────────────────────
    TEST("psbt_get_total_input_value v0 = 100000");
    {
        uint8_t pbuf[512];
        size_t plen = build_v0_psbt(pbuf, sizeof(pbuf));
        psbt_t psbt;
        psbt_parse(pbuf, plen, &psbt);
        uint64_t val = psbt_get_total_input_value(&psbt);
        if (val == 100000) PASS();
        else { char msg[64]; snprintf(msg, 64, "got %llu", (unsigned long long)val); FAIL(msg); }
    }

    // ── Test 8: Total output value v0 ────────────────────────────────────
    TEST("psbt_get_total_output_value v0 = 100000");
    {
        uint8_t pbuf[512];
        size_t plen = build_v0_psbt(pbuf, sizeof(pbuf));
        psbt_t psbt;
        psbt_parse(pbuf, plen, &psbt);
        uint64_t val = psbt_get_total_output_value(&psbt);
        if (val == 100000) PASS();
        else FAIL("wrong output value");
    }

    // ── Test 9: Fee calculation v0 ───────────────────────────────────────
    TEST("psbt_get_fee v0 = 0 (in == out)");
    {
        uint8_t pbuf[512];
        size_t plen = build_v0_psbt(pbuf, sizeof(pbuf));
        psbt_t psbt;
        psbt_parse(pbuf, plen, &psbt);
        int64_t fee = psbt_get_fee(&psbt);
        if (fee == 0) PASS();
        else FAIL("fee should be 0");
    }

    // ── Test 10: Fee calculation v2 ──────────────────────────────────────
    TEST("psbt_get_fee v2 = 50000 (200000 - 150000)");
    {
        uint8_t pbuf[512];
        size_t plen = build_v2_psbt(pbuf, sizeof(pbuf));
        psbt_t psbt;
        psbt_parse(pbuf, plen, &psbt);
        int64_t fee = psbt_get_fee(&psbt);
        if (fee == 50000) PASS();
        else { char msg[64]; snprintf(msg, 64, "got %lld", (long long)fee); FAIL(msg); }
    }

    // ── Test 11: Total input value v2 ────────────────────────────────────
    TEST("psbt_get_total_input_value v2 = 200000");
    {
        uint8_t pbuf[512];
        size_t plen = build_v2_psbt(pbuf, sizeof(pbuf));
        psbt_t psbt;
        psbt_parse(pbuf, plen, &psbt);
        uint64_t val = psbt_get_total_input_value(&psbt);
        if (val == 200000) PASS();
        else FAIL("wrong input total");
    }

    // ── Test 12: BIP32 derivation path ───────────────────────────────────
    TEST("v0 BIP32 derivation path m/84'/0'/0'");
    {
        uint8_t pbuf[512];
        size_t plen = build_v0_psbt(pbuf, sizeof(pbuf));
        psbt_t psbt;
        psbt_parse(pbuf, plen, &psbt);
        if (!psbt.inputs[0].bip32_derivation.present) FAIL("no derivation");
        else if (psbt.inputs[0].bip32_derivation.path_len != 3) FAIL("wrong path len");
        else if (psbt.inputs[0].bip32_derivation.path[0] != 0x80000054)
            FAIL("wrong first path element");
        else PASS();
    }

    // ── Test 13: Malformed PSBT (truncated global map) ───────────────────
    TEST("reject truncated global map");
    {
        uint8_t buf[7] = {0x70,0x73,0x62,0x74,0xff, 0x01, 0x00};
        psbt_t psbt;
        if (psbt_parse(buf, 7, &psbt) != PSBT_OK) PASS();
        else FAIL("should reject truncated");
    }

    // ── Test 14: Missing global tx in v0 ─────────────────────────────────
    TEST("reject v0 PSBT without global tx");
    {
        uint8_t buf[12] = {0x70,0x73,0x62,0x74,0xff, 0x01, 0xFB, 0x01, 0x00, 0x00, 0x00, 0x00};
        psbt_t psbt;
        if (psbt_parse(buf, 12, &psbt) == PSBT_ERR_PARSE) PASS();
        else FAIL("should reject missing global tx");
    }

    // ── Test 15: Value functions NULL safety ─────────────────────────────
    TEST("psbt_get_total_input_value NULL returns 0");
    {
        if (psbt_get_total_input_value(NULL) == 0) PASS();
        else FAIL("should return 0");
    }

    TEST("psbt_get_total_output_value NULL returns 0");
    {
        if (psbt_get_total_output_value(NULL) == 0) PASS();
        else FAIL("should return 0");
    }

    TEST("psbt_get_fee NULL returns 0");
    {
        if (psbt_get_fee(NULL) == 0) PASS();
        else FAIL("should return 0");
    }

    // ── Test 18: v2 prev_txid field ──────────────────────────────────────
    TEST("v2 PSBT sets prev txid from PSBT_IN_PREVIOUS_TXID");
    {
        uint8_t pbuf[512];
        size_t plen = build_v2_psbt(pbuf, sizeof(pbuf));
        psbt_t psbt;
        psbt_parse(pbuf, plen, &psbt);
        int ok = 1;
        for (int i = 0; i < 32; i++) {
            if (psbt.inputs[0].txid[i] != (uint8_t)(0xFE - i)) { ok = 0; break; }
        }
        if (ok) PASS();
        else FAIL("wrong txid");
    }

    // ── Test 19: Negative fee returns -1 ─────────────────────────────────
    TEST("psbt_get_fee negative (out > in) returns -1");
    {
        psbt_t psbt;
        memset(&psbt, 0, sizeof(psbt));
        psbt.version = 0;
        psbt.input_count = 1;
        psbt.output_count = 1;
        psbt.inputs[0].witness_utxo.present = true;
        psbt.inputs[0].witness_utxo.amount = 100;
        psbt.outputs[0].amount = 200;
        if (psbt_get_fee(&psbt) == -1) PASS();
        else FAIL("should return -1");
    }

    // ── Test 20: PSBT with Taproot internal key ──────────────────────────
    TEST("v2 PSBT with taproot internal key");
    {
        uint8_t pbuf[1024];
        size_t plen = build_v2_psbt(pbuf, sizeof(pbuf));

        size_t ins_pos = 0;
        bool found_first_sep = false;
        for (size_t i = 5; i < plen; i++) {
            if (pbuf[i] == 0x00) { found_first_sep = true; continue; }
            if (found_first_sep) { ins_pos = i; break; }
        }

        uint8_t newbuf[1024];
        memcpy(newbuf, pbuf, ins_pos);
        size_t npos = ins_pos;
        uint8_t tk_key[32];
        for (int i = 0; i < 32; i++) tk_key[i] = (uint8_t)(0x50 + i);
        write_kv(newbuf, &npos, PSBT_IN_TAP_INTERNAL_KEY, NULL, 0, tk_key, 32);
        memcpy(newbuf + npos, pbuf + ins_pos, plen - ins_pos);
        npos += plen - ins_pos;

        psbt_t psbt;
        if (psbt_parse(newbuf, npos, &psbt) != PSBT_OK) FAIL("parse failed");
        else if (!psbt.inputs[0].has_taproot) FAIL("taproot not detected");
        else PASS();
    }

    // ── Summary ──────────────────────────────────────────────────────────
    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}

#else
#include <cstdio>
int main(void) {
    printf("PSBT tests require USE_SE_STUB.\n");
    return 0;
}
#endif
