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

static size_t build_v0_psbt(uint8_t *buf, size_t buf_max) {
    memset(buf, 0, buf_max);
    size_t pos = 0;

    memcpy(buf + pos, "\x70\x73\x62\x74\xff", 5);
    pos += 5;

    uint8_t tx[256];
    size_t tx_pos = 0;
    write_u32le(tx, &tx_pos, 1);
    tx[tx_pos++] = 0x00; tx[tx_pos++] = 0x01;
    tx[tx_pos++] = 0x01;
    for (int i = 0; i < 32; i++) tx[tx_pos++] = (uint8_t)(0xAB + i);
    write_u32le(tx, &tx_pos, 0);
    tx[tx_pos++] = 0x00;
    write_u32le(tx, &tx_pos, 0xFFFFFFFD);
    tx[tx_pos++] = 0x01;
    write_u64le(tx, &tx_pos, 100000ULL);
    tx[tx_pos++] = 0x16;
    tx[tx_pos++] = 0x00;
    tx[tx_pos++] = 0x14;
    for (int i = 0; i < 20; i++) tx[tx_pos++] = (uint8_t)(0xCC + i);
    write_u32le(tx, &tx_pos, 0);

    write_kv(buf, &pos, PSBT_GLOBAL_UNSIGNED_TX, NULL, 0, tx, tx_pos);
    buf[pos++] = 0x00;

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
    buf[pos++] = 0x00;

    write_kv(buf, &pos, PSBT_OUT_BIP32_DERIVATION, deriv_key, dk_pos, pubkey, 33);
    buf[pos++] = 0x00;

    return pos;
}

int main(void) {
    printf("=== PSBT Serialize Unit Tests ===\n\n");

    TEST("v0 parse→serialize→parse roundtrip");
    {
        uint8_t original[1024];
        size_t orig_len = build_v0_psbt(original, sizeof(original));

        psbt_t psbt1;
        if (psbt_parse(original, orig_len, &psbt1) != PSBT_OK)
            FAIL("first parse failed");
        else {
            uint8_t serialized[2048];
            size_t ser_len = psbt_serialize(&psbt1, serialized, sizeof(serialized));
            if (ser_len == 0) FAIL("serialize failed");
            else {
                psbt_t psbt2;
                if (psbt_parse(serialized, ser_len, &psbt2) != PSBT_OK)
                    FAIL("second parse failed");
                else if (psbt2.version != psbt1.version)
                    FAIL("version mismatch");
                else if (psbt2.input_count != psbt1.input_count)
                    FAIL("input count mismatch");
                else if (psbt2.output_count != psbt1.output_count)
                    FAIL("output count mismatch");
                else if (psbt2.inputs[0].witness_utxo.amount !=
                         psbt1.inputs[0].witness_utxo.amount)
                    FAIL("witness amount mismatch");
                else if (psbt2.inputs[0].sighash_type !=
                         psbt1.inputs[0].sighash_type)
                    FAIL("sighash type mismatch");
                else PASS();
            }
        }
    }

    TEST("serialize after adding partial_sig");
    {
        uint8_t original[1024];
        size_t orig_len = build_v0_psbt(original, sizeof(original));

        psbt_t psbt;
        psbt_parse(original, orig_len, &psbt);

        psbt.inputs[0].has_partial_sig = true;
        for (uint8_t i = 0; i < PSBT_PUBKEY_LEN; i++)
            psbt.inputs[0].partial_sig_pubkey[i] = (uint8_t)(0x20 + i);
        for (uint8_t i = 0; i < 70; i++)
            psbt.inputs[0].partial_sig[i] = (uint8_t)(0x30 + i);
        psbt.inputs[0].partial_sig_len = 70;

        uint8_t serialized[2048];
        size_t ser_len = psbt_serialize(&psbt, serialized, sizeof(serialized));
        if (ser_len == 0) FAIL("serialize failed");
        else {
            psbt_t psbt2;
            if (psbt_parse(serialized, ser_len, &psbt2) != PSBT_OK)
                FAIL("re-parse failed");
            else if (!psbt2.inputs[0].has_partial_sig)
                FAIL("partial_sig not preserved");
            else if (psbt2.inputs[0].partial_sig_len != 70)
                FAIL("partial_sig length mismatch");
            else if (memcmp(psbt2.inputs[0].partial_sig,
                            psbt.inputs[0].partial_sig, 70) != 0)
                FAIL("partial_sig data mismatch");
            else PASS();
        }
    }

    TEST("serialize with tap_key_sig");
    {
        uint8_t original[1024];
        size_t orig_len = build_v0_psbt(original, sizeof(original));

        psbt_t psbt;
        psbt_parse(original, orig_len, &psbt);

        psbt.inputs[0].has_tap_key_sig = true;
        for (uint8_t i = 0; i < PSBT_SCHNORR_SIG_LEN; i++)
            psbt.inputs[0].tap_key_sig[i] = (uint8_t)(0x50 + i);

        uint8_t serialized[2048];
        size_t ser_len = psbt_serialize(&psbt, serialized, sizeof(serialized));
        if (ser_len == 0) FAIL("serialize failed");
        else {
            psbt_t psbt2;
            if (psbt_parse(serialized, ser_len, &psbt2) != PSBT_OK)
                FAIL("re-parse failed");
            else if (!psbt2.inputs[0].has_tap_key_sig)
                FAIL("tap_key_sig not preserved");
            else if (memcmp(psbt2.inputs[0].tap_key_sig,
                            psbt.inputs[0].tap_key_sig,
                            PSBT_SCHNORR_SIG_LEN) != 0)
                FAIL("tap_key_sig data mismatch");
            else PASS();
        }
    }

    TEST("serialize taproot internal key");
    {
        uint8_t original[1024];
        size_t orig_len = build_v0_psbt(original, sizeof(original));

        psbt_t psbt;
        psbt_parse(original, orig_len, &psbt);

        psbt.inputs[0].has_taproot = true;
        for (uint8_t i = 0; i < 32; i++)
            psbt.inputs[0].tap_internal_key[i] = (uint8_t)(0x60 + i);

        uint8_t serialized[2048];
        size_t ser_len = psbt_serialize(&psbt, serialized, sizeof(serialized));
        if (ser_len == 0) FAIL("serialize failed");
        else {
            psbt_t psbt2;
            if (psbt_parse(serialized, ser_len, &psbt2) != PSBT_OK)
                FAIL("re-parse failed");
            else if (!psbt2.inputs[0].has_taproot)
                FAIL("taproot not preserved");
            else if (memcmp(psbt2.inputs[0].tap_internal_key,
                            psbt.inputs[0].tap_internal_key, 32) != 0)
                FAIL("tap_internal_key mismatch");
            else PASS();
        }
    }

    TEST("serialize two inputs two outputs");
    {
        psbt_t psbt;
        memset(&psbt, 0, sizeof(psbt));
        psbt.version = 0;
        psbt.tx_version = 2;
        psbt.tx_has_segwit_marker = true;
        psbt.input_count = 2;
        psbt.output_count = 2;
        psbt.locktime = 100;

        for (uint32_t i = 0; i < 2; i++) {
            for (int j = 0; j < 32; j++)
                psbt.inputs[i].txid[j] = (uint8_t)(0xDE + i * 10 + j);
            psbt.inputs[i].vout = i;
            psbt.inputs[i].sequence = 0xFFFFFFFF;
            psbt.inputs[i].witness_utxo.present = true;
            psbt.inputs[i].witness_utxo.amount = 50000000;
            psbt.inputs[i].witness_utxo.script_pubkey[0] = 0x00;
            psbt.inputs[i].witness_utxo.script_pubkey[1] = 0x14;
            for (int j = 0; j < 20; j++)
                psbt.inputs[i].witness_utxo.script_pubkey[2 + j] = (uint8_t)(0xAA + i * 20 + j);
            psbt.inputs[i].witness_utxo.script_pubkey_len = 22;
        }

        for (uint32_t i = 0; i < 2; i++) {
            psbt.outputs[i].amount = 40000000 + i * 5000000;
            psbt.outputs[i].script_pubkey[0] = 0x00; psbt.outputs[i].script_pubkey[1] = 0x14;
            for (int j = 0; j < 20; j++)
                psbt.outputs[i].script_pubkey[2 + j] = (uint8_t)(0xBB + i * 20 + j);
            psbt.outputs[i].script_pubkey_len = 22;
        }

        uint8_t serialized[4096];
        size_t ser_len = psbt_serialize(&psbt, serialized, sizeof(serialized));
        if (ser_len == 0) FAIL("serialize failed");
        else {
            psbt_t psbt2;
            if (psbt_parse(serialized, ser_len, &psbt2) != PSBT_OK)
                FAIL("re-parse failed");
            else if (psbt2.input_count != 2)
                FAIL("input count mismatch");
            else if (psbt2.output_count != 2)
                FAIL("output count mismatch");
            else if (psbt2.outputs[0].amount != 40000000)
                FAIL("output 0 amount mismatch");
            else if (psbt2.outputs[1].amount != 45000000)
                FAIL("output 1 amount mismatch");
            else PASS();
        }
    }

    TEST("serialize NULL psbt returns 0");
    {
        uint8_t buf[32];
        size_t len = psbt_serialize(NULL, buf, sizeof(buf));
        if (len == 0) PASS();
        else FAIL("should return 0");
    }

    TEST("serialize NULL buf returns 0");
    {
        psbt_t psbt;
        memset(&psbt, 0, sizeof(psbt));
        size_t len = psbt_serialize(&psbt, NULL, 100);
        if (len == 0) PASS();
        else FAIL("should return 0");
    }

    TEST("serialize buf too small returns 0");
    {
        psbt_t psbt;
        memset(&psbt, 0, sizeof(psbt));
        size_t len = psbt_serialize(&psbt, (uint8_t *)"x", 5);
        if (len == 0) PASS();
        else FAIL("should return 0 for small buffer");
    }

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}

#else
#include <cstdio>
int main(void) {
    printf("PSBT serialize tests require USE_SE_STUB.\n");
    return 0;
}
#endif
