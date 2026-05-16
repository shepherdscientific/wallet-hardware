#include "psbt.h"
#include <cstring>

static uint8_t read_u8(const uint8_t *buf, size_t *pos, size_t end) {
    if (*pos >= end) return 0;
    return buf[(*pos)++];
}

static uint16_t read_u16le(const uint8_t *buf, size_t *pos, size_t end) {
    if (*pos + 2 > end) { *pos = end; return 0; }
    uint16_t v = (uint16_t)buf[*pos] | ((uint16_t)buf[*pos + 1] << 8);
    *pos += 2;
    return v;
}

static uint32_t read_u32le(const uint8_t *buf, size_t *pos, size_t end) {
    if (*pos + 4 > end) { *pos = end; return 0; }
    uint32_t v = (uint32_t)buf[*pos]
               | ((uint32_t)buf[*pos + 1] << 8)
               | ((uint32_t)buf[*pos + 2] << 16)
               | ((uint32_t)buf[*pos + 3] << 24);
    *pos += 4;
    return v;
}

static uint64_t read_u64le(const uint8_t *buf, size_t *pos, size_t end) {
    if (*pos + 8 > end) { *pos = end; return 0; }
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v |= ((uint64_t)buf[*pos + i]) << (i * 8);
    *pos += 8;
    return v;
}

static uint64_t read_varint(const uint8_t *buf, size_t *pos, size_t end) {
    if (*pos >= end) return 0;
    uint8_t first = buf[(*pos)++];
    if (first < 0xFD) return first;
    if (first == 0xFD) return read_u16le(buf, pos, end);
    if (first == 0xFE) return read_u32le(buf, pos, end);
    return read_u64le(buf, pos, end);
}

static bool copy_bytes(const uint8_t *src, size_t *pos, size_t src_end,
                       uint8_t *dst, size_t dst_max, size_t *written) {
    size_t remaining = src_end - *pos;
    if (remaining < 1) return false;
    uint64_t key_len = read_varint(src, pos, src_end);
    if (key_len > remaining) return false;
    if (key_len > dst_max) return false;
    if (src + *pos + key_len > src + src_end) return false;
    memcpy(dst, src + *pos, (size_t)key_len);
    *pos += (size_t)key_len;
    if (written) *written = (size_t)key_len;
    return true;
}

static bool parse_global_map(const uint8_t *buf, size_t *pos, size_t end,
                             psbt_t *psbt) {
    while (*pos < end) {
        if (*pos >= end) return false;

        uint64_t key_len = read_varint(buf, pos, end);
        if (key_len == 0) return true;

        if (key_len < 1 || *pos + key_len > end) return false;
        uint8_t key_type = buf[(*pos)++];
        size_t key_data_start = *pos;
        size_t key_data_end = *pos + (size_t)(key_len - 1);
        *pos = key_data_end;

        uint64_t val_len = read_varint(buf, pos, end);
        if (*pos + val_len > end) return false;

        size_t val_start = *pos;

        if (key_type == PSBT_GLOBAL_UNSIGNED_TX) {
            if (val_len < 10) return false;
            psbt->has_global_tx = true;

            size_t tx_pos = val_start;
            size_t tx_end = val_start + (size_t)val_len;
            read_u32le(buf, &tx_pos, tx_end);

            bool segwit = false;
            if (tx_pos < tx_end && buf[tx_pos] == 0x00) {
                segwit = true;
                tx_pos += 2;
            }

            uint32_t tx_in_count = (uint32_t)read_varint(buf, &tx_pos, tx_end);
            psbt->input_count = tx_in_count;
            if (tx_in_count > PSBT_MAX_INPUTS) return false;

            for (uint32_t i = 0; i < tx_in_count; i++) {
                if (tx_pos + 36 > tx_end) return false;
                for (int j = 0; j < 32; j++)
                    psbt->inputs[i].txid[j] = buf[tx_pos + j];
                tx_pos += 32;
                psbt->inputs[i].vout = read_u32le(buf, &tx_pos, tx_end);
                uint64_t script_len = read_varint(buf, &tx_pos, tx_end);
                if (tx_pos + script_len + 4 > tx_end) return false;
                tx_pos += (size_t)script_len;
                psbt->inputs[i].sequence = read_u32le(buf, &tx_pos, tx_end);
            }

            uint32_t tx_out_count = (uint32_t)read_varint(buf, &tx_pos, tx_end);
            psbt->output_count = tx_out_count;
            if (tx_out_count > PSBT_MAX_OUTPUTS) return false;

            for (uint32_t i = 0; i < tx_out_count; i++) {
                if (tx_pos + 8 > tx_end) return false;
                psbt->outputs[i].amount = read_u64le(buf, &tx_pos, tx_end);
                uint64_t script_len = read_varint(buf, &tx_pos, tx_end);
                if (tx_pos + script_len > tx_end) return false;
                if (script_len > sizeof(psbt->outputs[0].script_pubkey)) return false;
                memcpy(psbt->outputs[i].script_pubkey, buf + tx_pos, (size_t)script_len);
                psbt->outputs[i].script_pubkey_len = (uint8_t)script_len;
                tx_pos += (size_t)script_len;
            }

            if (tx_pos + 4 > tx_end) return false;
            psbt->locktime = read_u32le(buf, &tx_pos, tx_end);
        }

        *pos = val_start + (size_t)val_len;
    }
    return false;
}

static bool parse_input_map(const uint8_t *buf, size_t *pos, size_t end,
                            psbt_input_t *input, uint8_t version) {
    while (*pos < end) {
        if (*pos >= end) return false;

        uint64_t key_len = read_varint(buf, pos, end);
        if (key_len == 0) return true;

        if (key_len < 1 || *pos + key_len > end) return false;
        uint8_t key_type = buf[(*pos)++];

        size_t key_data_start = *pos;
        size_t key_data_remaining = (size_t)(key_len - 1);
        size_t key_data_end = *pos + key_data_remaining;
        *pos = key_data_end;

        uint64_t val_len = read_varint(buf, pos, end);
        if (*pos + val_len > end) return false;
        size_t val_start = *pos;
        size_t val_end = *pos + (size_t)val_len;

        switch (key_type) {
        case PSBT_IN_WITNESS_UTXO:
            if (val_len >= 8) {
                input->witness_utxo.present = true;
                size_t rd = val_start;
                input->witness_utxo.amount = read_u64le(buf, &rd, val_end);
                size_t script_remaining = (size_t)val_len - 8;
                if (script_remaining <= sizeof(input->witness_utxo.script_pubkey)) {
                    memcpy(input->witness_utxo.script_pubkey,
                           buf + rd, script_remaining);
                    input->witness_utxo.script_pubkey_len = (uint8_t)script_remaining;
                }
            }
            break;
        case PSBT_IN_SIGHASH_TYPE:
            if (val_len >= 4) {
                size_t rd = val_start;
                input->sighash_type = read_u32le(buf, &rd, val_end);
            }
            break;
        case PSBT_IN_BIP32_DERIVATION:
            if (key_data_remaining >= 4) {
                input->bip32_derivation.present = true;
                memcpy(input->bip32_derivation.fingerprint, buf + key_data_start, 4);
                size_t path_bytes = key_data_remaining - 4;
                uint8_t path_len = (uint8_t)(path_bytes / 4);
                if (path_len > PSBT_PATH_MAX) path_len = PSBT_PATH_MAX;
                input->bip32_derivation.path_len = path_len;
                size_t ppos = key_data_start + 4;
                for (uint8_t j = 0; j < path_len; j++)
                    input->bip32_derivation.path[j] =
                        read_u32le(buf, &ppos, ppos + 4);
                if (val_len <= PSBT_PUBKEY_LEN) {
                    memcpy(input->bip32_derivation.pubkey,
                           buf + val_start, (size_t)val_len);
                }
            }
            break;
        case PSBT_IN_PREVIOUS_TXID:
            if (val_len == 32)
                memcpy(input->txid, buf + val_start, 32);
            break;
        case PSBT_IN_OUTPUT_INDEX:
            if (val_len >= 4) {
                size_t rd = val_start;
                input->vout = read_u32le(buf, &rd, val_end);
            }
            break;
        case PSBT_IN_SEQUENCE:
            if (val_len >= 4) {
                size_t rd = val_start;
                input->sequence = read_u32le(buf, &rd, val_end);
            }
            break;
        case PSBT_IN_TAP_INTERNAL_KEY:
            if (val_len == 32) {
                input->has_taproot = true;
                memcpy(input->tap_internal_key, buf + val_start, 32);
            }
            break;
        case PSBT_IN_TAP_BIP32_DERIV:
            if (key_data_remaining >= 4) {
                input->bip32_derivation.present = true;
                memcpy(input->bip32_derivation.fingerprint, buf + key_data_start, 4);
                size_t path_bytes = key_data_remaining - 4;
                uint8_t path_len = (uint8_t)(path_bytes / 4);
                if (path_len > PSBT_PATH_MAX) path_len = PSBT_PATH_MAX;
                input->bip32_derivation.path_len = path_len;
                size_t ppos = key_data_start + 4;
                for (uint8_t j = 0; j < path_len; j++)
                    input->bip32_derivation.path[j] =
                        read_u32le(buf, &ppos, ppos + 4);
            }
            break;
        default:
            break;
        }

        *pos = val_end;
    }
    return false;
}

static bool parse_output_map(const uint8_t *buf, size_t *pos, size_t end,
                             psbt_output_t *output, uint8_t version) {
    while (*pos < end) {
        if (*pos >= end) return false;

        uint64_t key_len = read_varint(buf, pos, end);
        if (key_len == 0) return true;

        if (key_len < 1 || *pos + key_len > end) return false;
        uint8_t key_type = buf[(*pos)++];

        size_t key_data_start = *pos;
        size_t key_data_remaining = (size_t)(key_len - 1);
        size_t key_data_end = *pos + key_data_remaining;
        *pos = key_data_end;

        uint64_t val_len = read_varint(buf, pos, end);
        if (*pos + val_len > end) return false;
        size_t val_start = *pos;
        size_t val_end = *pos + (size_t)val_len;

        switch (key_type) {
        case PSBT_OUT_AMOUNT:
            if (val_len >= 8) {
                size_t rd = val_start;
                output->amount = read_u64le(buf, &rd, val_end);
            }
            break;
        case PSBT_OUT_SCRIPT:
            if (val_len <= sizeof(output->script_pubkey)) {
                memcpy(output->script_pubkey, buf + val_start, (size_t)val_len);
                output->script_pubkey_len = (uint8_t)val_len;
            }
            break;
        case PSBT_OUT_BIP32_DERIVATION:
            if (key_data_remaining >= 4) {
                output->bip32_derivation.present = true;
                memcpy(output->bip32_derivation.fingerprint, buf + key_data_start, 4);
                size_t path_bytes = key_data_remaining - 4;
                uint8_t path_len = (uint8_t)(path_bytes / 4);
                if (path_len > PSBT_PATH_MAX) path_len = PSBT_PATH_MAX;
                output->bip32_derivation.path_len = path_len;
                size_t ppos = key_data_start + 4;
                for (uint8_t j = 0; j < path_len; j++)
                    output->bip32_derivation.path[j] =
                        read_u32le(buf, &ppos, ppos + 4);
            }
            break;
        case PSBT_OUT_TAP_BIP32_DERIV:
            if (key_data_remaining >= 4) {
                output->bip32_derivation.present = true;
                memcpy(output->bip32_derivation.fingerprint, buf + key_data_start, 4);
                size_t path_bytes = key_data_remaining - 4;
                uint8_t path_len = (uint8_t)(path_bytes / 4);
                if (path_len > PSBT_PATH_MAX) path_len = PSBT_PATH_MAX;
                output->bip32_derivation.path_len = path_len;
                size_t ppos = key_data_start + 4;
                for (uint8_t j = 0; j < path_len; j++)
                    output->bip32_derivation.path[j] =
                        read_u32le(buf, &ppos, ppos + 4);
            }
            break;
        default:
            break;
        }

        *pos = val_end;
    }
    return false;
}

static bool is_input_map_type(uint8_t first_key_type) {
    switch (first_key_type) {
    case PSBT_IN_NON_WITNESS_UTXO:
    case PSBT_IN_WITNESS_UTXO:
    case PSBT_IN_PARTIAL_SIG:
    case PSBT_IN_SIGHASH_TYPE:
    case PSBT_IN_REDEEM_SCRIPT:
    case PSBT_IN_WITNESS_SCRIPT:
    case PSBT_IN_BIP32_DERIVATION:
    case PSBT_IN_PREVIOUS_TXID:
    case PSBT_IN_OUTPUT_INDEX:
    case PSBT_IN_SEQUENCE:
    case PSBT_IN_TAP_KEY_SIG:
    case PSBT_IN_TAP_BIP32_DERIV:
    case PSBT_IN_TAP_INTERNAL_KEY:
        return true;
    default:
        return false;
    }
}

static bool is_output_map_type(uint8_t first_key_type) {
    switch (first_key_type) {
    case PSBT_OUT_REDEEM_SCRIPT:
    case PSBT_OUT_WITNESS_SCRIPT:
    case PSBT_OUT_BIP32_DERIVATION:
    case PSBT_OUT_AMOUNT:
    case PSBT_OUT_SCRIPT:
    case PSBT_OUT_TAP_BIP32_DERIV:
        return true;
    default:
        return false;
    }
}

psbt_err_t psbt_parse(const uint8_t *buf, size_t len, psbt_t *psbt_out) {
    if (!buf || !psbt_out) return PSBT_ERR_INVALID;
    if (len < 5) return PSBT_ERR_MAGIC;

    memset(psbt_out, 0, sizeof(psbt_t));

    if (buf[0] != 0x70 || buf[1] != 0x73 || buf[2] != 0x62 || buf[3] != 0x74)
        return PSBT_ERR_MAGIC;
    if (buf[4] == 0xff)
        psbt_out->version = 0;
    else if (buf[4] == 0xfe)
        psbt_out->version = 2;
    else
        return PSBT_ERR_MAGIC;

    size_t pos = 5;

    if (!parse_global_map(buf, &pos, len, psbt_out))
        return PSBT_ERR_PARSE;

    if (psbt_out->version == 0) {
        if (!psbt_out->has_global_tx)
            return PSBT_ERR_PARSE;

        for (uint32_t i = 0; i < psbt_out->input_count; i++) {
            if (pos >= len) return PSBT_ERR_PARSE;
            if (!parse_input_map(buf, &pos, len, &psbt_out->inputs[i], 0))
                return PSBT_ERR_PARSE;
        }

        for (uint32_t i = 0; i < psbt_out->output_count; i++) {
            if (pos >= len) return PSBT_ERR_PARSE;
            if (!parse_output_map(buf, &pos, len, &psbt_out->outputs[i], 0))
                return PSBT_ERR_PARSE;
        }
    } else {
        uint32_t in_count = 0;
        uint32_t out_count = 0;

        while (pos < len) {
            size_t peek_pos = pos;
            uint64_t kl = read_varint(buf, &peek_pos, len);
            if (kl == 0) { pos = peek_pos; continue; }
            if (peek_pos >= len) break;

            bool is_input = false;
            size_t scan = pos;
            while (scan < len) {
                uint64_t sk = read_varint(buf, &scan, len);
                if (sk == 0) break;
                if (scan >= len) break;
                uint8_t kt = buf[scan++];
                if (scan + (size_t)(sk - 1) > len) break;
                scan += (size_t)(sk - 1);
                uint64_t sv = read_varint(buf, &scan, len);
                if (scan + sv > len) break;
                if (kt == PSBT_IN_PREVIOUS_TXID) { is_input = true; }
                scan += (size_t)sv;
            }

            if (is_input) {
                if (in_count >= PSBT_MAX_INPUTS) return PSBT_ERR_TOO_LARGE;
                if (!parse_input_map(buf, &pos, len, &psbt_out->inputs[in_count], 2))
                    return PSBT_ERR_PARSE;
                in_count++;
            } else {
                if (out_count >= PSBT_MAX_OUTPUTS) return PSBT_ERR_TOO_LARGE;
                if (!parse_output_map(buf, &pos, len, &psbt_out->outputs[out_count], 2))
                    return PSBT_ERR_PARSE;
                out_count++;
            }
        }

        psbt_out->input_count = in_count;
        psbt_out->output_count = out_count;
    }

    return PSBT_OK;
}

uint64_t psbt_get_total_input_value(const psbt_t *psbt) {
    if (!psbt) return 0;
    uint64_t total = 0;
    if (psbt->version == 0) {
        for (uint32_t i = 0; i < psbt->input_count; i++) {
            if (!psbt->inputs[i].witness_utxo.present) continue;
            total += psbt->inputs[i].witness_utxo.amount;
        }
    } else {
        for (uint32_t i = 0; i < psbt->input_count; i++) {
            if (!psbt->inputs[i].witness_utxo.present) continue;
            total += psbt->inputs[i].witness_utxo.amount;
        }
    }
    return total;
}

uint64_t psbt_get_total_output_value(const psbt_t *psbt) {
    if (!psbt) return 0;
    uint64_t total = 0;
    for (uint32_t i = 0; i < psbt->output_count; i++)
        total += psbt->outputs[i].amount;
    return total;
}

int64_t psbt_get_fee(const psbt_t *psbt) {
    if (!psbt) return 0;
    uint64_t in = psbt_get_total_input_value(psbt);
    uint64_t out = psbt_get_total_output_value(psbt);
    if (in < out) return -1;
    return (int64_t)(in - out);
}
