#include "psbt_signer.h"
#include "se051_hal.h"
#include "sha256.h"
#include "ripemd160.h"
#include "bip32.h"
#include <string.h>

static void dbl_sha256(const uint8_t *data, size_t len, uint8_t hash[32]) {
  uint8_t first[32];
  sha256(data, len, first);
  sha256(first, 32, hash);
}

static void tagged_hash(const uint8_t *tag, size_t tag_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t hash[32]) {
  uint8_t tag_hash[32];
  sha256(tag, tag_len, tag_hash);
  sha256_ctx ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, tag_hash, 32);
  sha256_update(&ctx, tag_hash, 32);
  sha256_update(&ctx, msg, msg_len);
  sha256_final(&ctx, hash);
}

static void write_u32le(uint8_t *buf, uint32_t val) {
  buf[0] = (uint8_t)(val & 0xFF);
  buf[1] = (uint8_t)((val >> 8) & 0xFF);
  buf[2] = (uint8_t)((val >> 16) & 0xFF);
  buf[3] = (uint8_t)((val >> 24) & 0xFF);
}

static void write_u64le(uint8_t *buf, uint64_t val) {
  for (int i = 0; i < 8; i++)
    buf[i] = (uint8_t)((val >> (i * 8)) & 0xFF);
}

static void write_varint_len(uint8_t *buf, size_t *pos, uint64_t val) {
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

static bool is_p2wpkh(const psbt_input_t *input) {
  return input->witness_utxo.present &&
         input->witness_utxo.script_pubkey_len == 22 &&
         input->witness_utxo.script_pubkey[0] == 0x00 &&
         input->witness_utxo.script_pubkey[1] == 0x14;
}

static bool is_p2tr(const psbt_input_t *input) {
  return input->witness_utxo.present &&
         input->witness_utxo.script_pubkey_len == 34 &&
         input->witness_utxo.script_pubkey[0] == 0x51 &&
         input->witness_utxo.script_pubkey[1] == 0x20;
}

static se051_err_t se051_derive_child_key(const uint32_t *path, uint8_t path_len,
                                           uint8_t temp_key_id) {
  uint8_t key[BIP32_KEY_LEN];
  uint8_t chain[BIP32_CHAIN_LEN];
  size_t out_len;

  if (se051_read_object(SE051_KEY_BIP32_MASTER, key, sizeof(key), &out_len) != SE_OK)
    return SE_ERR_NOTFOUND;
  if (out_len < BIP32_KEY_LEN) {
    memset(key, 0, sizeof(key));
    return SE_ERR_PARAM;
  }

  if (se051_read_object(SE051_KEY_CHAIN_CODE, chain, sizeof(chain), &out_len) != SE_OK) {
    memset(key, 0, sizeof(key));
    return SE_ERR_NOTFOUND;
  }
  if (out_len < BIP32_CHAIN_LEN) {
    memset(key, 0, sizeof(key));
    memset(chain, 0, sizeof(chain));
    return SE_ERR_PARAM;
  }

  uint8_t cur_key[BIP32_KEY_LEN];
  uint8_t cur_chain[BIP32_CHAIN_LEN];
  memcpy(cur_key, key, sizeof(cur_key));
  memcpy(cur_chain, chain, sizeof(cur_chain));
  memset(key, 0, sizeof(key));
  memset(chain, 0, sizeof(chain));

  for (uint8_t i = 0; i < path_len; i++) {
    uint8_t child_key[BIP32_KEY_LEN];
    uint8_t child_chain[BIP32_CHAIN_LEN];
    if (!hd_ckd_priv(cur_key, cur_chain, path[i], child_key, child_chain)) {
      memset(cur_key, 0, sizeof(cur_key));
      memset(cur_chain, 0, sizeof(cur_chain));
      return SE_ERR_INTERNAL;
    }
    memcpy(cur_key, child_key, sizeof(cur_key));
    memcpy(cur_chain, child_chain, sizeof(cur_chain));
    memset(child_key, 0, sizeof(child_key));
    memset(child_chain, 0, sizeof(child_chain));
  }

  se051_err_t err = se051_store_key(temp_key_id, cur_key, BIP32_KEY_LEN);
  memset(cur_key, 0, sizeof(cur_key));
  memset(cur_chain, 0, sizeof(cur_chain));
  return err;
}

static void build_scriptcode(const uint8_t script_pubkey[64], uint8_t scriptcode[25]) {
  scriptcode[0] = 0x19;
  scriptcode[1] = 0x76;
  scriptcode[2] = 0xa9;
  scriptcode[3] = 0x14;
  memcpy(scriptcode + 4, script_pubkey + 2, 20);
  scriptcode[24] = 0x88;
  scriptcode[25] = 0xac;
}

static void compute_hash_prevouts(const psbt_t *psbt, uint8_t hash[32]) {
  uint8_t buf[PSBT_MAX_INPUTS * 36];
  size_t pos = 0;
  for (uint32_t i = 0; i < psbt->input_count; i++) {
    memcpy(buf + pos, psbt->inputs[i].txid, 32);
    pos += 32;
    write_u32le(buf + pos, psbt->inputs[i].vout);
    pos += 4;
  }
  dbl_sha256(buf, pos, hash);
}

static void compute_hash_sequence(const psbt_t *psbt, uint8_t hash[32]) {
  uint8_t buf[PSBT_MAX_INPUTS * 4];
  size_t pos = 0;
  for (uint32_t i = 0; i < psbt->input_count; i++) {
    write_u32le(buf + pos, psbt->inputs[i].sequence);
    pos += 4;
  }
  dbl_sha256(buf, pos, hash);
}

static void compute_hash_outputs(const psbt_t *psbt, uint8_t hash[32]) {
  uint8_t buf[1024];
  size_t pos = 0;
  for (uint32_t i = 0; i < psbt->output_count; i++) {
    write_u64le(buf + pos, psbt->outputs[i].amount);
    pos += 8;
    write_varint_len(buf, &pos, psbt->outputs[i].script_pubkey_len);
    memcpy(buf + pos, psbt->outputs[i].script_pubkey,
           psbt->outputs[i].script_pubkey_len);
    pos += psbt->outputs[i].script_pubkey_len;
  }
  dbl_sha256(buf, pos, hash);
}

bool sighash_bip143(const psbt_t *psbt, uint32_t input_index,
                     uint32_t sighash_type, uint8_t hash_out[32]) {
  if (!psbt || !hash_out) return false;
  if (input_index >= psbt->input_count) return false;
  if (!is_p2wpkh(&psbt->inputs[input_index])) return false;

  uint8_t hash_prevouts[32];
  uint8_t hash_sequence[32];
  uint8_t hash_outputs[32];
  compute_hash_prevouts(psbt, hash_prevouts);
  compute_hash_sequence(psbt, hash_sequence);
  compute_hash_outputs(psbt, hash_outputs);

  const psbt_input_t *input = &psbt->inputs[input_index];
  uint8_t scriptcode[26];
  build_scriptcode(input->witness_utxo.script_pubkey, scriptcode);

  uint8_t buf[256];
  size_t pos = 0;
  write_u32le(buf + pos, psbt->tx_version);
  pos += 4;
  memcpy(buf + pos, hash_prevouts, 32); pos += 32;
  memcpy(buf + pos, hash_sequence, 32); pos += 32;
  memcpy(buf + pos, input->txid, 32); pos += 32;
  write_u32le(buf + pos, input->vout); pos += 4;
  memcpy(buf + pos, scriptcode, 26); pos += 26;
  write_u64le(buf + pos, input->witness_utxo.amount); pos += 8;
  write_u32le(buf + pos, input->sequence); pos += 4;
  memcpy(buf + pos, hash_outputs, 32); pos += 32;
  write_u32le(buf + pos, psbt->locktime); pos += 4;
  write_u32le(buf + pos, sighash_type); pos += 4;

  dbl_sha256(buf, pos, hash_out);
  return true;
}

static void compute_sha_amounts(const psbt_t *psbt, uint8_t hash[32]) {
  uint8_t buf[PSBT_MAX_INPUTS * 8];
  size_t pos = 0;
  for (uint32_t i = 0; i < psbt->input_count; i++) {
    if (!psbt->inputs[i].witness_utxo.present) {
      memset(buf + pos, 0, 8);
      pos += 8;
      continue;
    }
    write_u64le(buf + pos, psbt->inputs[i].witness_utxo.amount);
    pos += 8;
  }
  sha256(buf, pos, hash);
}

static void compute_sha_scriptpubkeys(const psbt_t *psbt, uint8_t hash[32]) {
  uint8_t buf[1024];
  size_t pos = 0;
  for (uint32_t i = 0; i < psbt->input_count; i++) {
    const psbt_input_t *inp = &psbt->inputs[i];
    if (!inp->witness_utxo.present) {
      buf[pos++] = 0x00;
      continue;
    }
    write_varint_len(buf, &pos, inp->witness_utxo.script_pubkey_len);
    memcpy(buf + pos, inp->witness_utxo.script_pubkey,
           inp->witness_utxo.script_pubkey_len);
    pos += inp->witness_utxo.script_pubkey_len;
  }
  sha256(buf, pos, hash);
}

static void compute_sha_sequences(const psbt_t *psbt, uint8_t hash[32]) {
  uint8_t buf[PSBT_MAX_INPUTS * 4];
  size_t pos = 0;
  for (uint32_t i = 0; i < psbt->input_count; i++) {
    write_u32le(buf + pos, psbt->inputs[i].sequence);
    pos += 4;
  }
  sha256(buf, pos, hash);
}

static void compute_sha_outputs(const psbt_t *psbt, uint8_t hash[32]) {
  uint8_t buf[1024];
  size_t pos = 0;
  for (uint32_t i = 0; i < psbt->output_count; i++) {
    write_u64le(buf + pos, psbt->outputs[i].amount);
    pos += 8;
    write_varint_len(buf, &pos, psbt->outputs[i].script_pubkey_len);
    memcpy(buf + pos, psbt->outputs[i].script_pubkey,
           psbt->outputs[i].script_pubkey_len);
    pos += psbt->outputs[i].script_pubkey_len;
  }
  sha256(buf, pos, hash);
}

bool sighash_bip341(const psbt_t *psbt, uint32_t input_index,
                     uint8_t hash_out[32]) {
  if (!psbt || !hash_out) return false;
  if (input_index >= psbt->input_count) return false;
  if (!is_p2tr(&psbt->inputs[input_index])) return false;

  uint8_t sha_prevouts[32];
  uint8_t sha_amounts[32];
  uint8_t sha_scriptpubkeys[32];
  uint8_t sha_sequences[32];
  uint8_t sha_outputs[32];

  compute_hash_prevouts(psbt, sha_prevouts);
  compute_sha_amounts(psbt, sha_amounts);
  compute_sha_scriptpubkeys(psbt, sha_scriptpubkeys);
  compute_sha_sequences(psbt, sha_sequences);
  compute_sha_outputs(psbt, sha_outputs);

  uint8_t sigmsg[256];
  size_t pos = 0;
  sigmsg[pos++] = 0x00;
  write_u32le(sigmsg + pos, psbt->tx_version); pos += 4;
  write_u32le(sigmsg + pos, psbt->locktime); pos += 4;
  memcpy(sigmsg + pos, sha_prevouts, 32); pos += 32;
  memcpy(sigmsg + pos, sha_amounts, 32); pos += 32;
  memcpy(sigmsg + pos, sha_scriptpubkeys, 32); pos += 32;
  memcpy(sigmsg + pos, sha_sequences, 32); pos += 32;
  memcpy(sigmsg + pos, sha_outputs, 32); pos += 32;
  sigmsg[pos++] = 0x00;
  write_u32le(sigmsg + pos, (uint32_t)input_index); pos += 4;

  const char tag[] = "TapSighash";
  tagged_hash((const uint8_t *)tag, 10, sigmsg, pos, hash_out);
  return true;
}

static bool input_is_owned(const psbt_input_t *input) {
  return input->bip32_derivation.present && input->bip32_derivation.path_len > 0;
}

static int psbt_sign_input(psbt_t *psbt, uint32_t input_index) {
  psbt_input_t *input = &psbt->inputs[input_index];
  if (!input_is_owned(input)) return 0;

  if (input->bip32_derivation.path_len > PSBT_PATH_MAX)
    return PSBT_SIGN_ERR_PARAM;

  uint32_t path[PSBT_PATH_MAX];
  for (uint8_t i = 0; i < input->bip32_derivation.path_len; i++)
    path[i] = input->bip32_derivation.path[i];

  se051_err_t err = se051_derive_child_key(path,
      input->bip32_derivation.path_len, PSBT_TEMP_KEY_ID);
  if (err != SE_OK) return PSBT_SIGN_ERR_SE;

  uint8_t sighash[32];
  uint32_t sighash_type = input->sighash_type ? input->sighash_type : PSBT_SIGHASH_ALL;

  if (is_p2wpkh(input)) {
    if (!sighash_bip143(psbt, input_index, sighash_type, sighash)) {
      se051_delete_key(PSBT_TEMP_KEY_ID);
      return PSBT_SIGN_ERR_SIGHASH;
    }

    size_t sig_len;
    uint8_t sig[SE051_ECDSA_MAX_DER_LEN];
    err = se051_ecdsa_sign(PSBT_TEMP_KEY_ID, sighash, sig, &sig_len);
    if (err != SE_OK) {
      se051_delete_key(PSBT_TEMP_KEY_ID);
      return PSBT_SIGN_ERR_SE;
    }

    uint8_t pubkey[SE051_PUBKEY_COMPRESSED];
    if (se051_get_pubkey(PSBT_TEMP_KEY_ID, pubkey) != SE_OK) {
      se051_delete_key(PSBT_TEMP_KEY_ID);
      memset(sig, 0, sizeof(sig));
      return PSBT_SIGN_ERR_SE;
    }

    sig[sig_len++] = (uint8_t)(sighash_type & 0xFF);
    if (sig_len > sizeof(input->partial_sig)) sig_len = sizeof(input->partial_sig);
    input->has_partial_sig = true;
    memcpy(input->partial_sig_pubkey, pubkey, PSBT_PUBKEY_LEN);
    memcpy(input->partial_sig, sig, sig_len);
    input->partial_sig_len = (uint8_t)sig_len;
    memset(sig, 0, sizeof(sig));
  } else if (is_p2tr(input)) {
    if (!sighash_bip341(psbt, input_index, sighash)) {
      se051_delete_key(PSBT_TEMP_KEY_ID);
      return PSBT_SIGN_ERR_SIGHASH;
    }

    uint8_t sig[64];
    err = se051_schnorr_sign(PSBT_TEMP_KEY_ID, sighash, sig);
    if (err != SE_OK) {
      se051_delete_key(PSBT_TEMP_KEY_ID);
      return PSBT_SIGN_ERR_SE;
    }

    input->has_tap_key_sig = true;
    memcpy(input->tap_key_sig, sig, 64);
    memset(sig, 0, sizeof(sig));
  } else {
    se051_delete_key(PSBT_TEMP_KEY_ID);
    return PSBT_SIGN_ERR_PARAM;
  }

  se051_delete_key(PSBT_TEMP_KEY_ID);
  return 1;
}

int psbt_sign(psbt_t *psbt, const bool *selected) {
  if (!psbt) return PSBT_SIGN_ERR_PARAM;

  int signed_count = 0;
  for (uint32_t i = 0; i < psbt->input_count; i++) {
    if (selected && !selected[i]) continue;
    int result = psbt_sign_input(psbt, i);
    if (result < 0) {
      for (uint32_t j = 0; j < psbt->input_count; j++) {
        psbt->inputs[j].has_partial_sig = false;
        psbt->inputs[j].has_tap_key_sig = false;
      }
      return result;
    }
    signed_count += result;
  }
  return signed_count;
}
