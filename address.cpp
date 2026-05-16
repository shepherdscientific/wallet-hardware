#include "address.h"
#include "bip32.h"
#include "sha256.h"
#include "ripemd160.h"
#include "base58.h"
#include "bech32.h"
#include "se051_hal.h"
#include <string.h>

static void hash160(const uint8_t *data, size_t len, uint8_t out[20]) {
  uint8_t sha[32];
  sha256(data, len, sha);
  ripemd160(sha, 32, out);
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

static bool gen_p2pkh(const uint8_t pubkey[33], char out[MAX_ADDRESS_LEN]) {
  uint8_t h160[20];
  hash160(pubkey, 33, h160);
  return base58check_encode(0x00, h160, 20, out);
}

static bool gen_p2wpkh(const uint8_t pubkey[33], char out[MAX_ADDRESS_LEN]) {
  uint8_t h160[20];
  hash160(pubkey, 33, h160);
  return bech32_encode("bc", 0, h160, 20, out);
}

static bool gen_p2tr(const uint8_t pubkey[33], char out[MAX_ADDRESS_LEN]) {
  const uint8_t *internal_xonly = pubkey + 1;

  const char tag[] = "TapTweak";
  uint8_t tweak[32];
  tagged_hash((const uint8_t *)tag, 8, internal_xonly, 32, tweak);

  uint8_t tweaked_xonly[32];
  if (!hd_ec_pubkey_tweak(pubkey, tweak, tweaked_xonly))
    return false;

  return bech32m_encode("bc", 1, tweaked_xonly, 32, out);
}

bool address_generate(address_type_t type, uint32_t index,
                      char addr_out[MAX_ADDRESS_LEN]) {
  if (!addr_out) return false;
  return address_generate_with_path(type, 0, index, addr_out);
}

bool address_generate_with_path(address_type_t type, uint32_t change,
                                uint32_t index, char addr_out[MAX_ADDRESS_LEN]) {
  if (!addr_out) return false;

  hd_path_t path;
  switch (type) {
    case ADDRESS_P2PKH: path.path[0] = (44 | HD_HARDENED); break;
    case ADDRESS_P2WPKH: path.path[0] = (84 | HD_HARDENED); break;
    case ADDRESS_P2TR: path.path[0] = (86 | HD_HARDENED); break;
    default: return false;
  }
  path.path[1] = (0 | HD_HARDENED);
  path.path[2] = (0 | HD_HARDENED);
  path.path[3] = change;
  path.path[4] = index;

  uint8_t pubkey[BIP32_PUBKEY_LEN];
  if (!hd_derive_pubkey(&path, index, pubkey))
    return false;

  switch (type) {
    case ADDRESS_P2PKH:  return gen_p2pkh(pubkey, addr_out);
    case ADDRESS_P2WPKH: return gen_p2wpkh(pubkey, addr_out);
    case ADDRESS_P2TR:   return gen_p2tr(pubkey, addr_out);
    default:             return false;
  }
}

const char *address_type_name(address_type_t type) {
  switch (type) {
    case ADDRESS_P2PKH:  return "P2PKH";
    case ADDRESS_P2WPKH: return "P2WPKH";
    case ADDRESS_P2TR:   return "P2TR";
    default:             return "UNKNOWN";
  }
}
