#include "wallet_storage.h"
#include "se051_hal.h"
#include "hmac_sha512.h"
#include "bip32.h"
#include "sha256.h"
#include "ripemd160.h"
#include <string.h>

#if defined(ARDUINO) && defined(ESP32)
#include <Preferences.h>
static Preferences s_wlt_prefs;
#define NVS_WLT_NAMESPACE "wlt"
#define NVS_WLT_XPUB_KEY  "acct_xpub"
#endif

#define PBKDF2_ITERATIONS 2048
#define BIP32_SEED_LEN    64
#define BIP32_MASTER_KEY_LEN 32
#define BIP32_CHAIN_CODE_LEN 32

static const char BIP39_SALT_PREFIX[] = "mnemonic";
static const char BIP32_KEY_PREFIX[]  = "Bitcoin seed";

static void secure_zero(void *buf, size_t len) {
  volatile uint8_t *p = (volatile uint8_t *)buf;
  while (len--) *p++ = 0;
}

static void pbkdf2_hmac_sha512(const uint8_t *password, size_t password_len,
                               const uint8_t *salt, size_t salt_len,
                               uint32_t iterations,
                               uint8_t derived_key[BIP32_SEED_LEN]) {
  uint8_t U_current[HMAC_SHA512_OUTPUT_SIZE];
  uint8_t U_xor[HMAC_SHA512_OUTPUT_SIZE];
  uint8_t salt_cat[256];
  size_t  salt_cat_len;

  memset(U_xor, 0, sizeof(U_xor));

  if (salt_len + 4 > sizeof(salt_cat)) return;
  memcpy(salt_cat, salt, salt_len);
  salt_cat[salt_len + 0] = 0x00;
  salt_cat[salt_len + 1] = 0x00;
  salt_cat[salt_len + 2] = 0x00;
  salt_cat[salt_len + 3] = 0x01;
  salt_cat_len = salt_len + 4;

  for (uint32_t iter = 0; iter < iterations; iter++) {
    if (iter == 0) {
      hmac_sha512(password, password_len, salt_cat, salt_cat_len, U_current);
    } else {
      hmac_sha512(password, password_len, U_current, sizeof(U_current), U_current);
    }

    for (size_t b = 0; b < HMAC_SHA512_OUTPUT_SIZE; b++) {
      U_xor[b] ^= U_current[b];
    }
  }

  memcpy(derived_key, U_xor, BIP32_SEED_LEN);

  secure_zero(U_current, sizeof(U_current));
  secure_zero(U_xor, sizeof(U_xor));
  secure_zero(salt_cat, sizeof(salt_cat));
}

// ─── BIP32 xpub helpers ───────────────────────────────────────────────────────

static const char XPUB_B58_ALPHA[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// base58check-encode exactly 78 raw BIP32 xpub bytes into out (≥120 chars).
static bool xpub_base58check(const uint8_t raw[78], char out[XPUB_STR_LEN]) {
    // Append 4-byte double-SHA256 checksum.
    uint8_t h1[32], h2[32];
    sha256(raw, 78, h1);
    sha256(h1, 32, h2);

    uint8_t buf[82];
    memcpy(buf, raw, 78);
    memcpy(buf + 78, h2, 4);

    // Base58 encode: process each byte, accumulate base-58 digits LE.
    uint8_t digits[120];
    memset(digits, 0, sizeof(digits));
    int dlen = 0;

    for (int i = 0; i < 82; i++) {
        int carry = (int)buf[i];
        for (int j = 0; j < dlen; j++) {
            carry += (int)digits[j] * 256;
            digits[j] = (uint8_t)(carry % 58);
            carry /= 58;
        }
        while (carry > 0) {
            if (dlen >= (int)sizeof(digits)) return false;
            digits[dlen++] = (uint8_t)(carry % 58);
            carry /= 58;
        }
    }

    // Leading zero bytes → leading '1' chars (xpub version 0x0488B21E has none).
    int zeros = 0;
    while (zeros < 82 && buf[zeros] == 0) zeros++;

    int p = 0;
    for (int i = 0; i < zeros; i++) out[p++] = '1';
    for (int i = dlen - 1; i >= 0; i--) out[p++] = XPUB_B58_ALPHA[digits[i]];
    out[p] = '\0';
    return p > 0;
}

// HASH160 = RIPEMD160(SHA256(data))
static void hash160(const uint8_t *data, size_t len, uint8_t out20[20]) {
    uint8_t sha_out[32];
    sha256(data, len, sha_out);
    ripemd160(sha_out, 32, out20);
}

// Derive the m/84'/0'/0' account xpub from master private key + chain code.
// Serialises as a standard 78-byte BIP32 xpub and base58check-encodes it.
// Returns false on any crypto failure.
static bool derive_account_xpub(const uint8_t master_key[BIP32_KEY_LEN],
                                 const uint8_t master_chain[BIP32_CHAIN_LEN],
                                 char xpub_out[XPUB_STR_LEN]) {
    uint8_t k0[BIP32_KEY_LEN], c0[BIP32_CHAIN_LEN]; // m/84'
    uint8_t k1[BIP32_KEY_LEN], c1[BIP32_CHAIN_LEN]; // m/84'/0'
    uint8_t k2[BIP32_KEY_LEN], c2[BIP32_CHAIN_LEN]; // m/84'/0'/0'

    // Three hardened steps.
    if (!hd_ckd_priv(master_key, master_chain, 84  | HD_HARDENED, k0, c0)) return false;
    if (!hd_ckd_priv(k0,         c0,           0   | HD_HARDENED, k1, c1)) return false;
    if (!hd_ckd_priv(k1,         c1,           0   | HD_HARDENED, k2, c2)) return false;

    // Public key at account level (depth 3).
    uint8_t pub_acc[BIP32_PUBKEY_LEN];
    if (!hd_pubkey_from_priv(k2, pub_acc)) return false;

    // Parent fingerprint = HASH160(pubkey at depth 2 = m/84'/0')[0:4].
    uint8_t pub_parent[BIP32_PUBKEY_LEN];
    if (!hd_pubkey_from_priv(k1, pub_parent)) return false;
    uint8_t h160[20];
    hash160(pub_parent, BIP32_PUBKEY_LEN, h160);

    // Zero sensitive intermediate keys.
    secure_zero(k0, sizeof(k0));  secure_zero(c0, sizeof(c0));
    secure_zero(k1, sizeof(k1));  secure_zero(c1, sizeof(c1));
    secure_zero(k2, sizeof(k2));
    // c2 stays — it IS the account chain code going into the xpub.

    // Serialise 78-byte xpub:
    //  [0:4]   version  0x0488B21E  (mainnet xpub)
    //  [4]     depth    3
    //  [5:9]   parent fingerprint
    //  [9:13]  child index  0x80000000 (0' hardened)
    //  [13:45] chain code
    //  [45:78] compressed public key
    uint8_t raw[78];
    raw[0] = 0x04; raw[1] = 0x88; raw[2] = 0xB2; raw[3] = 0x1E; // xpub
    raw[4] = 3;                                                    // depth
    raw[5] = h160[0]; raw[6] = h160[1]; raw[7] = h160[2]; raw[8] = h160[3];
    raw[9]  = 0x80; raw[10] = 0x00; raw[11] = 0x00; raw[12] = 0x00; // 0'
    memcpy(raw + 13, c2, 32);      // account chain code
    memcpy(raw + 45, pub_acc, 33); // account compressed pubkey

    secure_zero(c2, sizeof(c2));

    return xpub_base58check(raw, xpub_out);
}

// ─── NVS-backed xpub storage ─────────────────────────────────────────────────

bool wallet_store_account_xpub(const char *xpub_str) {
    if (!xpub_str || xpub_str[0] == '\0') return false;
#if defined(ARDUINO) && defined(ESP32)
    s_wlt_prefs.begin(NVS_WLT_NAMESPACE, false);
    bool ok = s_wlt_prefs.putString(NVS_WLT_XPUB_KEY, xpub_str);
    s_wlt_prefs.end();
    return ok;
#else
    (void)xpub_str;
    return true; // stub for host tests
#endif
}

bool wallet_get_account_xpub(char xpub_out[XPUB_STR_LEN]) {
    if (!xpub_out) return false;
#if defined(ARDUINO) && defined(ESP32)
    s_wlt_prefs.begin(NVS_WLT_NAMESPACE, true);
    String s = s_wlt_prefs.getString(NVS_WLT_XPUB_KEY, "");
    s_wlt_prefs.end();
    if (s.length() == 0) return false;
    strncpy(xpub_out, s.c_str(), XPUB_STR_LEN - 1);
    xpub_out[XPUB_STR_LEN - 1] = '\0';
    return true;
#else
    xpub_out[0] = '\0';
    return false;
#endif
}

// ─────────────────────────────────────────────────────────────────────────────

bool wallet_generate_seed(const char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN],
                          const char *passphrase) {
  char   mnemonic_str[BIP39_MNEMONIC_WORDS * (BIP39_WORD_MAX_LEN)];
  size_t mnemonic_len = 0;
  uint8_t seed[BIP32_SEED_LEN];
  uint8_t bip32_i[HMAC_SHA512_OUTPUT_SIZE];
  uint8_t master_key[BIP32_MASTER_KEY_LEN];
  uint8_t chain_code[BIP32_CHAIN_CODE_LEN];

  memset(mnemonic_str, 0, sizeof(mnemonic_str));
  for (int i = 0; i < BIP39_MNEMONIC_WORDS; i++) {
    size_t wlen = strlen(mnemonic[i]);
    if (wlen == 0) return false;
    memcpy(mnemonic_str + mnemonic_len, mnemonic[i], wlen);
    mnemonic_len += wlen;
    if (i < BIP39_MNEMONIC_WORDS - 1) {
      mnemonic_str[mnemonic_len++] = ' ';
    }
  }

  size_t passphrase_len = passphrase ? strlen(passphrase) : 0;
  uint8_t salt[256];
  size_t salt_len = sizeof(BIP39_SALT_PREFIX) - 1 + passphrase_len;
  if (salt_len > sizeof(salt)) return false;
  memcpy(salt, BIP39_SALT_PREFIX, sizeof(BIP39_SALT_PREFIX) - 1);
  if (passphrase_len > 0) {
    memcpy(salt + sizeof(BIP39_SALT_PREFIX) - 1, passphrase, passphrase_len);
  }

  pbkdf2_hmac_sha512((const uint8_t *)mnemonic_str, mnemonic_len,
                     salt, salt_len,
                     PBKDF2_ITERATIONS, seed);

  secure_zero(mnemonic_str, sizeof(mnemonic_str));
  secure_zero(salt, sizeof(salt));

  hmac_sha512((const uint8_t *)BIP32_KEY_PREFIX, sizeof(BIP32_KEY_PREFIX) - 1,
              seed, BIP32_SEED_LEN, bip32_i);

  secure_zero(seed, sizeof(seed));

  memcpy(master_key, bip32_i, BIP32_MASTER_KEY_LEN);
  memcpy(chain_code, bip32_i + BIP32_MASTER_KEY_LEN, BIP32_CHAIN_CODE_LEN);
  secure_zero(bip32_i, sizeof(bip32_i));

  se051_err_t err = se051_store_key(SE051_KEY_BIP32_MASTER, master_key, BIP32_MASTER_KEY_LEN);
  if (err != SE_OK) {
    secure_zero(master_key, sizeof(master_key));
    secure_zero(chain_code, sizeof(chain_code));
    return false;
  }

  err = se051_store_key(SE051_KEY_CHAIN_CODE, chain_code, BIP32_CHAIN_CODE_LEN);
  if (err != SE_OK) {
    se051_delete_key(SE051_KEY_BIP32_MASTER);
    secure_zero(master_key, sizeof(master_key));
    secure_zero(chain_code, sizeof(chain_code));
    return false;
  }

  // Derive and store the account xpub (m/84'/0'/0') while both master_key
  // and chain_code are still in RAM.  This is the only window where hardened
  // derivation is possible (private key required).  The result is persisted to
  // NVS so it can be retrieved later for the GET_XPUB USB handshake.
  char xpub_str[XPUB_STR_LEN];
  bool xpub_ok = derive_account_xpub(master_key, chain_code, xpub_str);

  secure_zero(master_key, sizeof(master_key));
  secure_zero(chain_code, sizeof(chain_code));

  if (xpub_ok) {
    wallet_store_account_xpub(xpub_str);
    secure_zero(xpub_str, sizeof(xpub_str));
  }

  uint8_t pubkey[SE051_PUBKEY_COMPRESSED];
  if (se051_get_pubkey(SE051_KEY_BIP32_MASTER, pubkey) != SE_OK) {
    se051_delete_key(SE051_KEY_BIP32_MASTER);
    se051_delete_key(SE051_KEY_CHAIN_CODE);
    return false;
  }

  return true;
}

bool wallet_is_initialized(void) {
  uint8_t pubkey[SE051_PUBKEY_COMPRESSED];
  if (se051_get_pubkey(SE051_KEY_BIP32_MASTER, pubkey) != SE_OK) return false;
  if (se051_get_pubkey(SE051_KEY_CHAIN_CODE, pubkey) != SE_OK) return false;
  return true;
}

bool wallet_has_passphrase(void) {
  uint8_t flag[1] = {0};
  size_t out_len = 0;
  if (se051_read_object(SE051_OBJ_HAS_PASSPHRASE, flag, 1, &out_len) != SE_OK) {
    return false;
  }
  return (out_len == 1 && flag[0] == 1);
}

bool wallet_set_passphrase_flag(bool has) {
  uint8_t flag = has ? 1 : 0;
  return se051_store_key(SE051_OBJ_HAS_PASSPHRASE, &flag, 1) == SE_OK;
}

//
// Anti-phishing device pairing code — threat model:
//
// This generates a 4-word BIP39-encoded device identity on first setup.
// The code is exported once over USB as PAIRING:<4words>\n so the companion
// app can store it. On every subsequent boot, the same 4 words are displayed
// on the OLED for 3 seconds after PIN entry. The user must visually confirm
// the words match what the companion app shows.
//
// What this protects against:
//   - Cloned device with different SE serial (anti-phish words differ)
//   - Fake companion app that hasn't seen the device's pairing code
//
// Limitations (documented threat model):
//   - A sophisticated attacker who modifies the firmware can display a fake
//     code that matches their own companion app. This raises the bar but is
//     not a cryptographic guarantee — it relies on the user's visual attention.
//   - The companion app must store and verify the pairing code on every
//     connection. If the app is compromised, the anti-phish check is bypassed.
//   - Secure boot (US-023) is the primary defense against firmware modification.
//
// The anti-phish code is stored in SE object 0x04 and can only be reset via
// a full factory reset (wallet_factory_reset()). It persists across wallet
// restores since it identifies the device, not the wallet.
//
bool wallet_generate_anti_phish(void) {
  uint8_t rnd[8] = {0};

  se051_err_t err = se051_get_random(rnd, sizeof(rnd));
  if (err != SE_OK) return false;

  uint16_t indices[4];
  for (int i = 0; i < 4; i++) {
    indices[i] = ((uint16_t)rnd[i * 2] << 8) | rnd[i * 2 + 1];
    indices[i] = indices[i] % BIP39_WORDLIST_SIZE;
  }

  secure_zero(rnd, sizeof(rnd));

  err = se051_store_key(SE051_OBJ_ANTI_PHISH,
                        (const uint8_t *)indices,
                        sizeof(indices));
  secure_zero(indices, sizeof(indices));

  return err == SE_OK;
}

bool wallet_has_anti_phish(void) {
  uint8_t dummy[8];
  size_t out_len = 0;
  return se051_read_object(SE051_OBJ_ANTI_PHISH, dummy, sizeof(dummy),
                           &out_len) == SE_OK && out_len == 8;
}

bool wallet_get_anti_phish(char words[4][BIP39_WORD_MAX_LEN]) {
  if (!words) return false;

  uint8_t buf[8] = {0};
  size_t out_len = 0;

  se051_err_t err = se051_read_object(SE051_OBJ_ANTI_PHISH, buf, sizeof(buf),
                                      &out_len);
  if (err != SE_OK || out_len != 8) return false;

  for (int i = 0; i < 4; i++) {
    uint16_t idx = ((uint16_t)buf[i * 2] << 8) | buf[i * 2 + 1];
    idx = idx % BIP39_WORDLIST_SIZE;
    strncpy(words[i], bip39_wordlist[idx], BIP39_WORD_MAX_LEN - 1);
    words[i][BIP39_WORD_MAX_LEN - 1] = '\0';
  }

  secure_zero(buf, sizeof(buf));
  return true;
}
