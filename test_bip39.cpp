#ifdef USE_SE_STUB

#include "bip39.h"
#include "se051_hal.h"
#include "sha256.h"
#include <cstdio>
#include <cstring>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
  tests_run++; \
  printf("  TEST: %s ... ", name); \
} while(0)

#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while(0)

static bool word_in_wordlist(const char *word) {
  for (int i = 0; i < BIP39_WORDLIST_SIZE; i++) {
    if (strcmp(word, bip39_wordlist[i]) == 0) return true;
  }
  return false;
}

int main(void) {
  printf("=== BIP39 Mnemonic Generation Unit Tests ===\n\n");

  se051_init();

  TEST("bip39_generate returns true");
  {
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    memset(mnemonic, 0, sizeof(mnemonic));
    if (bip39_generate(mnemonic)) PASS();
    else FAIL("generate returned false");
  }

  TEST("bip39_generate produces 24 non-empty words");
  {
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    memset(mnemonic, 0, sizeof(mnemonic));
    bip39_generate(mnemonic);
    int all_non_empty = 1;
    for (int i = 0; i < BIP39_MNEMONIC_WORDS; i++) {
      if (mnemonic[i][0] == '\0') { all_non_empty = 0; break; }
    }
    if (all_non_empty) PASS();
    else FAIL("one or more words are empty");
  }

  TEST("bip39_generate words are all ≤ 8 characters");
  {
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    bip39_generate(mnemonic);
    int all_valid_len = 1;
    for (int i = 0; i < BIP39_MNEMONIC_WORDS; i++) {
      if (strlen(mnemonic[i]) > 8) { all_valid_len = 0; break; }
    }
    if (all_valid_len) PASS();
    else FAIL("one or more words exceed 8 characters");
  }

  TEST("bip39_generate all words in BIP39 wordlist");
  {
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    bip39_generate(mnemonic);
    int all_in_list = 1;
    for (int i = 0; i < BIP39_MNEMONIC_WORDS; i++) {
      if (!word_in_wordlist(mnemonic[i])) {
        printf("\n    word '%s' not found in wordlist", mnemonic[i]);
        all_in_list = 0;
        break;
      }
    }
    if (all_in_list) PASS();
    else FAIL("word not in wordlist");
  }

  TEST("bip39_generate produces varied mnemonics across 10 calls");
  {
    char first[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    memset(first, 0, sizeof(first));
    bip39_generate(first);
    int any_different = 0;
    for (int call = 1; call < 10; call++) {
      char curr[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
      memset(curr, 0, sizeof(curr));
      bip39_generate(curr);
      if (memcmp(first, curr, sizeof(first)) != 0) {
        any_different = 1;
        break;
      }
    }
    if (any_different) PASS();
    else FAIL("all 10 calls produced identical mnemonics");
  }

  TEST("bip39_validate passes on a generated mnemonic");
  {
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    bip39_generate(mnemonic);
    if (bip39_validate(mnemonic)) PASS();
    else FAIL("validate rejected a freshly generated mnemonic");
  }

  TEST("bip39_validate rejects a corrupted mnemonic");
  {
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    bip39_generate(mnemonic);
    strcpy(mnemonic[0], "abandon");
    bool result = bip39_validate(mnemonic);
    if (!result) PASS();
    else FAIL("validate accepted a corrupted mnemonic");
  }

  TEST("bip39_word_to_index returns correct index for known word");
  {
    if (bip39_word_to_index("abandon") == 0) PASS();
    else FAIL("abandon should be index 0");
  }

  TEST("bip39_word_to_index returns 0xFFFF for unknown word");
  {
    if (bip39_word_to_index("zzzzzzzz") == 0xFFFF) PASS();
    else FAIL("unknown word should return 0xFFFF");
  }

  TEST("bip39_validate rejects mnemonic with invalid word");
  {
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    memset(mnemonic, 0, sizeof(mnemonic));
    for (int i = 0; i < BIP39_MNEMONIC_WORDS; i++) {
      strcpy(mnemonic[i], "abandon");
    }
    mnemonic[0][0] = 'z';
    mnemonic[0][1] = 'z';
    mnemonic[0][2] = 'z';
    mnemonic[0][3] = 'z';
    mnemonic[0][4] = '\0';
    if (!bip39_validate(mnemonic)) PASS();
    else FAIL("validate accepted mnemonic with invalid word");
  }

  TEST("bip39_generate preserves null termination");
  {
    char mnemonic[BIP39_MNEMONIC_WORDS][BIP39_WORD_MAX_LEN];
    memset(mnemonic, 0xAA, sizeof(mnemonic));
    bip39_generate(mnemonic);
    int all_terminated = 1;
    for (int i = 0; i < BIP39_MNEMONIC_WORDS; i++) {
      if (mnemonic[i][BIP39_WORD_MAX_LEN - 1] != '\0') {
        all_terminated = 0;
        break;
      }
    }
    if (all_terminated) PASS();
    else FAIL("one or more words not null terminated");
  }

  TEST("sha256 produces correct hash for empty string");
  {
    const char *expected = "\xe3\xb0\xc4\x42\x98\xfc\x1c\x14"
                           "\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24"
                           "\x27\xae\x41\xe4\x64\x9b\x93\x4c"
                           "\xa4\x95\x99\x1b\x78\x52\xb8\x55";
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256(NULL, 0, hash);
    if (memcmp(hash, expected, SHA256_DIGEST_LENGTH) == 0) PASS();
    else FAIL("empty string hash mismatch");
  }

  TEST("sha256 produces correct hash for 'abc'");
  {
    const char *expected = "\xba\x78\x16\xbf\x8f\x01\xcf\xea"
                           "\x41\x41\x40\xde\x5d\xae\x22\x23"
                           "\xb0\x03\x61\xa3\x96\x17\x7a\x9c"
                           "\xb4\x10\xff\x61\xf2\x00\x15\xad";
    uint8_t hash[SHA256_DIGEST_LENGTH];
    sha256((const uint8_t *)"abc", 3, hash);
    if (memcmp(hash, expected, SHA256_DIGEST_LENGTH) == 0) PASS();
    else FAIL("'abc' hash mismatch");
  }

  TEST("BIP39 wordlist has exactly 2048 entries");
  {
    if (BIP39_WORDLIST_SIZE == 2048) PASS();
    else FAIL("BIP39_WORDLIST_SIZE is not 2048");
  }

  TEST("bip39_find_prefix 'a' returns >0 matches at index 0");
  {
    uint16_t first = 0xFFFF;
    uint16_t count = bip39_find_prefix("a", &first);
    if (count > 0 && first == 0 && strcmp(bip39_wordlist[first], "abandon") == 0)
      PASS();
    else
      FAIL("prefix 'a' should match multiple words starting at abandon");
    printf(" (%u matches)", count);
  }

  TEST("bip39_find_prefix 'z' returns >0 matches");
  {
    uint16_t first = 0xFFFF;
    uint16_t count = bip39_find_prefix("z", &first);
    if (count > 0 && first < BIP39_WORDLIST_SIZE)
      PASS();
    else
      FAIL("prefix 'z' should match some words");
    printf(" (%u matches)", count);
  }

  TEST("bip39_find_prefix 'zzz' returns 0 matches");
  {
    uint16_t first = 0xFFFF;
    uint16_t count = bip39_find_prefix("zzz", &first);
    if (count == 0) PASS();
    else FAIL("prefix 'zzz' should match no words");
  }

  TEST("bip39_find_prefix 'aba' matches 'abandon'");
  {
    uint16_t first = 0xFFFF;
    uint16_t count = bip39_find_prefix("aba", &first);
    if (count > 0 && strcmp(bip39_wordlist[first], "abandon") == 0)
      PASS();
    else
      FAIL("prefix 'aba' should match 'abandon'");
    printf(" (%u matches)", count);
  }

  TEST("bip39_find_prefix 'ab' returns all words starting with 'ab'");
  {
    uint16_t first1 = 0xFFFF, first2 = 0xFFFF;
    uint16_t count1 = bip39_find_prefix("ab", &first1);
    uint16_t count2 = bip39_find_prefix("abandon", &first2);
    if (count1 > count2 && first1 == first2)
      PASS();
    else
      FAIL("broader prefix should include narrower");
    printf(" (%u vs %u)", count1, count2);
  }

  TEST("bip39_find_prefix exact word match returns 1 match");
  {
    uint16_t first = 0xFFFF;
    uint16_t count = bip39_find_prefix("abandon", &first);
    if (count == 1 && strcmp(bip39_wordlist[first], "abandon") == 0)
      PASS();
    else
      FAIL("exact prefix should return 1 match");
    printf(" (%u matches)", count);
  }

  printf("\n=== Results: %d/%d passed, %d failed ===\n",
         tests_passed, tests_run, tests_failed);
  return tests_failed ? 1 : 0;
}

#else
#include <cstdio>
int main(void) {
  printf("ERROR: This test requires USE_SE_STUB to be defined.\n");
  return 1;
}
#endif
