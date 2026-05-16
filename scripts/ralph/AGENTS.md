# Python Agent Logic (Lean Mode)

## 1. Python Environment
- VirtualEnv: `.venv/bin/activate`
- Type Checking: `mypy .`
- Testing: `pytest`

## 2. Iteration Rules
1. Read `prd.json` & `AGENTS.md`.
2. Check `git log -n 10`.
3. Execute ONE task from `prd.json` (Priority-based).
4. Update `progress.txt` (Human Audit) & `prd.json` (State).
5. If tests fail: Fix or document blocker in `AGENTS.md` and EXIT.

## 3. Discovered Patterns (The "Brain")
- Alembic migrations require `alembic.ini` configuration file with `script_location = db/migrations` and `prepend_path = .`
- When running Alembic from `orchestrator/`, the env.py must add the repo root (parent of orchestrator/) to sys.path for imports
- Use `sa.Enum("value1", "value2", ..., name="typename")` in migration files instead of `sa.Enum("typename", name="typename")` to avoid duplicate enum creation
- PostgreSQL JSONB type must be imported from `sqlalchemy.dialects.postgresql` (not `sqlalchemy`) - use `from sqlalchemy.dialects.postgresql import JSONB`
- Alembic async migrations require `greenlet` library - install with `pip install greenlet`
- Alembic async migrations with asyncpg require `psycopg2-binary` - install with `pip install psycopg2-binary`

## 4. ⚠️ CRITICAL: Updating prd.json Safely

**NEVER manually edit prd.json or use sed/awk!** This creates duplicate keys.

**ALWAYS use jq to update prd.json:**

```bash
# Mark a story as complete (US-015)
jq '(.userStories[] | select(.id == "US-015") | .passes) = true' prd.json > /tmp/prd.json && mv /tmp/prd.json prd.json

# Mark a story as incomplete
jq '(.userStories[] | select(.id == "US-015") | .passes) = false' prd.json > /tmp/prd.json && mv /tmp/prd.json prd.json

# Update notes for a story
jq '(.userStories[] | select(.id == "US-015") | .notes) = "Implementation complete"' prd.json > /tmp/prd.json && mv /tmp/prd.json prd.json
```

**Validation: Check for duplicate keys before committing:**

```bash
# Run validation script
./validate-prd.sh

# Or manual check (should return empty)
python3 -c "import json; d=json.load(open('prd.json')); print('Duplicates found!' if any('passes' in str(s) and str(s).count('\"passes\"') > 1 for s in d['userStories']) else '')"
```

**If you find duplicate keys, run:**
```bash
./fix-prd-duplicates.sh
```

## 5. Aider Review (Mandatory Post-Implementation Gate)
- Run `./scripts/ralph/aider_review.sh` **after** implementation, **before** updating prd.json.
- Apply *all* critical fixes Aider suggests.
- If Aider reports a reusable pattern (e.g., anti-pattern), add it here.
- If Aider finds a blocker you cannot fix: document in this file and EXIT (no commit).

## 6. Firmware / C++ Patterns (ESP32-S3 + Arduino)

### PRD Bootstrap Pattern
- When no `prd.json` exists, create one with the following structure before starting implementation:
  ```json
  {
    "userStories": [
      {
        "id": "US-001",
        "description": "Brief description of the story",
        "priority": 1,
        "passes": false,
        "notes": ""
      }
    ]
  }
  ```
- This ensures the agent has a clear task list to work from and can track progress properly.
- Use `jq` to update the file as described in Section 4.

### SEAL (Secure Element Abstraction Layer)
- Define HAL in a single header (`se051_hal.h`) with `extern "C"` guards.
- Two backends selected by build flag: `-DUSE_SE051` (real I2C) or `-DUSE_SE_STUB` (CI mock).
- All higher-level modules (BIP39, BIP32, PSBT signing) call only the HAL interface — never Wire directly.
- Stub returns deterministic but valid-looking data for CI; real impl uses 3-retry I2C with 50 ms back-off.
- Unit tests compile with `g++ -DUSE_SE_STUB` on host — no ESP32 toolchain needed for CI.
- Agents: `security-engineer`, `firmware-engineer`.

### I2C Retry Pattern
- Wrap all I2C reads/writes in a retry loop: 3 attempts, 50 ms delay between retries.
- Return `SE_ERR_COMM` only after exhausting all retries.
- This is mandatory for the SE051C2 which can NACK during busy states.

### APDU Framing (ISO 7816-4 over I2C)
- SE051C2 commands are APDUs with CLA, INS, P1, P2, Lc, data, Le.
- I2C write sends the APDU; I2C read receives response with status words.
- Status word 0x9000 = success; 0x6982/0x6983 = locked; 0x6985 = conditions not satisfied.
- Agents: `security-engineer`.

### Typed Error Codes
- Use `typedef enum { SE_OK, SE_ERR_COMM, SE_ERR_AUTH, SE_ERR_LOCKED, ... } se051_err_t;`
- All HAL functions return error codes, never void. Callers must check return values.
- Agents: `firmware-engineer`.

### APDU Command Mapping
- When implementing SE051 HAL functions, always verify the APDU instruction byte against the SE051 datasheet.
- Each operation must use a dedicated INS byte: `APDU_INS_DELETE_KEY (0xE0)` for deletion, `APDU_INS_PUT_DATA (0xDA)` for storage, `APDU_INS_GET_DATA (0xCA)` for reads, `APDU_INS_GET_RND (0x84)` for random, `APDU_INS_INTERNAL_AUTH (0x88)` for signing.
- Keep a comment next to each APDU constant referencing the datasheet section.

### Partial State Cleanup
- Multi-step SE storage operations must clean up on failure to prevent partial state.
- If storing key A succeeds but key B fails, delete key A before returning error.
- wallet_is_initialized() returns true only when ALL required objects exist in SE.

### Test Vectors
- Always verify cryptographic primitives against standard test vectors (FIPS 180-4 for SHA, RFC 4231 for HMAC, BIP32 spec for key derivation).
- Derive test vectors using a known-good implementation (Python's hashlib) before coding.

### Prefix-Based Word Selection on Sorted Wordlists
- When implementing UI to select a word from a large sorted list (e.g., BIP39 wordlist), use binary search (`bip39_find_prefix`) to find the first match and count.
- Keep a fixed-size prefix buffer (e.g., 4 chars) and guard against overflow: check `prefixLen >= maxLen` before writing.
- Two-phase input: (1) Letter entry — CONFIRM cycles letters A-Z, CANCEL locks and advances to next prefix position. (2) Word scroll — CANCEL scrolls filtered matches, CONFIRM selects.
- Auto-transition to word scroll when match count is manageable (1-30) and prefix is long enough (>= 3 chars).
- Show live match preview including the current tentative letter via a separate preview function.
- Zero-match guard: never enter word scroll mode with 0 matches; use `restoreMatchCount > 0` check. Also check for zero before modulo: `(pos + 1) % count` is UB when count==0.
- After word selection, reset prefix and start fresh for the next word position.
- Validate full mnemonic checksum after all 24 words; show "Bad checksum - retry" and reset to word 1 on failure.
- Sensitive buffers (mnemonic words, prefix) zeroed with volatile pointer pattern after use.

### Bitcoin Address Encoding Patterns
- **Hash160 pattern:** `sha256(data, sha)`, `ripemd160(sha, hash160)` — used by both P2PKH and P2WPKH address generation.
- **Tagged hash (BIP340/BIP86):** `sha256(tag_hash || tag_hash || msg)` where `tag_hash = sha256(tag)`. Used for Taproot tweak computation.
- **BIP86 Taproot tweak:** decompress pubkey → `t*G` (scalar multiply) → point_add(P, tG) → extract x-only coordinate. Exposed as `hd_ec_pubkey_tweak()` from bip32.
- **Bech32/32m difference:** Bech32 checksum XOR constant = 1, Bech32m (BIP350 for witness v1+) uses 0x2bc830a3. Same encode pipeline otherwise.
- **Fixed-size buffers for addresses:** Max Base58Check output ≈35 chars, max Bech32 ≈73 chars. Safe bound: 128 chars for MAX_ADDRESS_LEN.
- **Address type cycling UI:** Store type index (0=P2PKH, 1=P2WPKH, 2=P2TR), CANCEL advances type, CONFIRM returns to menu. Generate via `address_generate(type, index, str)` which selects the correct derivation path (44'/84'/86').
- Agents: `bitcoin-protocol-engineer`, `firmware-engineer`.

### PSBT Parsing (BIP174/BIP370)
- Use `typedef enum { PSBT_OK, PSBT_ERR_INVALID, PSBT_ERR_MAGIC, ... } psbt_err_t;` for typed error codes.
- Parse PSBT buffer as: magic bytes (5) → global map (until 0x00 separator) → input maps (each until 0x00) → output maps (each until 0x00).
- v0: extract input_count/output_count from global unsigned TX (legacy format, no segwit marker/flag). v2: classify maps by scanning for PSBT_IN_PREVIOUS_TXID (0x0E) — input-only key type.
- Key-value encoding: compact size varint for key_len + value_len. Key data = key_type (1 byte) + optional extra bytes. Separator = key_len varint of 0x00.
- **Critical:** `read_u64le/read_u32le` modify their `*pos` pointer argument. When using these inside a KV parser, save the original value position (`size_t val_end = val_start + val_len;`) before calls and use `*pos = val_end` after.
- PSBT_IN_SIGHASH_TYPE (0x03) and PSBT_OUT_AMOUNT (0x03) share key type — classification by key type alone is ambiguous in v2. Use PSBT_IN_PREVIOUS_TXID (0x0E) as the definitive input-only discriminator.
- Fingerprints stored as `uint8_t[4]` for portability, not `uint32_t`.
- Host-based testing: `g++ -DUSE_SE_STUB -I. psbt.cpp test_psbt.cpp` — self-contained PSBT builder functions in test file produce valid v0/v2 PSBTs. No ESP32 toolchain needed.
- Agents: `bitcoin-protocol-engineer`.
- Use ricmoo/QRCode library (MIT, self-contained) with `extern "C"` guards for cross-platform compatibility.
- Wrapper (`qr_renderer.cpp`) handles: uppercase bech32 for alphanumeric mode, version auto-selection from capacity tables, capacity pre-validation (library doesn't report overflow).
- Rendering in wallet1.ino: use `display.fillRect()` at integer scale (1-3px), centered via `(128 - size*scale)/2` offset.
- Navigation pattern: CONFIRM pushes QR_DISPLAY state, CANCEL pops back to text view — same as SIGN_TX.
- "Address too long" fallback when even version 4 (max 33x33 on 128x64) can't fit the address.
- Host-based testing: compile with `g++ -I. qrcode.c qr_renderer.cpp test_qr_renderer.cpp` — no Arduino dependencies needed.

### PSBT Signing (BIP143/BIP341)
- `sighash_bip143()`: hashPrevouts/hashSequence/hashOutputs as SHA256d, scriptCode for P2WPKH = 0x1976a914 + pubkey_hash(20) + 0x88ac. Construct sigMsg: version || hashPrevouts || hashSequence || outpoint || scriptCode || amount || nSequence || hashOutputs || locktime || sighash_type, then SHA256d.
- `sighash_bip341()`: uses single SHA256 for sha_prevouts/amounts/scriptpubkeys/sequences/outputs preimages. Construct sigMsg: hash_type(0x00) || version || locktime || sha_prevouts || sha_amounts || sha_scriptpubkeys || sha_sequences || sha_outputs || spend_type(0x00) || input_index. Then tagged_hash("TapSighash", sigMsg).
- ECDSA signing: SE returns DER-encoded signature; appended sighash byte (e.g., 0x01 for SIGHASH_ALL). Store in PSBT_IN_PARTIAL_SIG (0x02) with key=pubkey.
- Schnorr signing: SE returns raw 64-byte signature. Store in PSBT_IN_TAP_KEY_SIG (0x13).
- SE temp key pattern: derive child → store as PSBT_TEMP_KEY_ID (0xF0) → sign → delete temp → on ANY error, flush ALL signatures to prevent partial PSBT.
- PSBT v0 builder: unsigned TX KV wraps TX content INLINE (not pre-buffer reference): magic || varint(key_len=1) || key_type(0x00) || varint(tx_len) || unsigned_tx_bytes || separator(0x00) || input_maps || separator || output_maps || separator.
- Key derivation: read master key from SE (0x01) + chain code (0x02), walk path with hd_ckd_priv(). All-hardened paths avoid EC scalarmult bug. Non-hardened paths affected by known EC doubling parity issue for large scalars.
