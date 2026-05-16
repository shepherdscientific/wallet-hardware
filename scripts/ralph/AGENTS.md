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
