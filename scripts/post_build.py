Import("env")
import hashlib
import struct

PLACEHOLDER = b"buildhash_plchld"

# Magic word for esp_app_desc_t (ESP_APP_DESC_MAGIC_WORD)
APP_DESC_MAGIC = struct.pack("<I", 0xABCD5AA5)

# Offset of app_elf_sha256[32] within esp_app_desc_t:
#   uint32_t magic_word      4
#   uint32_t secure_version  4
#   uint32_t reserv1[2]      8
#   char version[32]        32
#   char project_name[32]   32
#   char time[16]           16
#   char date[16]           16
#   char idf_ver[32]        32
#   ─────────────────────────
#   total before sha256:   144  (0x90)
SHA256_FIELD_OFFSET = 144
SHA256_FIELD_LEN = 32


def _update_app_desc_sha256(data: bytearray) -> bytearray:
    """
    Find the esp_app_desc_t magic word, zero the app_elf_sha256 field,
    recompute SHA-256 over the entire (zeroed) image, and write it back.

    The ESP-IDF bootloader verifies: sha256(binary with sha256_field=0x00*32)
    == stored app_elf_sha256.  If we have patched any bytes in the binary we
    must redo this digest or the bootloader will loop-restart forever.
    """
    magic_pos = bytes(data).find(APP_DESC_MAGIC)
    if magic_pos < 0:
        print("post_build.py: WARNING — esp_app_desc_t magic not found; "
              "SHA-256 field not updated (may cause boot loop on production)")
        return data

    sha_field_start = magic_pos + SHA256_FIELD_OFFSET
    sha_field_end = sha_field_start + SHA256_FIELD_LEN

    if sha_field_end > len(data):
        print("post_build.py: WARNING — binary too short to contain "
              "app_elf_sha256 field; skipping SHA-256 update")
        return data

    # Zero the field so the digest is computed over canonical form
    data[sha_field_start:sha_field_end] = b"\x00" * SHA256_FIELD_LEN
    new_digest = hashlib.sha256(bytes(data)).digest()
    data[sha_field_start:sha_field_end] = new_digest

    return data


def after_build(source, target, env):
    bin_path = str(target[0])
    if not bin_path.endswith(".bin"):
        return

    with open(bin_path, "rb") as f:
        data = bytearray(f.read())

    if PLACEHOLDER not in bytes(data):
        print(f"post_build.py: placeholder not found in {bin_path}, skipping")
        return

    # Step 1 — inject build hash into the placeholder.
    # Hash is computed BEFORE the placeholder is replaced so the value
    # reflects the canonical source image (placeholder still present).
    sha_full = hashlib.sha256(bytes(data)).hexdigest()
    sha_short = sha_full[:16]
    hash_bytes = sha_short.encode("ascii")

    idx = bytes(data).index(PLACEHOLDER)
    data[idx : idx + len(PLACEHOLDER)] = hash_bytes

    # Step 2 — recompute esp_app_desc_t SHA-256 so the bootloader
    # accepts the patched image.  Without this the bootloader detects
    # a digest mismatch and calls esp_restart() in an infinite loop
    # (symptom: rst:0x3 RTC_SW_SYS_RST / Saved PC in bootloader IRAM).
    data = _update_app_desc_sha256(data)

    with open(bin_path, "wb") as f:
        f.write(bytes(data))

    print(f"post_build.py: injected build hash {sha_short}, "
          f"updated app_elf_sha256 at binary offset "
          f"0x{bytes(data).find(APP_DESC_MAGIC) + SHA256_FIELD_OFFSET:04X}")


env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", after_build)
