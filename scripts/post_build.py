Import("env")
import hashlib

PLACEHOLDER = b"buildhash_plchld"


def after_build(source, target, env):
    bin_path = str(target[0])
    if not bin_path.endswith(".bin"):
        return

    with open(bin_path, "rb") as f:
        data = f.read()

    if PLACEHOLDER not in data:
        print(f"post_build.py: placeholder not found in {bin_path}, skipping")
        return

    sha_full = hashlib.sha256(data).hexdigest()
    sha_short = sha_full[:16]
    hash_bytes = sha_short.encode("ascii")

    data = data.replace(PLACEHOLDER, hash_bytes, 1)

    with open(bin_path, "wb") as f:
        f.write(data)

    print(f"post_build.py: injected build hash {sha_short} into {bin_path}")


env.AddPostAction("$BUILD_DIR/${PROGNAME}.bin", after_build)
