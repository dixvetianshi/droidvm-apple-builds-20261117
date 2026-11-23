"""Admit the pinned encrypted original seed/public-key input on this CI runner."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

CIPHER_SHA = "c509db65ff70fe5faff13f54eda51cf37b357d5d77841e91a93316dacc3ab14c"
MANIFEST_SHA = "4885d1632c601fe1cd77ab53218431bb3c6bdf169a7542b506113822337f705a"
MAX_PLAIN = 80 << 20


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--encrypted", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--openssl", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("The admitted input directory must be new")
    encoded = args.encrypted.read_bytes()
    if len(encoded) != 26856560 or hashlib.sha256(encoded).hexdigest() != CIPHER_SHA:
        raise ValueError("The supplied ciphertext differs from the selected release asset")
    if encoded[:8] != b"Salted__":
        raise ValueError("The ciphertext is not the selected OpenSSL format")
    result = subprocess.run([
        str(args.openssl), "enc", "-d", "-aes-256-cbc", "-saltlen", "8", "-pbkdf2", "-iter", "200000",
        "-pass", "env:ARTIFACT_KEY",
    ], input=encoded, capture_output=True, check=True)
    with gzip.GzipFile(fileobj=io.BytesIO(result.stdout)) as stream:
        plain = stream.read(MAX_PLAIN + 1)
        if len(plain) > MAX_PLAIN:
            raise ValueError("The selected input exceeds its bounded expansion")
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != 16 or len(set(names)) != 16 or not all(m.isreg() for m in members):
            raise ValueError("The selected input must contain sixteen unique regular files")
        manifest_member = next(m for m in members if m.name == "input-manifest.json")
        raw = archive.extractfile(manifest_member).read()
        if hashlib.sha256(raw).hexdigest() != MANIFEST_SHA:
            raise ValueError("The selected plaintext manifest digest differs")
        manifest = json.loads(raw)
        expected = manifest["members"]
        if set(names) != {*expected, "input-manifest.json"}:
            raise ValueError("The archive's files differ from the admitted manifest")
        admitted = []
        for member in members:
            if member.name == "input-manifest.json":
                body = raw
            else:
                facts = expected[member.name]
                if member.size != facts["bytes"] or not 0 <= member.size <= MAX_PLAIN:
                    raise ValueError("An admitted member's extent differs")
                body = archive.extractfile(member).read()
                if len(body) != member.size or hashlib.sha256(body).hexdigest() != facts["sha256"]:
                    raise ValueError("An admitted member's complete bytes differ")
            parts = member.name.split("/")
            if any(p in ("", ".", "..") for p in parts) or "\\" in member.name or ":" in member.name:
                raise ValueError("An admitted member is not a relative POSIX file path")
            admitted.append((parts, body))
        args.output.mkdir(parents=True, exist_ok=False)
        for parts, body in admitted:
            target = args.output.joinpath(*parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as output:
                output.write(body)
    print(json.dumps({"input_members_verified": 16, "input_manifest_sha256": MANIFEST_SHA,
                      "ciphertext_sha256": CIPHER_SHA, "private_keys_included": False}))


if __name__ == "__main__":
    main()
