"""Create the deterministic TrollDock signer release asset from verified build output.

Run after copying the tested signer to bin/zsign/zsign.exe and its matching
build recipe and build-provenance.json into zsign-patch/. Updates only zsign's
manifest entry. This script performs no downloads or publishing.
"""
import hashlib
import json
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parent


def sha256(data):
    return hashlib.sha256(data).hexdigest().upper()


def main():
    source = ROOT / "zsign-patch"
    provenance = json.loads((source / "build-provenance.json").read_text(encoding="utf-8-sig"))
    binary = (ROOT / "bin/zsign/zsign.exe").read_bytes()
    binary_hash = sha256(binary)
    if binary_hash.lower() != provenance["executableSha256"].lower():
        raise SystemExit("Binary does not match its build provenance.")
    patch = (source / "zsign-per-bundle-entitlements.patch").read_bytes()
    if sha256(patch).lower() != provenance["patchSha256"].lower():
        raise SystemExit("Patch does not match its build provenance.")
    members = {"zsign.exe": binary}
    for name in ["build-zsign.ps1", "build-zsign.py", "zsign-per-bundle-entitlements.patch", "README.txt", "build-provenance.json"]:
        members["source/" + name] = (source / name).read_bytes()
    for name in ["zsign-LICENSE.txt", "OpenSSL-3.4.0-LICENSE.txt", "zlib-1.3.1-LICENSE.txt", "minizip-1.1-LICENSE.txt"]:
        members["licenses/" + name] = (ROOT / "licenses" / name).read_bytes()
    # Optional files are explicitly enumerated: no build output, keys, fixtures or
    # arbitrary local files enter this release archive.
    for name in ["zsign.manifest"]:
        if (source / name).exists():
            members["source/" + name] = (source / name).read_bytes()
    archive_name = f"zsign-{provenance['version']}-win-x64.zip"
    archive_path = ROOT / "downloads" / archive_name
    archive_path.parent.mkdir(exist_ok=True)
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, contents in sorted(members.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 11, 10, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, contents, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    archive_hash = sha256(archive_path.read_bytes())
    manifest_path = ROOT / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    entry = next(tool for tool in manifest["tools"] if tool["name"] == "zsign")
    entry.update(version=provenance["version"],
                 distribution="TrollDock patched build; see zsign-patch/ for reproducible source recipe",
                 releaseUrl="https://github.com/saxsofonist/TrollDock/releases/tag/v1.1.0",
                 downloadUrl="https://github.com/saxsofonist/TrollDock/releases/download/v1.1.0/" + archive_name,
                 archiveName=archive_name, archiveSha256=archive_hash,
                 binarySha256=binary_hash, sourceArchiveUrl=provenance["sourceUrl"],
                 sourceArchiveSha256=provenance["sourceSha256"].upper(),
                 patchSha256=provenance["patchSha256"].upper(), sourceRecipe="zsign-patch/build-zsign.ps1")
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print("Archive:", archive_path)
    print("Archive SHA-256:", archive_hash)
    print("Executable SHA-256:", binary_hash)


if __name__ == "__main__":
    main()

