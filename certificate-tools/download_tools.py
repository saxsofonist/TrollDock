#!/usr/bin/env python3
"""Fetch the exact pinned Windows x64 signing tools recorded in manifest.json.

Python 3.10+; no mandatory third-party dependencies. If certifi is installed its
CA bundle is used. TLS certificate verification always remains enabled.
"""
import argparse
import hashlib
import io
import json
from pathlib import Path
import ssl
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent


def verify(data: bytes, expected: str, label: str) -> bytes:
    actual = hashlib.sha256(data).hexdigest()
    if actual.lower() != expected.lower():
        raise RuntimeError(f"SHA-256 mismatch for {label}: expected {expected}, received {actual}")
    return data


def https_context():
    try:
        import certifi
    except ImportError:
        return ssl.create_default_context()
    return ssl.create_default_context(cafile=certifi.where())


def download(url: str) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("Only verified HTTPS downloads are permitted")
    request = urllib.request.Request(url, headers={"User-Agent": "TrollDock-tool-download/1"})
    with urllib.request.urlopen(request, timeout=120, context=https_context()) as response:
        return response.read()


def write_verified(path: Path, data: bytes, expected: str):
    verify(data, expected, str(path))
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".download")
    try:
        temporary.write_bytes(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "bin", help="Executable destination directory")
    parser.add_argument("--verify-only", action="store_true", help="Verify existing executables and licenses without network access")
    options = parser.parse_args()
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8-sig"))
    for tool in manifest["tools"]:
        binary = options.output / tool["binaryPath"]
        license_path = ROOT / tool["licensePath"]
        if options.verify_only:
            verify(binary.read_bytes(), tool["binarySha256"], str(binary))
            verify(license_path.read_bytes(), tool["licenseSha256"], str(license_path))
        else:
            cache = ROOT / "downloads" / tool["archiveName"]
            if cache.exists():
                archive_bytes = verify(cache.read_bytes(), tool["archiveSha256"], str(cache))
            else:
                archive_bytes = verify(download(tool["downloadUrl"]), tool["archiveSha256"], tool["archiveName"])
                write_verified(cache, archive_bytes, tool["archiveSha256"])
            # Extract only the explicitly pinned member; no archive path is trusted.
            with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
                executable = archive.read(tool["archiveMember"])
            write_verified(binary, executable, tool["binarySha256"])
            if license_path.exists():
                verify(license_path.read_bytes(), tool["licenseSha256"], str(license_path))
            else:
                write_verified(license_path, download(tool["licenseUrl"]), tool["licenseSha256"])
        print(f"Verified {tool['name']} {tool['version']}: {binary}")
    print("Include manifest.json and licenses/ with the distributed tools/ directory.")


if __name__ == "__main__":
    main()
