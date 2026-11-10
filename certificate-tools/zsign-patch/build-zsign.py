"""Build the TrollDock zsign patch from a hash-pinned official source archive.

Requires Python 3, Git for Windows and Visual Studio C++ build tools. No global
packages are installed. The upstream archive contains its Windows OpenSSL static
libraries and the zlib/minizip sources; their licenses must accompany distribution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import urllib.request
import uuid
import zipfile

UPSTREAM_COMMIT = "9299685bab7ef99827e06e5dfda93af747386590"
SOURCE_URL = f"https://codeload.github.com/zhlynn/zsign/zip/{UPSTREAM_COMMIT}"
SOURCE_SHA256 = "7b61b2f2a29113d2fdf970599dca5ec4709d1b524cdd571c9a1f7cb3d28c3b73"
PATCH_SHA256 = "361b8a9c496bf8fb03b927e3ab45fd9679d46618e215af2a2ef5ecd45844972f"
VERSION = "1.1.3-trolldock.1"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-directory", type=Path, default=Path(__file__).parent / ".build-zsign")
    parser.add_argument("--source-archive", type=Path)
    parser.add_argument("--msbuild", type=Path)
    parser.add_argument("--toolset", default="v145")
    parser.add_argument("--vc-tools-version", default="14.50.35717")
    parser.add_argument("--windows-sdk", default="10.0.26100.0")
    args = parser.parse_args()
    if os.name != "nt":
        raise SystemExit("This recipe builds the Windows x64 release with Microsoft C++.")
    root = args.work_directory.resolve()
    root.mkdir(parents=True, exist_ok=True)
    patch = Path(__file__).with_name("zsign-per-bundle-entitlements.patch")
    if digest(patch) != PATCH_SHA256:
        raise SystemExit("Patch SHA-256 mismatch; obtain the matching source recipe and patch.")
    archive = args.source_archive.resolve() if args.source_archive else root / "upstream.zip"
    if not archive.exists():
        context = ssl.create_default_context()
        try:
            import certifi
            context = ssl.create_default_context(cafile=certifi.where())
        except ImportError:
            pass
        request = urllib.request.Request(SOURCE_URL, headers={"User-Agent": "TrollDock-zsign-build"})
        with urllib.request.urlopen(request, context=context, timeout=120) as response:
            archive.write_bytes(response.read())
    if digest(archive) != SOURCE_SHA256:
        raise SystemExit("Official source archive SHA-256 mismatch.")
    extraction = root / ("source-" + uuid.uuid4().hex)
    extraction.mkdir()
    with zipfile.ZipFile(archive) as package:
        for entry in package.infolist():
            if not (extraction / entry.filename).resolve().is_relative_to(extraction):
                raise SystemExit("Unexpected source archive path.")
        package.extractall(extraction)
    source = extraction / ("zsign-" + UPSTREAM_COMMIT)
    git = shutil.which("git")
    if not git:
        raise SystemExit("Git for Windows is required to apply the checked source patch.")
    subprocess.run([git, "apply", "--check", str(patch.resolve())], cwd=source, check=True)
    subprocess.run([git, "apply", "--whitespace=nowarn", str(patch.resolve())], cwd=source, check=True)
    msbuild = args.msbuild
    if msbuild is None:
        vswhere = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "Microsoft Visual Studio/Installer/vswhere.exe"
        if not vswhere.exists():
            raise SystemExit("Visual Studio Installer/vswhere.exe is missing; pass --msbuild.")
        installation = subprocess.check_output([str(vswhere), "-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"], text=True).strip()
        msbuild = Path(installation) / "MSBuild/Current/Bin/MSBuild.exe"
    if not msbuild.is_file():
        raise SystemExit("MSBuild.exe is unavailable; install the Desktop C++ workload.")
    compiler = msbuild.parents[3] / "VC/Tools/MSVC" / args.vc_tools_version / "bin/Hostx64/x64/cl.exe"
    compiler_version = "unavailable"
    if compiler.is_file():
        compiler_info = subprocess.run([str(compiler)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        match = re.search(rb"\b19\.\d+\.\d+\b", compiler_info.stdout)
        if match:
            compiler_version = match.group().decode("ascii")
    # Python canonicalizes Windows environment keys: avoid duplicate Path/PATH
    # entries emitted by some hosts, which break Framework MSBuild child tools.
    environment = dict(os.environ)
    environment.pop("CL", None)
    environment.pop("LINK", None)
    environment["_CL_"] = "/utf-8 /Brepro /DOPENSSL_NO_FILENAMES"
    environment["_LINK_"] = "/Brepro"
    command = [str(msbuild), str(source / "build/windows/vs2022/zsign.sln"),
               "/p:Configuration=Release", "/p:Platform=x64", f"/p:PlatformToolset={args.toolset}",
               f"/p:VCToolsVersion={args.vc_tools_version}", f"/p:WindowsTargetPlatformVersion={args.windows_sdk}",
               f"/p:ExtraDefines=ZSIGN_VERSION={VERSION}", "/p:ExtraResourceDefines=ZSIGN_VERSION_NUM=1%2C1%2C3%2C1",
               "/m", "/verbosity:minimal", "/nologo"]
    build_log = root / "build.log"
    with build_log.open("wb") as output:
        result = subprocess.run(command, env=environment, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        raise SystemExit(f"MSBuild failed ({result.returncode}); see {build_log}")
    built = source / "build/windows/vs2022/x64/Release/zsign.exe"
    output = root / "output"
    output.mkdir(exist_ok=True)
    executable = output / "zsign.exe"
    shutil.copyfile(built, executable)
    version = subprocess.check_output([str(executable), "-v"], text=True).strip()
    if VERSION not in version:
        raise SystemExit("Unexpected signer version after build.")
    metadata = {"version": VERSION, "upstreamCommit": UPSTREAM_COMMIT, "sourceUrl": SOURCE_URL,
                "sourceSha256": SOURCE_SHA256, "patchSha256": PATCH_SHA256, "executableSha256": digest(executable),
                "toolset": args.toolset, "vcToolsVersion": args.vc_tools_version, "windowsSdk": args.windows_sdk,
                "compilerVersion": compiler_version,
                "compilerFlags": environment["_CL_"], "linkerFlags": environment["_LINK_"],
                "staticDependencies": "OpenSSL 3.4.0 (upstream-vendored Windows libraries), zlib 1.3.1/minizip 1.1 (vendored source)"}
    (output / "build-provenance.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(version)
    print("Output:", executable)
    print("SHA-256:", metadata["executableSha256"])
    print("Source and intermediates retained in:", extraction)


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    main()
