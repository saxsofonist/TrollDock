TrollDock's patched zsign: 1.1.3-trolldock.2

This is a locally built modification, not the official upstream executable.
Upstream: https://github.com/zhlynn/zsign
Pinned upstream commit: 9299685bab7ef99827e06e5dfda93af747386590 (v1.1.3)
Official source archive:
https://codeload.github.com/zhlynn/zsign/zip/9299685bab7ef99827e06e5dfda93af747386590
Source archive SHA-256:
7b61b2f2a29113d2fdf970599dca5ec4709d1b524cdd571c9a1f7cb3d28c3b73

The patch preserves the profile's explicit application-identifier and Keychain
groups verbatim. These signed entitlement identities are independent of the
app/extension's CFBundleIdentifier and CodeDirectory identifier, which remain
unchanged. A trailing wildcard uses the original bundle ID when the resulting
identity is within the profile's pattern; otherwise it appends that bundle ID
after the pattern's fixed prefix. Keychain wildcards prefer the resolved app
identity when permitted, otherwise the same fixed-prefix expansion is used.
Malformed patterns fail. XML and DER use the same resolved entitlement dictionary.
Each .app/.appex receives the original CMS profile before resource sealing.
Library/framework entitlement handling remains upstream. Version .2 removes the
incorrect bundle-ID equality restriction introduced in .1; it retains Unicode
and long-path handling, nested profile embedding and code signature checks.

Rebuilding (Windows x64):
1. Install Git for Windows, Python 3, and Visual Studio Desktop development with
   C++. The release was built with VS 2026, MSVC 14.50.35717 (v145), Windows SDK
   10.0.26100.0. The archive vendors the required Windows OpenSSL static libraries.
2. Keep build-zsign.ps1, build-zsign.py and zsign-per-bundle-entitlements.patch
   together, then run:
     powershell -ExecutionPolicy Bypass -File .\build-zsign.ps1
   Optional: -Python <python.exe> -SourceArchive <already-downloaded-source.zip>
   Toolset/compiler/SDK parameters allow other installed versions; binary hashes
   may differ with another compiler/toolchain.
3. The recipe checks the archive and patch hashes, applies the patch to a fresh
   source directory, builds with /Brepro and OPENSSL_NO_FILENAMES (to omit local
   source paths from OpenSSL error strings), checks --version, and writes zsign.exe
   plus build-provenance.json under .build-zsign/output. All intermediate source
   files remain under the selected build directory. No global packages are added.

Licenses: zsign MIT (Copyright 2026 zhlynn), OpenSSL 3.4.0 Apache-2.0,
zlib 1.3.1 zlib license, and minizip 1.1 zlib license. Distributions must retain the
upstream notices supplied alongside TrollDock. The local changes are MIT-licensed.
The archive includes prebuilt OpenSSL libraries; this recipe does not rebuild them.

Tests use synthetic local certificates and Mach-O bundles, never a real device.
They verify CMS, CodeDirectory page hashes, XML/DER identifiers, nested resource
seals and embedded profile bytes. Certificate trust and provisioning eligibility
remain subject to validation by iOS during real installation.

The Windows application manifest opts into long paths and UTF-8 ANSI APIs on
supported Windows versions. Directory creation uses recursive CreateDirectoryW
with extended Unicode paths instead of the shell's MAX_PATH-limited helper.
This permits deep and non-ASCII job/certificate paths without changing the user's
system code page or editing the source IPA. Remaining Win32 APIs use the system's
long-path support; Windows long paths must be enabled for paths beyond MAX_PATH.
