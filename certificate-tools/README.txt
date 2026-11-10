TrollDock certificate tools and reproducible provenance
=====================================================

zsign 1.1.3-trolldock.1 is TrollDock's patched Windows x64 build, under MIT.
It is based on the official zhlynn/zsign v1.1.3 source at commit
9299685bab7ef99827e06e5dfda93af747386590.
https://github.com/zhlynn/zsign/releases/tag/v1.1.3

The patch resolves application-identifier and permitted wildcard Keychain groups
separately for each app and extension, preserving the profile's actual App ID
prefix (which can differ from its Team ID). XML and DER entitlements use the same
resolved dictionary. The original selected profile is embedded in each allowed
app/extension before its resource seal is generated. An unpermitted nested bundle
fails signing. See zsign-patch/ for the checked patch, complete build recipe,
compiler provenance and upstream source-archive digest.

Arguments: -f -k <temporary blank-password P12> -m <profile> -o <temporary IPA>
-t <private job directory> -z 1 <private input copy>. No password argument.
The source IPA selected by the user is never passed to zsign.

The executable statically links upstream-vendored OpenSSL 3.4.0 and compiled
zlib 1.3.1/minizip 1.1. Their licenses are included in licenses/.

go-ios 1.3.2 is the official danielpaulus/go-ios Windows build, under MIT.
https://github.com/danielpaulus/go-ios/releases/tag/v1.3.2

Arguments: --udid=<selected device> install --path=<temporary signed IPA>.
The pinned main.go dispatches installApp to zipconduit.New and SendFile.
The zipconduit installer reports a JSON INFO message "installation successful"
only after the device returns completion. TrollDock requires that marker,
exit code 0, and no JSON ERROR/FATAL message before reporting success.
A later apps --all lookup is supplementary and cannot substitute for the
acknowledgement. This certificate installation path uses Apple USB services.

Obtain pinned executables: python download_tools.py
Verify existing files without downloads: python download_tools.py --verify-only
The zsign archive is the TrollDock release asset; go-ios is the official upstream
release asset. manifest.json pins each archive, executable and project license.
The official go-ios archive hash was checked against the GitHub asset digest.
TrollDock also verifies executable hashes before every child process launch.

Process lifecycle: Windows CreateProcess atomically assigns the child to a
Job Object with KILL_ON_JOB_CLOSE. An explicit inherited-handle list is used.
Closing TrollDock or its Job Object terminates owned child processes and their
descendants. TEMP, TMP and TMPDIR are set to the private signing job directory.

Offline integration tests: run make-test-ipa.py, then dotnet run --project
../TrollDock.ToolTests/ToolTests.csproj. Tests generate synthetic identities and
non-runnable Mach-O fixtures. They verify CMS signatures, SHA-256 code pages,
XML/DER entitlements, main/nested resource seals, exact embedded profile bytes,
unchanged input and workflow cleanup with a simulated USB acknowledgement.
No synthetic test IPA is installed on a device. Successful cryptographic tests
do not substitute for Apple's certificate/profile validation on an actual device.

The test-fixture folder contains synthetic private keys and test IPAs generated
locally. It is development-only; exclude it from binary/source releases. Release
source includes only the generation code, with no user credentials or IPA data.

