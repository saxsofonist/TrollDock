global using System;
global using System.Collections.Generic;
global using System.IO;
global using System.Linq;
using System.ComponentModel;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using TrollDock.Services;

var settingsFile = AppSettings.SettingsPath;
if (!Path.GetFullPath(settingsFile).StartsWith(Path.GetFullPath(AppContext.BaseDirectory), StringComparison.OrdinalIgnoreCase))
    throw new InvalidOperationException("Tests may only use their own settings directory.");
var previousSettings = File.Exists(settingsFile) ? File.ReadAllBytes(settingsFile) : null;
int checks = 0;
int unavailableChecks = 0;

void Check(bool condition, string description)
{
    if (!condition) throw new Exception(description);
    checks++;
    Console.WriteLine("PASS " + description);
}

void Reject(Action action, Func<Exception, bool> expected, string description)
{
    Exception? exception = null;
    try { action(); } catch (Exception error) { exception = error; }
    Check(exception is not null && expected(exception), description);
}

try
{
    if (File.Exists(settingsFile)) File.Delete(settingsFile);
    var settings = AppSettings.Load();
    Check(settings.Username == "root" && settings.ReadPassword() == "" && settings.HostKeys.Count == 0, "Missing settings use safe defaults");
    const string secret = "Unicode-SSH-!пароль-$(not-a-command)-🔑";
    var dpapiAvailable = true;
    try { settings.SetPassword(secret, true); }
    catch (Win32Exception error) when (error.NativeErrorCode == 2)
    {
        dpapiAvailable = false;
        unavailableChecks = 5;
        Console.WriteLine("UNVERIFIED 5 DPAPI checks: Windows sandbox profile cannot access its protection key (Win32 error 2). No credential store permissions requested.");
    }
    if (dpapiAvailable)
    {
        Check(settings.EncryptedPassword.Length > 0 && settings.EncryptedPassword != secret, "Password stored as ciphertext");
        Check(settings.ReadPassword() == secret, "Windows DPAPI round-trip preserves Unicode password");
    }
    settings.Username = "test-root";
    settings.LastSerial = "fixture-device";
    settings.Save();
    var stored = File.ReadAllText(settingsFile);
    Check(!stored.Contains(secret, StringComparison.Ordinal) && !stored.Contains("пароль", StringComparison.Ordinal), "Saved JSON never contains plaintext password");
    Check(!File.Exists(settingsFile + ".tmp"), "Atomic settings save leaves no temporary file");
    var loaded = AppSettings.Load();
    Check(loaded.Username == "test-root" && loaded.LastSerial == "fixture-device", "Settings reload preserves profile");
    if (dpapiAvailable)
    {
        Check(loaded.ReadPassword() == secret, "Settings reload preserves encrypted credential");
        var encrypted = Convert.FromBase64String(loaded.EncryptedPassword);
        encrypted[^1] ^= 0x40;
        loaded.EncryptedPassword = Convert.ToBase64String(encrypted);
        Reject(() => loaded.ReadPassword(), e => e is Win32Exception, "Tampered DPAPI ciphertext fails closed");
    }
    loaded.EncryptedPassword = "not-base64";
    Reject(() => loaded.ReadPassword(), e => e is FormatException, "Corrupt encoded password is rejected");
    settings.SetPassword(secret, false);
    settings.Save();
    Check(settings.EncryptedPassword == "" && AppSettings.Load().ReadPassword() == "", "Disabling remember removes persisted credential");
    if (dpapiAvailable)
    {
        settings.SetPassword("", true);
        Check(settings.ReadPassword() == "", "DPAPI supports an empty stored password");
    }

    var initialKey = Encoding.ASCII.GetBytes("abc");
    settings.VerifyHostKey("fixture-device", initialKey);
    const string knownFingerprint = "SHA256:ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0";
    Check(settings.HostKeys["fixture-device"] == knownFingerprint, "First SSH key records the expected SHA256 fingerprint");
    Check(AppSettings.Load().HostKeys["fixture-device"] == knownFingerprint, "Trusted SSH fingerprint persists across launches");
    stored = File.ReadAllText(settingsFile);
    settings.VerifyHostKey("fixture-device", initialKey);
    Check(File.ReadAllText(settingsFile) == stored, "Repeated matching SSH key leaves trust store unchanged");
    Reject(() => settings.VerifyHostKey("fixture-device", Encoding.ASCII.GetBytes("changed-key")), e => e is IOException, "Changed SSH host key is rejected");
    Check(settings.HostKeys["fixture-device"] == knownFingerprint && File.ReadAllText(settingsFile) == stored, "Rejected SSH key never replaces trusted fingerprint");
    settings.VerifyHostKey("second-fixture-device", Encoding.ASCII.GetBytes("different-device-key"));
    Check(settings.HostKeys.Count == 2 && settings.HostKeys["fixture-device"] == knownFingerprint, "Each device maintains independent SSH trust");

    File.WriteAllText(settingsFile, "{not valid JSON}");
    Reject(() => AppSettings.Load(), e => e is JsonException, "Corrupt settings are not silently overwritten with defaults");
    File.WriteAllText(settingsFile, "null");
    Reject(() => AppSettings.Load(), e => e is IOException, "Null settings document is rejected");

    Check(TrollStoreResults.IsInstalled(0) && TrollStoreResults.IsInstalled(182) && TrollStoreResults.IsInstalled(184), "TrollStore success and success-with-warning exit statuses accepted");
    Check(!TrollStoreResults.IsInstalled(171) && !TrollStoreResults.IsInstalled(180) && !TrollStoreResults.IsInstalled(183) && !TrollStoreResults.IsInstalled(-1), "TrollStore conflict, encrypted main binary and incomplete result remain failures");
    Reject(() => TrollStoreResults.SuccessMessage(171), e => e is ArgumentOutOfRangeException, "Failure status cannot produce a success message");
    Check(TrollStoreResults.FailureMessage(999).Contains("999", StringComparison.Ordinal), "Unknown TrollStore failure keeps original exit code");
}
finally
{
    if (previousSettings is null) { if (File.Exists(settingsFile)) File.Delete(settingsFile); }
    else File.WriteAllBytes(settingsFile, previousSettings);
}

var fixtures = Path.Combine(AppContext.BaseDirectory, "fixtures");
Directory.CreateDirectory(fixtures);
string MakeFile(string name, byte[] bytes)
{
    var path = Path.Combine(fixtures, name);
    File.WriteAllBytes(path, bytes);
    return path;
}
string MakeZip(string name, params string[] entries)
{
    var path = Path.Combine(fixtures, name);
    using var zip = new ZipArchive(File.Create(path), ZipArchiveMode.Create);
    foreach (var entry in entries)
    {
        using var writer = new StreamWriter(zip.CreateEntry(entry).Open());
        writer.Write("test fixture");
    }
    return path;
}
bool FileError(Exception error) => error is IOException or InvalidDataException;
var package = MakeZip("тест package.ipa", "Payload/Demo.app/Info.plist", "Payload/Demo.app/Demo");
PackageFileValidator.Validate(package, false);
Check(true, "IPA structure accepted with Unicode and spaces in its filename");
File.Delete(package);
Check(!File.Exists(package), "IPA inspection releases file handles");
Reject(() => PackageFileValidator.Validate(MakeZip("wrong-location.ipa", "Other/Payload/Demo.app/Info.plist"), false), FileError, "Misplaced application does not pass IPA validation");
Reject(() => PackageFileValidator.Validate(MakeZip("nested-info.ipa", "Payload/Demo.app/Sub/Info.plist"), false), FileError, "Nested component plist does not substitute for main application plist");
Reject(() => PackageFileValidator.Validate(MakeZip("traversal.ipa", "Payload/../Demo.app/Info.plist"), false), FileError, "Traversal-shaped entry does not pass main IPA structure check");
Reject(() => PackageFileValidator.Validate(MakeZip("empty-zip.ipa"), false), FileError, "Empty ZIP is rejected as IPA");
Reject(() => PackageFileValidator.Validate(MakeFile("text.ipa", Encoding.UTF8.GetBytes("not a zip archive")), false), FileError, "Renamed text file is rejected as IPA");
Reject(() => PackageFileValidator.Validate(MakeFile("empty.ipa", []), false), FileError, "Empty IPA file is rejected");
Reject(() => PackageFileValidator.Validate(MakeFile("empty.deb", []), true), FileError, "Empty DEB file is rejected");
Reject(() => PackageFileValidator.Validate(MakeFile("short.deb", Encoding.ASCII.GetBytes("!<arch>")), true), FileError, "Truncated DEB signature is rejected");
Reject(() => PackageFileValidator.Validate(MakeFile("wrong.deb", Encoding.ASCII.GetBytes("not a deb archive")), true), FileError, "Renamed text file is rejected as DEB");
PackageFileValidator.Validate(MakeFile("header.deb", Encoding.ASCII.GetBytes("!<arch>\n")), true);
Check(true, "DEB ar signature passes initial check before remote dpkg-deb validation");
Reject(() => PackageFileValidator.Validate(Path.Combine(fixtures, "missing.ipa"), false), FileError, "Missing selection fails without starting transfer");
Console.WriteLine($"{checks} checks passed; {unavailableChecks} DPAPI checks unverified in sandbox; no device contacted.");
