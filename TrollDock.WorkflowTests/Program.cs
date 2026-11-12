using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using TrollDock.Services;

await WorkflowChecks.RunAsync();

internal static class WorkflowChecks
{
    private static int passed;
    private const string Udid = "00000001-0000000000000001";
    private static void Check(bool value, string name) { if (!value) throw new Exception(name); Console.WriteLine("PASS " + name); passed++; }
    private static void Reject(Action action, string name)
    {
        try { action(); }
        catch (Exception e) when (e is IOException or ArgumentException) { Check(true, name); return; }
        throw new Exception("Did not reject " + name);
    }
    public static async Task RunAsync()
    {
        var root = Path.Combine(AppContext.BaseDirectory, "test-data-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        try
        {
            using var material = Material();
            var original = Path.Combine(root, "original.ipa");
            MakeIpa(original, false);
            var originalHash = SHA256.HashData(File.ReadAllBytes(original));
            var scenarios = new[] { "success", "sign-error", "install-error", "cancel-sign", "cancel-before-install", "verify-missing", "verify-error", "changed-bundle" };
            foreach (var scenario in scenarios)
            {
                using var cancellation = new CancellationTokenSource();
                var fake = new FakeTools(scenario, cancellation);
                var progress = new CaptureProgress();
                var logs = new List<string>();
                var staging = Path.Combine(root, scenario);
                var workflow = new CertificateInstallWorkflow(fake, staging);
                Exception? failure = null;
                try { await workflow.InstallAsync(original, material, Udid, progress, logs.Add, cancellation.Token); }
                catch (Exception error) { failure = error; }
                var expectsFailure = scenario is "sign-error" or "install-error" or "cancel-sign" or "cancel-before-install" or "changed-bundle";
                Check((failure is not null) == expectsFailure, scenario + " correct outcome");
                if (scenario.StartsWith("cancel")) Check(failure is OperationCanceledException, scenario + " preserves cancellation");
                Check(!Directory.Exists(staging) || Directory.GetFileSystemEntries(staging).Length == 0, scenario + " removes complete job including input, signed IPA, P12 and nested caches");
                Check(originalHash.AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(original))), scenario + " leaves original IPA unchanged");
                if (scenario is "verify-missing" or "verify-error")
                    Check(progress.Values.Last().Detail.Contains("Проверьте") && progress.Values.Last().Stage == "Установлено", scenario + " verification uncertainty remains visible");
                if (scenario is "sign-error" or "cancel-sign" or "cancel-before-install" or "changed-bundle") Check(!fake.InstallCalled, scenario + " prevents install");
                if (scenario == "success")
                {
                    Check(fake.InstallCalled && fake.VerifyCalled, "success installs and verifies");
                    Check(progress.Values.Any(p => p.Stage == "Установка по USB" && !p.CanCancel), "installation phase is not interruptible");
                    Check(fake.InputWasCopy && fake.PrivateMaterialPresent, "signer gets only private job copy and temporary signing material");
                    Check(!fake.CustomEntitlementsPresent, "normal Team ID profile uses bundled per-bundle entitlements");
                }
            }
            using (var legacyMaterial = Material(legacy: true))
            using (var cancellation = new CancellationTokenSource())
            {
                var fake = new FakeTools("legacy", cancellation);
                var staging = Path.Combine(root, "legacy");
                await new CertificateInstallWorkflow(fake, staging).InstallAsync(original, legacyMaterial, Udid, new CaptureProgress(), _ => { }, cancellation.Token);
                Check(fake.InstallCalled && !fake.CustomEntitlementsPresent, "legacy App ID profile uses bundled per-bundle entitlements");
                Check(Directory.GetFileSystemEntries(staging).Length == 0, "legacy profile job is fully deleted");
                var nestedIpa = Path.Combine(root, "legacy-nested.ipa"); MakeIpa(nestedIpa, false, extension: true);
                var blocked = new FakeTools("legacy-nested", cancellation);
                var blockedStaging = Path.Combine(root, "legacy-nested");
                await new CertificateInstallWorkflow(blocked, blockedStaging).InstallAsync(nestedIpa, legacyMaterial, Udid, new CaptureProgress(), _ => { }, cancellation.Token);
                Check(blocked.SignCalled && blocked.InstallCalled && Directory.GetFileSystemEntries(blockedStaging).Length == 0, "legacy nested bundles are signed, installed and cleaned");
            }
            using (var explicitMaterial = Material(legacy: true, applicationSuffix: "com.profile.registered"))
            {
                foreach (var nested in new[] { false, true })
                {
                    var bundle = nested ? "org.other.SecondApp" : "com.unrelated.first";
                    var scenario = nested ? "explicit-nested" : "explicit-main";
                    var source = Path.Combine(root, scenario + ".ipa");
                    MakeIpa(source, false, extension: nested, bundle: bundle);
                    var sourceHash = SHA256.HashData(File.ReadAllBytes(source));
                    var metadata = IpaInspection.Read(source);
                    using var cancellation = new CancellationTokenSource();
                    var fake = new FakeTools(scenario, cancellation);
                    var staging = Path.Combine(root, scenario);
                    await new CertificateInstallWorkflow(fake, staging).InstallAsync(source, explicitMaterial, Udid, new CaptureProgress(), _ => { }, cancellation.Token);
                    Check(fake.SignCalled && fake.InstallCalled, scenario + " allows an unrelated IPA Bundle ID with an explicit profile");
                    Check(fake.SignedInputMetadata?.BundleIdentifier == bundle && fake.InstalledMetadata?.BundleIdentifier == bundle
                        && fake.InstalledMetadata.ExtensionIdentifiers.SequenceEqual(metadata.ExtensionIdentifiers), scenario + " preserves main and nested IPA bundle identifiers");
                    Check(fake.VerifiedBundle == bundle, scenario + " checks installation using original Bundle ID");
                    Check(fake.ProfileHash!.AsSpan().SequenceEqual(SHA256.HashData(explicitMaterial.ProfileBytes)), scenario + " passes the original signed profile unchanged");
                    Check(sourceHash.AsSpan().SequenceEqual(SHA256.HashData(File.ReadAllBytes(source))), scenario + " keeps source IPA byte-for-byte unchanged");
                    Check(Directory.GetFileSystemEntries(staging).Length == 0, scenario + " deletes all temporary signing files");
                }
            }
            using (var cancellation = new CancellationTokenSource())
            {
                var blocked = new FakeTools("cleanup-blocked", cancellation);
                var blockedStaging = Path.Combine(root, "cleanup-blocked");
                var progress = new CaptureProgress();
                try
                {
                    Exception? failure = null;
                    try { await new CertificateInstallWorkflow(blocked, blockedStaging).InstallAsync(original, material, Udid, progress, _ => { }, cancellation.Token); }
                    catch (IOException e) { failure = e; }
                    Check(failure?.Message.Contains("не дал удалить") == true && !progress.Values.Any(v => v.Stage == "Установлено"), "locked output reports cleanup failure instead of unconditional success");
                    Check(failure is InstallationCompletedException, "cleanup failure after confirmed install preserves completed status for batch retry");
                    Check(Directory.GetFiles(blockedStaging, ".trolldock-signing-job", SearchOption.AllDirectories).Length == 1, "failed cleanup preserves ownership marker for next startup");
                }
                finally { blocked.BlockingHandle?.Dispose(); }
                Check(SigningWorkspace.CleanupAbandoned(blockedStaging).Count == 0 && Directory.GetDirectories(blockedStaging).Length == 0, "next startup removes leftovers after file lock is released");
            }
            TestWorkspace(root);
            TestInspection(root);
            TestSettings();
            Console.WriteLine($"Passed {passed} workflow checks.");
        }
        finally
        {
            var full = Path.GetFullPath(root);
            if (!full.StartsWith(Path.GetFullPath(AppContext.BaseDirectory), StringComparison.OrdinalIgnoreCase)
                || !Path.GetFileName(full).StartsWith("test-data-")) throw new Exception("Unexpected cleanup path");
            Directory.Delete(full, true);
        }
    }
    private static void TestWorkspace(string root)
    {
        var staging = Path.Combine(root, "cleanup");
        using (var active = new SigningWorkspace(staging))
        {
            File.WriteAllText(active.FilePath("signed.ipa"), "active");
            var abandoned = Path.Combine(staging, "job-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(abandoned);
            File.WriteAllText(Path.Combine(abandoned, ".trolldock-signing-job"), "TrollDock signing workspace v1");
            File.WriteAllText(Path.Combine(abandoned, "signed.ipa"), "orphan");
            var unrelated = Path.Combine(staging, "job-not-a-guid");
            Directory.CreateDirectory(unrelated);
            File.WriteAllText(Path.Combine(unrelated, ".trolldock-signing-job"), "marker");
            var unowned = Path.Combine(staging, "job-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(unowned);
            File.WriteAllText(Path.Combine(unowned, "keep.txt"), "unowned");
            var errors = SigningWorkspace.CleanupAbandoned(staging);
            Check(errors.Count == 0 && !Directory.Exists(abandoned), "startup removes only abandoned owned jobs");
            Check(File.Exists(active.FilePath("signed.ipa")), "startup preserves active job lease");
            Check(Directory.Exists(unrelated) && File.Exists(Path.Combine(unowned, "keep.txt")), "startup preserves unrelated and markerless directories");
            Reject(() => active.FilePath("../outside"), "job path rejects parent traversal");
            Reject(() => active.FilePath(Path.Combine(root, "absolute.ipa")), "job path rejects absolute path");
            Reject(() => active.FilePath("child\\file.ipa"), "job path rejects nested path");
        }
        var outside = Path.Combine(root, "outside");
        Directory.CreateDirectory(outside);
        var protectedFile = Path.Combine(outside, "keep.txt");
        File.WriteAllText(protectedFile, "must remain");
        var links = new SigningWorkspace(staging);
        try
        {
            Directory.CreateSymbolicLink(Path.Combine(links.DirectoryPath, "outside-link"), outside);
            File.CreateSymbolicLink(Path.Combine(links.DirectoryPath, "outside-file"), protectedFile);
            links.Dispose();
            Check(File.ReadAllText(protectedFile) == "must remain", "cleanup deletes links without following outside paths");
            var rootLink = Path.Combine(root, "root-link");
            Directory.CreateSymbolicLink(rootLink, outside);
            Reject(() => new SigningWorkspace(rootLink), "workspace rejects redirected staging root");
            Directory.Delete(rootLink);
        }
        catch (UnauthorizedAccessException) { Console.WriteLine("SKIP symlink checks: Windows symlink privilege unavailable"); links.Dispose(); }
        catch (IOException e) when (e.HResult == unchecked((int)0x80070522)) { Console.WriteLine("SKIP symlink checks: Windows symlink privilege unavailable"); links.Dispose(); }
        using (var junctionJob = new SigningWorkspace(staging))
        {
            CreateJunction(Path.Combine(junctionJob.DirectoryPath, "outside-junction"), outside);
            junctionJob.Dispose();
            Check(File.ReadAllText(protectedFile) == "must remain", "cleanup unlinks directory junction without deleting outside contents");
        }
        var junctionRoot = Path.Combine(root, "junction-root");
        CreateJunction(junctionRoot, outside);
        Reject(() => new SigningWorkspace(junctionRoot), "workspace rejects junction staging root");
        Reject(() => SigningWorkspace.CleanupAbandoned(junctionRoot), "startup cleanup rejects junction staging root");
        Directory.Delete(junctionRoot);
    }
    private static void CreateJunction(string link, string target)
    {
        // Both paths are generated below this test's own GUID directory, not user input.
        var info = new ProcessStartInfo("cmd.exe") { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        info.ArgumentList.Add("/d"); info.ArgumentList.Add("/c"); info.ArgumentList.Add("mklink"); info.ArgumentList.Add("/J"); info.ArgumentList.Add(link); info.ArgumentList.Add(target);
        using var process = Process.Start(info) ?? throw new Exception("Could not create test junction");
        process.WaitForExit();
        if (process.ExitCode != 0) throw new Exception("Could not create test junction: " + process.StandardError.ReadToEnd());
    }
    private static void TestInspection(string root)
    {
        var binary = Path.Combine(root, "binary.ipa"); MakeIpa(binary, true);
        var b = IpaInspection.Read(binary);
        Check(b.BundleIdentifier == "com.example.app" && b.Version == "12" && b.Name == "Тест", "binary plist parses identifier, version and UTF-16 name");
        var xml = Path.Combine(root, "xml.ipa"); MakeIpa(xml, false, extension: true);
        var x = IpaInspection.Read(xml);
        Check(x.BundleIdentifier == "com.example.app" && x.ExtensionIdentifiers.SequenceEqual(["com.example.app.extension"]), "XML plist and extension metadata");
        var watch = Path.Combine(root, "watch.ipa"); MakeIpa(watch, false);
        using (var archive = ZipFile.Open(watch, ZipArchiveMode.Update))
        {
            using (var stream = archive.CreateEntry("Payload/Demo.app/Watch/Watch.app/Info.plist").Open()) stream.Write(XmlPlist(new() { ["CFBundleIdentifier"] = "com.example.app.watch" }));
            using (var stream = archive.CreateEntry("Payload/Demo.app/Watch/Watch.app/PlugIns/Widget.appex/Info.plist").Open()) stream.Write(XmlPlist(new() { ["CFBundleIdentifier"] = "com.example.app.watch.widget" }));
            using (var stream = archive.CreateEntry("Payload/Demo.app/AppClips/Clip.app/Info.plist").Open()) stream.Write(XmlPlist(new() { ["CFBundleIdentifier"] = "com.example.app.clip" }));
        }
        Check(IpaInspection.Read(watch).ExtensionIdentifiers.SequenceEqual(["com.example.app.watch", "com.example.app.watch.widget", "com.example.app.clip"]), "nested watch extensions and App Clips are identified for preservation checks");
        foreach (var unsafePath in new[]
        {
            "../outside", "/absolute", "C:/absolute", "Payload\\bad", "Payload/./bad",
            "Payload/Demo.app/.. /outside", "Payload/Demo.app/trailing.", "Payload/Demo.app/trailing ",
            "Payload/Demo.app/a\u0000b", "Payload/Demo.app/a\u0001b", "Payload/Demo.app/a?b", "Payload/Demo.app/a*b",
            "Payload/Demo.app/CON.txt", "Payload/Demo.app/NUL", "Payload/Demo.app/COM1", "Payload/Demo.app/COM¹.txt",
            "Payload/Demo.app/LPT9.txt", "Payload/Demo.app/INFO.PLIST", "payload/Demo.app/other.txt",
            "Payload/Demo.app/Info.plist/child", "Payload//Demo.app/empty-segment"
        })
        {
            var path = Path.Combine(root, "bad-" + Guid.NewGuid().ToString("N") + ".ipa"); MakeIpa(path, false, extra: unsafePath);
            Reject(() => IpaInspection.Read(path), "IPA rejects unsafe archive path " + JsonSerializer.Serialize(unsafePath));
        }
        var reversedConflict = Path.Combine(root, "reverse-conflict.ipa");
        MakeIpa(reversedConflict, false, extra: "Payload/Demo.app/cache/a");
        using (var archive = ZipFile.Open(reversedConflict, ZipArchiveMode.Update))
        using (var stream = archive.CreateEntry("Payload/Demo.app/cache").Open()) stream.Write("conflict"u8);
        Reject(() => IpaInspection.Read(reversedConflict), "IPA rejects file replacing an implicit directory");
        var symlink = Path.Combine(root, "zip-link.ipa"); MakeIpa(symlink, false, extra: "Payload/Demo.app/link", link: true);
        Reject(() => IpaInspection.Read(symlink), "IPA rejects ZIP symbolic link");
        var broken = Path.Combine(root, "broken-binary.ipa");
        using (var archive = ZipFile.Open(broken, ZipArchiveMode.Create))
        using (var stream = archive.CreateEntry("Payload/Demo.app/Info.plist").Open()) stream.Write("bplist00bad"u8);
        Reject(() => IpaInspection.Read(broken), "IPA rejects truncated binary plist");
    }
    private static void TestSettings()
    {
        var settings = new AppSettings { StartupMode = "unknown", ModeOrder = ["certificate", "deb", "certificate", "bad"] };
        settings.NormalizeModes();
        Check(settings.ModeOrder.SequenceEqual(["certificate", "deb", "trollstore"]) && settings.StartupMode == "certificate", "mode normalization removes duplicates and unknown values, appends missing tabs");
        settings.StartupMode = "deb";
        settings.Save();
        try
        {
            var loaded = AppSettings.Load();
            Check(loaded.ModeOrder.SequenceEqual(settings.ModeOrder) && loaded.StartupMode == "deb", "tab ordering and startup tab persist across load");
            File.WriteAllText(AppSettings.SettingsPath, "{\"ModeOrder\":null,\"StartupMode\":null,\"HostKeys\":null}");
            var repaired = AppSettings.Load();
            Check(repaired.ModeOrder.SequenceEqual(["trollstore", "deb", "certificate"]) && repaired.StartupMode == "trollstore" && repaired.HostKeys is not null, "legacy/null settings normalize safely");
        }
        finally { File.Delete(AppSettings.SettingsPath); }
    }
    private static SigningMaterial Material(bool legacy = false, string applicationSuffix = "com.example.*")
    {
        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest("CN=TrollDock Workflow Test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
        var bcCert = new X509CertificateParser().ReadCertificate(certificate.RawData);
        var doc = new XDocument(new XElement("plist", new XElement("dict",
            new XElement("key", "Name"), new XElement("string", "Workflow Test"),
            new XElement("key", "ExpirationDate"), new XElement("date", DateTime.UtcNow.AddDays(5).ToString("O")),
            new XElement("key", "TeamIdentifier"), new XElement("array", new XElement("string", "TEAM123456")),
            new XElement("key", "ApplicationIdentifierPrefix"), new XElement("array", new XElement("string", legacy ? "LEGACY1234" : "TEAM123456")),
            new XElement("key", "Entitlements"), new XElement("dict", new XElement("key", "application-identifier"), new XElement("string", (legacy ? "LEGACY1234" : "TEAM123456") + "." + applicationSuffix)),
            new XElement("key", "DeveloperCertificates"), new XElement("array", new XElement("data", Convert.ToBase64String(certificate.RawData))),
            new XElement("key", "ProvisionedDevices"), new XElement("array", new XElement("string", Udid)))));
        var generator = new CmsSignedDataGenerator();
        generator.AddSigner(PrivateKeyFactory.CreateKey(rsa.ExportPkcs8PrivateKey()), bcCert, CmsSignedGenerator.DigestSha256);
        generator.AddCertificates(CollectionUtilities.CreateStore(new[] { bcCert }));
        var profile = generator.Generate(new CmsProcessableByteArray(Encoding.UTF8.GetBytes(doc.ToString())), true).GetEncoded();
        var p12 = certificate.Export(X509ContentType.Pkcs12, "test");
        try { return SigningMaterial.Load(p12, profile, "test"); }
        finally { CryptographicOperations.ZeroMemory(p12); }
    }
    internal static void MakeIpa(string path, bool binary, bool extension = false, string? extra = null, bool link = false, string bundle = "com.example.app")
    {
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        var values = new Dictionary<string, string> { ["CFBundleIdentifier"] = bundle, ["CFBundleVersion"] = "12", ["CFBundleDisplayName"] = "Тест" };
        using (var stream = archive.CreateEntry("Payload/Demo.app/Info.plist").Open()) stream.Write(binary ? BinaryPlist(values) : XmlPlist(values));
        if (extension)
            using (var stream = archive.CreateEntry("Payload/Demo.app/PlugIns/Widget.appex/Info.plist").Open()) stream.Write(XmlPlist(new() { ["CFBundleIdentifier"] = "com.example.app.extension" }));
        if (extra is not null)
        {
            var entry = archive.CreateEntry(extra);
            if (link) entry.ExternalAttributes = unchecked((int)0xA1FF0000);
            using var stream = entry.Open(); stream.Write("data"u8);
        }
    }
    private static byte[] XmlPlist(Dictionary<string, string> values) => Encoding.UTF8.GetBytes(new XDocument(new XElement("plist", new XElement("dict", values.SelectMany(p => new[] { new XElement("key", p.Key), new XElement("string", p.Value) })))).ToString());
    private static byte[] BinaryPlist(Dictionary<string, string> values)
    {
        using var buffer = new MemoryStream(); buffer.Write("bplist00"u8);
        var offsets = new List<int>();
        foreach (var value in values.Keys.Concat(values.Values))
        {
            offsets.Add((int)buffer.Position);
            var unicode = value.Any(c => c > 127); var encoded = unicode ? Encoding.BigEndianUnicode.GetBytes(value) : Encoding.ASCII.GetBytes(value);
            buffer.WriteByte((byte)((unicode ? 0x60 : 0x50) | Math.Min(value.Length, 15)));
            if (value.Length >= 15) { buffer.WriteByte(0x10); buffer.WriteByte((byte)value.Length); }
            buffer.Write(encoded);
        }
        offsets.Add((int)buffer.Position); buffer.WriteByte((byte)(0xD0 | values.Count));
        for (var i = 0; i < values.Count * 2; i++) buffer.WriteByte((byte)i);
        var offsetTable = buffer.Position;
        foreach (var offset in offsets) { buffer.WriteByte((byte)(offset >> 8)); buffer.WriteByte((byte)offset); }
        var trailer = new byte[32]; trailer[6] = 2; trailer[7] = 1;
        BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(8), (ulong)offsets.Count);
        BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(16), (ulong)(offsets.Count - 1));
        BinaryPrimitives.WriteUInt64BigEndian(trailer.AsSpan(24), (ulong)offsetTable);
        buffer.Write(trailer); return buffer.ToArray();
    }
    private sealed class CaptureProgress : IProgress<TransferProgress>
    {
        public List<TransferProgress> Values { get; } = [];
        public void Report(TransferProgress value) => Values.Add(value);
    }
    private sealed class FakeTools(string scenario, CancellationTokenSource cancellation) : ICertificateInstallTools
    {
        public bool SignCalled, InstallCalled, VerifyCalled, InputWasCopy, PrivateMaterialPresent, CustomEntitlementsPresent, EntitlementsWereExact;
        public IpaMetadata? SignedInputMetadata, InstalledMetadata;
        public string? VerifiedBundle;
        public byte[]? ProfileHash;
        public FileStream? BlockingHandle;
        public Task VerifyToolsAsync(CancellationToken token) { token.ThrowIfCancellationRequested(); return Task.CompletedTask; }
        public Task SignAsync(string input, string p12, string profile, string output, string job, Action<string> log, CancellationToken token, string? entitlementsPath = null)
        {
            SignCalled = true;
            SignedInputMetadata = IpaInspection.Read(input);
            ProfileHash = SHA256.HashData(File.ReadAllBytes(profile));
            CustomEntitlementsPresent = entitlementsPath is not null && File.Exists(entitlementsPath);
            if (CustomEntitlementsPresent)
            {
                var elements = XDocument.Load(entitlementsPath!).Root!.Element("dict")!.Elements().ToArray();
                var values = Enumerable.Range(0, elements.Length / 2).ToDictionary(i => elements[i * 2].Value, i => elements[i * 2 + 1]);
                EntitlementsWereExact = values["application-identifier"].Value == "LEGACY1234.com.example.app";
            }
            InputWasCopy = Path.GetFileName(input) == "input.ipa" && Path.GetDirectoryName(input) == job;
            PrivateMaterialPresent = File.Exists(p12) && File.Exists(profile);
            Directory.CreateDirectory(Path.Combine(job, "signer-cache", "nested"));
            File.WriteAllText(Path.Combine(job, "signer-cache", "nested", "temporary.txt"), "temporary");
            if (scenario == "changed-bundle") MakeIpa(output, false, bundle: "com.example.changed");
            else File.Copy(input, output);
            if (scenario == "sign-error") throw new IOException("synthetic signer failure");
            if (scenario is "cancel-sign" or "cancel-before-install") cancellation.Cancel();
            if (scenario == "cancel-sign") token.ThrowIfCancellationRequested();
            return Task.CompletedTask;
        }
        public Task InstallAsync(string ipa, string udid, Action<string> log)
        {
            InstallCalled = true;
            if (!File.Exists(ipa)) throw new Exception("No signed IPA during installation");
            InstalledMetadata = IpaInspection.Read(ipa);
            if (scenario == "install-error") throw new IOException("synthetic installer failure");
            if (scenario == "cleanup-blocked") BlockingHandle = new FileStream(ipa, FileMode.Open, FileAccess.Read, FileShare.None);
            return Task.CompletedTask;
        }
        public Task<bool> VerifyInstalledAsync(string bundle, string udid)
        {
            VerifyCalled = true;
            VerifiedBundle = bundle;
            if (scenario == "verify-error") throw new IOException("synthetic verification failure");
            return Task.FromResult(scenario != "verify-missing");
        }
    }
}

namespace TrollDock.Services
{
    // UI progress DTO only; all behavior under test is linked from production source above.
    public sealed record TransferProgress(string Stage, string Detail, double Percent, bool CanCancel);
}
