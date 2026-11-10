using System.Diagnostics;
using System.Buffers.Binary;
using System.IO.Compression;
using System.Reflection;
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

Console.OutputEncoding = System.Text.Encoding.UTF8;
var self = Environment.ProcessPath!;
ProcessStartInfo StartInfo(params string[] arguments)
{
    var start = new ProcessStartInfo(self) { WorkingDirectory = AppContext.BaseDirectory, UseShellExecute = false, CreateNoWindow = true };
    foreach (var arg in arguments) start.ArgumentList.Add(arg);
    return start;
}
if (args.FirstOrDefault() == "sleep") { await Task.Delay(Timeout.Infinite); return; }
if (args.FirstOrDefault() == "echo")
{
    Console.WriteLine(JsonSerializer.Serialize(args.Skip(1).ToArray()));
    Console.Error.WriteLine("stderr works");
    Console.WriteLine("ENV=" + Environment.GetEnvironmentVariable("TROLLDOCK_TEST_VALUE"));
    return;
}
if (args.FirstOrDefault() == "tree")
{
    using var descendant = Process.Start(StartInfo("sleep"))!;
    Console.WriteLine(descendant.Id);
    await Task.Delay(Timeout.Infinite);
    return;
}
if (args.FirstOrDefault() == "job-owner")
{
    using var job = new CertificateToolRunner.ChildProcessJob();
    using var child = job.Start(StartInfo("tree"));
    Console.WriteLine(child.Process.Id + "," + await child.StandardOutput.ReadLineAsync());
    await Task.Delay(Timeout.Infinite);
    return;
}
if (args.FirstOrDefault() == "tool-output")
{
    foreach (var line in args.Skip(1)) Console.WriteLine(line);
    return;
}
var passed = 0;
void Check(bool value, string message) { if (!value) throw new Exception(message); passed++; Console.WriteLine("PASS " + message); }
async Task RejectAsync(Func<Task> action, string message)
{
    try { await action(); } catch (Exception e) when (e is IOException or OperationCanceledException or ArgumentException)
    { Check(true, message); return; }
    throw new Exception("Did not reject: " + message);
}
async Task WaitGone(int pid)
{
    try { using var process = Process.GetProcessById(pid); using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10)); await process.WaitForExitAsync(cts.Token); }
    catch (ArgumentException) { }
}
byte[] ZipBytes(ZipArchive archive, string path)
{
    using var stream = archive.GetEntry(path)!.Open();
    using var memory = new MemoryStream(); stream.CopyTo(memory); return memory.ToArray();
}
Dictionary<string, XElement> Dictionary(XElement dictionary)
{
    var nodes = dictionary.Elements().ToArray();
    return Enumerable.Range(0, nodes.Length / 2).ToDictionary(i => nodes[i * 2].Value, i => nodes[i * 2 + 1]);
}
List<string> DerStrings(byte[] data)
{
    var result = new List<string>();
    void Read(ReadOnlySpan<byte> value, int depth)
    {
        if (depth > 64) throw new InvalidDataException("DER nesting is excessive");
        for (var i = 0; i < value.Length;)
        {
            var tag = value[i++]; var length = (int)value[i++];
            if ((length & 0x80) != 0)
            {
                var bytes = length & 0x7f; if (bytes is 0 or > 4) throw new InvalidDataException("DER length");
                length = 0;
                for (int j = 0; j < bytes; j++) length = checked((length << 8) | value[i++]);
            }
            var content = value.Slice(i, length);
            if ((tag & 0x20) != 0) Read(content, depth + 1);
            else if (tag == 0x0c) result.Add(Encoding.UTF8.GetString(content));
            i += length;
        }
    }
    Read(data, 0); return result;
}
void VerifyBundle(ZipArchive archive, string bundlePath, string appIdentifier, byte[] profile, string[]? expectedKeychainGroups = null)
{
    expectedKeychainGroups ??= [appIdentifier];
    var expectedBundleId = bundlePath.EndsWith(".appex", StringComparison.Ordinal) ? "com.example.trolldock.test.extension" : "com.example.trolldock.test";
    using var infoStream = new MemoryStream(ZipBytes(archive, bundlePath + "/Info.plist"));
    Check(Dictionary(XDocument.Load(infoStream).Root!.Element("dict")!)["CFBundleIdentifier"].Value == expectedBundleId, bundlePath + " original CFBundleIdentifier retained");
    var executable = ZipBytes(archive, bundlePath + "/TestFixture");
    var codeResources = ZipBytes(archive, bundlePath + "/_CodeSignature/CodeResources");
    Check(ZipBytes(archive, bundlePath + "/embedded.mobileprovision").AsSpan().SequenceEqual(profile), bundlePath + " exact original provisioning profile");
    uint LE(int offset) => BinaryPrimitives.ReadUInt32LittleEndian(executable.AsSpan(offset, 4));
    int signatureOffset = 0;
    for (int i = 0, offset = 32; i < LE(16); i++)
    {
        if (LE(offset) == 0x1d) signatureOffset = checked((int)LE(offset + 8));
        offset += checked((int)LE(offset + 4));
    }
    uint BE(int offset) => BinaryPrimitives.ReadUInt32BigEndian(executable.AsSpan(signatureOffset + offset, 4));
    Check(signatureOffset > 0 && BE(0) == 0xfade0cc0, bundlePath + " signature superblob");
    var slots = new Dictionary<uint, byte[]>();
    for (int i = 0; i < BE(8); i++)
    {
        var slot = BE(12 + i * 8); var offset = checked((int)BE(16 + i * 8));
        slots.Add(slot, executable.AsSpan(signatureOffset + offset, checked((int)BE(offset + 4))).ToArray());
    }
    var directory = slots[0];
    var cms = new CmsSignedData(new CmsProcessableByteArray(directory), slots[0x10000].AsSpan(8).ToArray());
    var certificates = cms.GetCertificates();
    Check(cms.GetSignerInfos().GetSigners().Count > 0 && cms.GetSignerInfos().GetSigners().All(signer => certificates.EnumerateMatches(signer.SignerID).Any(signer.Verify)), bundlePath + " CMS signature verifies");
    uint CD(int offset) => BinaryPrimitives.ReadUInt32BigEndian(directory.AsSpan(offset, 4));
    var identifierOffset = checked((int)CD(20));
    var identifierLength = Array.IndexOf(directory, (byte)0, identifierOffset) - identifierOffset;
    Check(Encoding.UTF8.GetString(directory, identifierOffset, identifierLength) == expectedBundleId, bundlePath + " CodeDirectory identifier matches original bundle ID independently of entitlement identity");
    var hashOffset = checked((int)CD(16)); var codeSlots = CD(28); var codeLimit = checked((int)CD(32));
    var hashSize = directory[36]; var pageSize = 1 << directory[39];
    Check(directory[37] == 2 && hashSize == 32, bundlePath + " SHA-256 code directory");
    for (int i = 0; i < codeSlots; i++)
    {
        var page = executable.AsSpan(i * pageSize, Math.Min(pageSize, codeLimit - i * pageSize));
        Check(SHA256.HashData(page).AsSpan().SequenceEqual(directory.AsSpan(hashOffset + i * hashSize, hashSize)), bundlePath + " code page " + i);
    }
    foreach (var special in new[] { (1, ZipBytes(archive, bundlePath + "/Info.plist")), (3, codeResources), (5, slots[5]), (7, slots[7]) })
        Check(SHA256.HashData(special.Item2).AsSpan().SequenceEqual(directory.AsSpan(hashOffset - special.Item1 * hashSize, hashSize)), bundlePath + " special slot " + special.Item1);
    using var xml = new MemoryStream(slots[5].AsSpan(8).ToArray());
    var entitlements = Dictionary(XDocument.Load(xml).Root!.Element("dict")!);
    Check(entitlements["application-identifier"].Value == appIdentifier, bundlePath + " exact XML application identifier");
    Check(entitlements["com.apple.developer.team-identifier"].Value == "TEAM123456", bundlePath + " original Team ID retained independently of App ID prefix");
    Check(entitlements["keychain-access-groups"].Elements().Select(e => e.Value).SequenceEqual(expectedKeychainGroups), bundlePath + " exact resolved XML keychain groups");
    var der = DerStrings(slots[7].AsSpan(8).ToArray());
    var expectedIdentities = new[] { appIdentifier }.Concat(expectedKeychainGroups).GroupBy(s => s).ToArray();
    Check(der.Contains("application-identifier") && der.Contains("keychain-access-groups") && expectedIdentities.All(group => der.Count(s => s == group.Key) == group.Count()) && !der.Any(s => s.Contains('*')), bundlePath + " matching concrete DER entitlements");
    using var resourcesStream = new MemoryStream(codeResources);
    var resources = Dictionary(XDocument.Load(resourcesStream).Root!.Element("dict")!);
    foreach (var item in Dictionary(resources["files2"]))
    {
        var expected = Convert.FromBase64String(Dictionary(item.Value)["hash2"].Value);
        Check(SHA256.HashData(ZipBytes(archive, bundlePath + "/" + item.Key)).AsSpan().SequenceEqual(expected), bundlePath + " resource hash " + item.Key);
    }
}
var toolRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "../../../../certificate-tools/bin"));
var fixtureRoot = Path.GetFullPath(Path.Combine(toolRoot, "../test-fixture"));
// A synthetic CA chain is required by zsign's CMS builder; no Apple identity is used.
Directory.CreateDirectory(fixtureRoot);
using (var authorityKey = RSA.Create(2048))
using (var signingKey = RSA.Create(2048))
{
    var authorityRequest = new CertificateRequest("CN=TrollDock Synthetic Test CA", authorityKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    authorityRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
    authorityRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
    using var authority = authorityRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-2), DateTimeOffset.UtcNow.AddDays(60));
    var leafRequest = new CertificateRequest("CN=TrollDock Test Identity, OU=TEAM123456", signingKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    leafRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
    leafRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
    using var publicLeaf = leafRequest.Create(authority, DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30), RandomNumberGenerator.GetBytes(16));
    using var leaf = publicLeaf.CopyWithPrivateKey(signingKey);
    using var publicAuthority = X509CertificateLoader.LoadCertificate(authority.RawData);
    var collection = new X509Certificate2Collection { leaf, publicAuthority };
    File.WriteAllBytes(Path.Combine(fixtureRoot, "identity.p12"), collection.Export(X509ContentType.Pkcs12, "")!);
    var profile = new XDocument(new XElement("plist", new XAttribute("version", "1.0"), new XElement("dict",
        new XElement("key", "Name"), new XElement("string", "Synthetic Test Only"),
        new XElement("key", "UUID"), new XElement("string", Guid.NewGuid().ToString()),
        new XElement("key", "ExpirationDate"), new XElement("date", DateTime.UtcNow.AddDays(10).ToString("O")),
        new XElement("key", "TeamIdentifier"), new XElement("array", new XElement("string", "TEAM123456")),
        new XElement("key", "ApplicationIdentifierPrefix"), new XElement("array", new XElement("string", "OLDPREFIX1")),
        new XElement("key", "Entitlements"), new XElement("dict", new XElement("key", "application-identifier"), new XElement("string", "OLDPREFIX1.com.example.*"), new XElement("key", "com.apple.developer.team-identifier"), new XElement("string", "TEAM123456"), new XElement("key", "keychain-access-groups"), new XElement("array", new XElement("string", "OLDPREFIX1.*"))),
        new XElement("key", "DeveloperCertificates"), new XElement("array", new XElement("data", Convert.ToBase64String(leaf.RawData))),
        new XElement("key", "ProvisionedDevices"), new XElement("array", new XElement("string", "00000001-0000000000000001"))
    )));
    var bcLeaf = new X509CertificateParser().ReadCertificate(leaf.RawData);
    var generator = new CmsSignedDataGenerator();
    generator.AddSigner(PrivateKeyFactory.CreateKey(signingKey.ExportPkcs8PrivateKey()), bcLeaf, CmsSignedGenerator.DigestSha256);
    generator.AddCertificates(CollectionUtilities.CreateStore(new[] { bcLeaf, new X509CertificateParser().ReadCertificate(publicAuthority.RawData) }));
    File.WriteAllBytes(Path.Combine(fixtureRoot, "profile.mobileprovision"), generator.Generate(new CmsProcessableByteArray(Encoding.UTF8.GetBytes(profile.ToString())), true).GetEncoded());
    var normalProfile = profile.ToString().Replace("OLDPREFIX1", "TEAM123456", StringComparison.Ordinal);
    File.WriteAllBytes(Path.Combine(fixtureRoot, "normal-profile.mobileprovision"), generator.Generate(new CmsProcessableByteArray(Encoding.UTF8.GetBytes(normalProfile)), true).GetEncoded());
    var exactProfile = normalProfile.Replace("TEAM123456.com.example.*", "TEAM123456.app.synthetic.unrelated", StringComparison.Ordinal)
        .Replace("TEAM123456.*", "TEAM123456.shared.specific", StringComparison.Ordinal);
    File.WriteAllBytes(Path.Combine(fixtureRoot, "exact-profile.mobileprovision"), generator.Generate(new CmsProcessableByteArray(Encoding.UTF8.GetBytes(exactProfile)), true).GetEncoded());
    var partialProfile = normalProfile.Replace("TEAM123456.com.example.*", "TEAM123456.allowed.prefix.*", StringComparison.Ordinal)
        .Replace("TEAM123456.*", "TEAM123456.other.keychain.*", StringComparison.Ordinal);
    File.WriteAllBytes(Path.Combine(fixtureRoot, "partial-profile.mobileprovision"), generator.Generate(new CmsProcessableByteArray(Encoding.UTF8.GetBytes(partialProfile)), true).GetEncoded());
    var malformedProfile = normalProfile.Replace("TEAM123456.com.example.*", "TEAM123456.invalid.*.suffix", StringComparison.Ordinal);
    File.WriteAllBytes(Path.Combine(fixtureRoot, "malformed-profile.mobileprovision"), generator.Generate(new CmsProcessableByteArray(Encoding.UTF8.GetBytes(malformedProfile)), true).GetEncoded());
}
var runner = new CertificateToolRunner(toolRoot);
await runner.VerifyToolsAsync(); Check(true, "pinned executable hashes");
var quoteCases = new[] { "", "plain", "space and кириллица", "a\"b", @"C:\path with space\", "\\\\\"" };
using (var job = new CertificateToolRunner.ChildProcessJob())
{
    var start = StartInfo(["echo", .. quoteCases]);
    start.Environment["TROLLDOCK_TEST_VALUE"] = "кириллица and spaces";
    using var child = job.Start(start);
    var output = child.StandardOutput.ReadToEndAsync();
    var error = child.StandardError.ReadToEndAsync();
    await child.Process.WaitForExitAsync();
    var lines = (await output).Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    Check(JsonSerializer.Deserialize<string[]>(lines[0])!.SequenceEqual(quoteCases), "native child argument quoting round trip");
    Check(lines[1] == "ENV=кириллица and spaces", "native child Unicode environment");
    Check((await error).Trim() == "stderr works", "native child separate stderr pipe");
    Check(child.Process.ExitCode == 0, "native child exit code");
}
int ownedPid, descendantPid;
using (var job = new CertificateToolRunner.ChildProcessJob())
using (var child = job.Start(StartInfo("tree")))
{
    ownedPid = child.Process.Id;
    descendantPid = int.Parse((await child.StandardOutput.ReadLineAsync())!);
}
await WaitGone(ownedPid); await WaitGone(descendantPid);
Check(true, "closing Job Object terminates child and descendant");
var ownerStart = StartInfo("job-owner");
ownerStart.RedirectStandardOutput = true;
using (var owner = Process.Start(ownerStart)!)
{
    var ids = (await owner.StandardOutput.ReadLineAsync())!.Split(',').Select(int.Parse).ToArray();
    owner.Kill(); await owner.WaitForExitAsync();
    await WaitGone(ids[0]); await WaitGone(ids[1]);
    Check(true, "abrupt parent death terminates child and descendant");
}
Check(CertificateToolRunner.TryReadLog("{\"level\":\"INFO\",\"msg\":\"installation successful\"}", out var level, out var message)
    && level == "INFO" && message == "installation successful", "parse structured install acknowledgement");
Check(!CertificateToolRunner.TryReadLog("installation successful", out _, out _), "plain success text is not an acknowledgement");
await RejectAsync(() => runner.InstallAsync("nonexistent.ipa", "", _ => { }), "empty UDID rejected before process start");
await RejectAsync(() => runner.InstallAsync("nonexistent.ipa", "--udid=another", _ => { }), "option injection rejected before process start");
var testRoot = Path.Combine(AppContext.BaseDirectory, "tool-test-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(testRoot);
try
{
    var tamperedToolRoot = Path.Combine(testRoot, "tampered-tools"); Directory.CreateDirectory(Path.Combine(tamperedToolRoot, "zsign"));
    File.WriteAllBytes(Path.Combine(tamperedToolRoot, "zsign", "zsign.exe"), [0, 1, 2, 3]);
    await RejectAsync(() => new CertificateToolRunner(tamperedToolRoot).VerifyToolsAsync(), "modified tool binary fails pinned hash verification");
    await RejectAsync(() => runner.SignAsync(Path.Combine(testRoot, "..", "original.ipa"), "key", "profile", "output", testRoot, _ => { }), "input outside temporary workspace rejected");
    var method = typeof(CertificateToolRunner).GetMethod("RunAsync", BindingFlags.Instance | BindingFlags.NonPublic)!;
    var testRunner = new CertificateToolRunner(Path.GetDirectoryName(self));
    async Task<object> RunFake(string[] arguments, CancellationToken token = default, TimeSpan? timeout = null)
    {
        var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(self)));
        var task = (Task)method.Invoke(testRunner, ["", Path.GetFileName(self), hash, arguments, testRoot, (Action<string>)(_ => { }), token, timeout ?? TimeSpan.FromSeconds(30)])!;
        await task;
        return task.GetType().GetProperty("Result")!.GetValue(task)!;
    }
    var success = await RunFake(["tool-output", "{\"level\":\"INFO\",\"msg\":\"installation successful\"}"]);
    Check((bool)success.GetType().GetProperty("InstallationComplete")!.GetValue(success)!, "runner recognizes JSON completion marker");
    var failure = await RunFake(["tool-output", "{\"level\":\"INFO\",\"msg\":\"installation successful\"}", "{\"level\":\"ERROR\",\"msg\":\"device rejected install\"}"]);
    Check((bool)failure.GetType().GetProperty("ErrorReported")!.GetValue(failure)!, "error after completion marker still fails");
    var spoof = await RunFake(["tool-output", "installation successful", "{\"level\":\"WARN\",\"msg\":\"installation successful\"}"]);
    Check(!(bool)spoof.GetType().GetProperty("InstallationComplete")!.GetValue(spoof)!, "plain text and wrong log level cannot confirm installation");
    using (var cancellation = new CancellationTokenSource(500))
        await RejectAsync(() => RunFake(["sleep"], cancellation.Token), "cancellation terminates and waits for child");
    await RejectAsync(() => RunFake(["sleep"], timeout: TimeSpan.FromMilliseconds(500)), "timeout terminates and waits for child");
    var jobDir = Path.Combine(testRoot, "signing job кириллица");
    Directory.CreateDirectory(jobDir);
    var original = Path.Combine(fixtureRoot, "unsigned.ipa");
    var before = SHA256.HashData(File.ReadAllBytes(original));
    foreach (var file in new[] { "unsigned.ipa", "identity.p12", "profile.mobileprovision" }) File.Copy(Path.Combine(fixtureRoot, file), Path.Combine(jobDir, file));
    var output = Path.Combine(jobDir, "signed.ipa");
    using var material = SigningMaterial.Load(Path.Combine(jobDir, "identity.p12"), Path.Combine(jobDir, "profile.mobileprovision"), "");
    await runner.SignAsync(Path.Combine(jobDir, "unsigned.ipa"), Path.Combine(jobDir, "identity.p12"), Path.Combine(jobDir, "profile.mobileprovision"), output, jobDir, Console.WriteLine);
    Check(File.Exists(output), "pinned zsign signs synthetic Mach-O fixture using blank-password P12");
    Check(SHA256.HashData(File.ReadAllBytes(original)).AsSpan().SequenceEqual(before), "source IPA remains byte-for-byte unchanged");
    using var archive = ZipFile.OpenRead(output);
    Check(archive.GetEntry("Payload/TestFixture.app/_CodeSignature/CodeResources") != null, "signed IPA contains resource seal");
    using var embedded = archive.GetEntry("Payload/TestFixture.app/embedded.mobileprovision")!.Open();
    using var bytes = new MemoryStream(); embedded.CopyTo(bytes);
    Check(bytes.ToArray().AsSpan().SequenceEqual(File.ReadAllBytes(Path.Combine(fixtureRoot, "profile.mobileprovision"))), "signed IPA contains exact supplied profile");
    using var executableStream = archive.GetEntry("Payload/TestFixture.app/TestFixture")!.Open();
    using var executableMemory = new MemoryStream(); executableStream.CopyTo(executableMemory);
    var executable = executableMemory.ToArray();
    uint LE(int offset) => BinaryPrimitives.ReadUInt32LittleEndian(executable.AsSpan(offset, 4));
    int signatureOffset = 0;
    for (int i = 0, offset = 32; i < LE(16); i++)
    {
        if (LE(offset) == 0x1d) signatureOffset = checked((int)LE(offset + 8));
        offset += checked((int)LE(offset + 4));
    }
    uint BE(int offset) => BinaryPrimitives.ReadUInt32BigEndian(executable.AsSpan(signatureOffset + offset, 4));
    Check(signatureOffset > 0 && BE(0) == 0xfade0cc0, "Mach-O contains embedded signature superblob");
    var slots = new Dictionary<uint, byte[]>();
    for (int i = 0; i < BE(8); i++)
    {
        var slot = BE(12 + i * 8); var offset = checked((int)BE(16 + i * 8));
        slots.Add(slot, executable.AsSpan(signatureOffset + offset, checked((int)BE(offset + 4))).ToArray());
    }
    var codeDirectory = slots[0];
    var cms = new CmsSignedData(new CmsProcessableByteArray(codeDirectory), slots[0x10000].AsSpan(8).ToArray());
    var certificates = cms.GetCertificates();
    Check(cms.GetSignerInfos().GetSigners().All(signer => certificates.EnumerateMatches(signer.SignerID).Any(signer.Verify)), "CMS signature cryptographically verifies against embedded certificate");
    uint CD(int offset) => BinaryPrimitives.ReadUInt32BigEndian(codeDirectory.AsSpan(offset, 4));
    var hashOffset = checked((int)CD(16)); var codeSlots = CD(28); var codeLimit = checked((int)CD(32));
    var hashSize = codeDirectory[36]; var pageSize = 1 << codeDirectory[39];
    Check(codeDirectory[37] == 2 && hashSize == 32, "CodeDirectory uses SHA-256");
    for (int i = 0; i < codeSlots; i++)
    {
        var page = executable.AsSpan(i * pageSize, Math.Min(pageSize, codeLimit - i * pageSize));
        Check(SHA256.HashData(page).AsSpan().SequenceEqual(codeDirectory.AsSpan(hashOffset + i * hashSize, hashSize)), "code page " + i + " hash verifies");
    }
    using var entitlementStream = new MemoryStream(slots[5].AsSpan(8).ToArray());
    var entitlementDocument = XDocument.Load(entitlementStream);
    var entitlementValues = entitlementDocument.Root!.Element("dict")!.Elements().ToArray();
    var appIdentifier = Enumerable.Range(0, entitlementValues.Length / 2).Where(i => entitlementValues[i * 2].Value == "application-identifier").Select(i => entitlementValues[i * 2 + 1].Value).Single();
    Check(appIdentifier == "OLDPREFIX1.com.example.trolldock.test", "signature contains concrete legacy-prefix application identifier");
    // Save only synthetic output for separate Mach-O/CMS verification; never distribute it.
    File.Copy(output, Path.Combine(fixtureRoot, "signed.ipa"), true);
    foreach (var scenario in new[] { ("normal-profile.mobileprovision", "TEAM123456"), ("profile.mobileprovision", "OLDPREFIX1") })
    {
        var nestedJob = Path.Combine(testRoot, scenario.Item2);
        Directory.CreateDirectory(nestedJob);
        foreach (var file in new[] { "unsigned-extension.ipa", "identity.p12", scenario.Item1 }) File.Copy(Path.Combine(fixtureRoot, file), Path.Combine(nestedJob, file));
        var nestedInput = Path.Combine(nestedJob, "unsigned-extension.ipa");
        var inputHash = SHA256.HashData(File.ReadAllBytes(nestedInput));
        var nestedOutput = Path.Combine(nestedJob, "signed.ipa");
        await runner.SignAsync(nestedInput, Path.Combine(nestedJob, "identity.p12"), Path.Combine(nestedJob, scenario.Item1), nestedOutput, nestedJob, _ => { });
        using var nestedArchive = ZipFile.OpenRead(nestedOutput);
        var profileBytes = File.ReadAllBytes(Path.Combine(nestedJob, scenario.Item1));
        VerifyBundle(nestedArchive, "Payload/TestFixture.app", scenario.Item2 + ".com.example.trolldock.test", profileBytes);
        VerifyBundle(nestedArchive, "Payload/TestFixture.app/PlugIns/Sample.appex", scenario.Item2 + ".com.example.trolldock.test.extension", profileBytes);
        Check(SHA256.HashData(File.ReadAllBytes(nestedInput)).AsSpan().SequenceEqual(inputHash), scenario.Item2 + " nested input remains unchanged");
    }
    var exactJob = Path.Combine(testRoot, "exact-profile"); Directory.CreateDirectory(exactJob);
    foreach (var file in new[] { "unsigned-extension.ipa", "identity.p12", "exact-profile.mobileprovision" }) File.Copy(Path.Combine(fixtureRoot, file), Path.Combine(exactJob, file));
    await runner.SignAsync(Path.Combine(exactJob, "unsigned-extension.ipa"), Path.Combine(exactJob, "identity.p12"), Path.Combine(exactJob, "exact-profile.mobileprovision"), Path.Combine(exactJob, "signed.ipa"), exactJob, _ => { });
    using (var exactArchive = ZipFile.OpenRead(Path.Combine(exactJob, "signed.ipa")))
    {
        var profileBytes = File.ReadAllBytes(Path.Combine(exactJob, "exact-profile.mobileprovision"));
        VerifyBundle(exactArchive, "Payload/TestFixture.app", "TEAM123456.app.synthetic.unrelated", profileBytes, ["TEAM123456.shared.specific"]);
        VerifyBundle(exactArchive, "Payload/TestFixture.app/PlugIns/Sample.appex", "TEAM123456.app.synthetic.unrelated", profileBytes, ["TEAM123456.shared.specific"]);
    }
    var partialJob = Path.Combine(testRoot, "partial-profile"); Directory.CreateDirectory(partialJob);
    foreach (var file in new[] { "unsigned-extension.ipa", "identity.p12", "partial-profile.mobileprovision" }) File.Copy(Path.Combine(fixtureRoot, file), Path.Combine(partialJob, file));
    await runner.SignAsync(Path.Combine(partialJob, "unsigned-extension.ipa"), Path.Combine(partialJob, "identity.p12"), Path.Combine(partialJob, "partial-profile.mobileprovision"), Path.Combine(partialJob, "signed.ipa"), partialJob, _ => { });
    using (var partialArchive = ZipFile.OpenRead(Path.Combine(partialJob, "signed.ipa")))
    {
        var profileBytes = File.ReadAllBytes(Path.Combine(partialJob, "partial-profile.mobileprovision"));
        VerifyBundle(partialArchive, "Payload/TestFixture.app", "TEAM123456.allowed.prefix.com.example.trolldock.test", profileBytes, ["TEAM123456.other.keychain.com.example.trolldock.test"]);
        VerifyBundle(partialArchive, "Payload/TestFixture.app/PlugIns/Sample.appex", "TEAM123456.allowed.prefix.com.example.trolldock.test.extension", profileBytes, ["TEAM123456.other.keychain.com.example.trolldock.test.extension"]);
    }
    var malformedJob = Path.Combine(testRoot, "malformed-profile"); Directory.CreateDirectory(malformedJob);
    foreach (var file in new[] { "unsigned.ipa", "identity.p12", "malformed-profile.mobileprovision" }) File.Copy(Path.Combine(fixtureRoot, file), Path.Combine(malformedJob, file));
    await RejectAsync(() => runner.SignAsync(Path.Combine(malformedJob, "unsigned.ipa"), Path.Combine(malformedJob, "identity.p12"), Path.Combine(malformedJob, "malformed-profile.mobileprovision"), Path.Combine(malformedJob, "signed.ipa"), malformedJob, _ => { }), "malformed wildcard identity fails signing");
    var corruptJob = Path.Combine(testRoot, "corrupt-profile"); Directory.CreateDirectory(corruptJob);
    foreach (var file in new[] { "unsigned.ipa", "identity.p12" }) File.Copy(Path.Combine(fixtureRoot, file), Path.Combine(corruptJob, file));
    File.WriteAllBytes(Path.Combine(corruptJob, "profile.mobileprovision"), [0, 1, 2, 3]);
    await RejectAsync(() => runner.SignAsync(Path.Combine(corruptJob, "unsigned.ipa"), Path.Combine(corruptJob, "identity.p12"), Path.Combine(corruptJob, "profile.mobileprovision"), Path.Combine(corruptJob, "signed.ipa"), corruptJob, _ => { }), "corrupted provisioning profile cannot produce successful signing result");
    var workflowInput = Path.Combine(fixtureRoot, "unsigned-extension.ipa");
    var workflowOriginalHash = SHA256.HashData(File.ReadAllBytes(workflowInput));
    var workflowStaging = Path.Combine(testRoot, "workflow-staging-测试-🧪");
    var workflowProfile = File.ReadAllBytes(Path.Combine(fixtureRoot, "exact-profile.mobileprovision"));
    using var workflowMaterial = SigningMaterial.Load(File.ReadAllBytes(Path.Combine(fixtureRoot, "identity.p12")), workflowProfile, "");
    var simulatedUsb = new RealSignFakeInstall(runner, ipa =>
    {
        using var signedArchive = ZipFile.OpenRead(ipa);
        VerifyBundle(signedArchive, "Payload/TestFixture.app", "TEAM123456.app.synthetic.unrelated", workflowProfile, ["TEAM123456.shared.specific"]);
        VerifyBundle(signedArchive, "Payload/TestFixture.app/PlugIns/Sample.appex", "TEAM123456.app.synthetic.unrelated", workflowProfile, ["TEAM123456.shared.specific"]);
    });
    var progress = new List<TransferProgress>();
    await new CertificateInstallWorkflow(simulatedUsb, workflowStaging).InstallAsync(workflowInput, workflowMaterial,
        "00000001-0000000000000001", new InlineProgress<TransferProgress>(progress.Add), _ => { }, CancellationToken.None);
    Check(simulatedUsb.InstalledUdid == "00000001-0000000000000001" && simulatedUsb.VerifyCalled, "real workflow targets fixed device and supplementary verification after simulated USB acknowledgement");
    Check(simulatedUsb.SignedIpa != workflowInput && simulatedUsb.JobDirectory is not null, "real workflow signs a separate private working copy");
    Check(simulatedUsb.ProfilePath!.Length > 260, "real workflow signs with a Unicode provisioning-profile path beyond MAX_PATH");
    Check(!Directory.Exists(simulatedUsb.JobDirectory) && !File.Exists(simulatedUsb.SignedIpa)
        && !Directory.EnumerateFileSystemEntries(workflowStaging).Any(), "real workflow deletes signed IPA, identity, profile, signer intermediates and workspace after simulated install");
    Check(SHA256.HashData(File.ReadAllBytes(workflowInput)).AsSpan().SequenceEqual(workflowOriginalHash), "real workflow leaves selected original IPA byte-for-byte unchanged");
    Check(progress.Last().Stage == "Установлено", "real workflow reports completion only after cleanup");
}
finally
{
    var full = Path.GetFullPath(testRoot);
    if (full.StartsWith(Path.GetFullPath(AppContext.BaseDirectory), StringComparison.OrdinalIgnoreCase) && Path.GetFileName(full).StartsWith("tool-test-")) Directory.Delete(full, true);
}
Console.WriteLine($"Passed {passed} checks.");

sealed class InlineProgress<T>(Action<T> callback) : IProgress<T>
{
    public void Report(T value) => callback(value);
}

sealed class RealSignFakeInstall(CertificateToolRunner runner, Action<string> inspect) : ICertificateInstallTools
{
    public string? JobDirectory { get; private set; }
    public string? SignedIpa { get; private set; }
    public string? ProfilePath { get; private set; }
    public string? InstalledUdid { get; private set; }
    public bool VerifyCalled { get; private set; }
    public Task VerifyToolsAsync(CancellationToken token) => runner.VerifyToolsAsync(token);
    public Task SignAsync(string input, string p12, string profile, string output, string job, Action<string> log, CancellationToken token, string? entitlementsPath = null)
    {
        JobDirectory = job;
        ProfilePath = profile;
        return runner.SignAsync(input, p12, profile, output, job, log, token, entitlementsPath);
    }
    public Task InstallAsync(string ipa, string udid, Action<string> log)
    {
        SignedIpa = ipa; InstalledUdid = udid;
        inspect(ipa); // Assertions run before the acknowledged USB boundary and cleanup.
        return Task.CompletedTask;
    }
    public Task<bool> VerifyInstalledAsync(string bundle, string udid)
    {
        VerifyCalled = true;
        return Task.FromResult(bundle == "com.example.trolldock.test" && udid == InstalledUdid);
    }
}
