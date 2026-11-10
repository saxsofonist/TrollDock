using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml.Linq;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509;
using TrollDock.Services;

var passed = 0;
void Check(bool value, string message) { if (!value) throw new Exception(message); passed++; Console.WriteLine("PASS " + message); }
void Reject(Action action, string message) { try { action(); } catch (Exception e) when (e is InvalidDataException or InvalidOperationException or ArgumentException) { passed++; Console.WriteLine("PASS " + message); return; } throw new Exception("Did not reject: " + message); }
using var rsa = RSA.Create(2048);
var request = new CertificateRequest("CN=TrollDock Test Identity, OU=TEAM123456", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
var password = "test only — password ∆";
var p12 = certificate.Export(X509ContentType.Pkcs12, password);
var originalP12Hash = SHA256.HashData(p12);
var bcCertificate = new X509CertificateParser().ReadCertificate(certificate.RawData);
var bcPrivate = PrivateKeyFactory.CreateKey(rsa.ExportPkcs8PrivateKey());
byte[] Profile(bool expired = false, bool appStore = false, bool all = false, bool mismatch = false, string keychainPattern = "OLDPREFIX1.*")
{
    var doc = new XDocument(new XElement("plist", new XAttribute("version", "1.0"), new XElement("dict",
        new XElement("key", "Name"), new XElement("string", "Test Development"),
        new XElement("key", "UUID"), new XElement("string", Guid.NewGuid().ToString()),
        new XElement("key", "ExpirationDate"), new XElement("date", DateTime.UtcNow.AddDays(expired ? -2 : 10).ToString("O")),
        new XElement("key", "CreationDate"), new XElement("date", DateTime.UtcNow.AddDays(-3).ToString("O")),
        new XElement("key", "TeamIdentifier"), new XElement("array", new XElement("string", "TEAM123456")),
        new XElement("key", "ApplicationIdentifierPrefix"), new XElement("array", new XElement("string", "OLDPREFIX1")),
        new XElement("key", "Entitlements"), new XElement("dict", new XElement("key", "application-identifier"), new XElement("string", "OLDPREFIX1.com.example.*"), new XElement("key", "com.apple.developer.team-identifier"), new XElement("string", "TEAM123456"),
            new XElement("key", "keychain-access-groups"), new XElement("array", new XElement("string", keychainPattern), new XElement("string", "TEAM123456.shared-explicit"))),
        new XElement("key", "DeveloperCertificates"), new XElement("array", new XElement("data", Convert.ToBase64String(mismatch ? [1, 2, 3] : certificate.RawData)))
    )));
    var dict = doc.Root!.Element("dict")!;
    if (!appStore && !all) dict.Add(new XElement("key", "ProvisionedDevices"), new XElement("array", new XElement("string", "00000001-0000000000000001")));
    if (all) dict.Add(new XElement("key", "ProvisionsAllDevices"), new XElement("true"));
    var generator = new CmsSignedDataGenerator();
    generator.AddSigner(bcPrivate, bcCertificate, CmsSignedGenerator.DigestSha256);
    generator.AddCertificates(CollectionUtilities.CreateStore(new[] { bcCertificate }));
    return generator.Generate(new CmsProcessableByteArray(Encoding.UTF8.GetBytes(doc.ToString())), true).GetEncoded();
}
var profile = Profile();
if (Environment.GetEnvironmentVariable("TROLLDOCK_WRITE_SIGNING_FIXTURE") == "1")
{
    var fixtureDirectory = Path.GetFullPath(Path.Combine("work", "certificate-tools", "test-fixture"));
    Directory.CreateDirectory(fixtureDirectory);
    File.WriteAllBytes(Path.Combine(fixtureDirectory, "identity.p12"), certificate.Export(X509ContentType.Pkcs12, ""));
    File.WriteAllBytes(Path.Combine(fixtureDirectory, "profile.mobileprovision"), profile);
    File.WriteAllText(Path.Combine(fixtureDirectory, "TEST-ONLY.txt"), "Synthetic local test identity. Not an Apple certificate. Bundle IDs: com.example.*; UDID: 00000001-0000000000000001; P12 password: empty.\n");
    Console.WriteLine("Wrote synthetic test-only fixture: " + fixtureDirectory);
}
using var material = SigningMaterial.Load(p12, profile, password);
Check(material.Metadata.TeamId == "TEAM123456", "parse team and legacy App ID prefix");
Check(material.Metadata.Name == "Test Development", "parse profile name");
Check(material.AllowsBundleIdentifier("com.example.application"), "wildcard accepts matching bundle");
Check(!material.AllowsBundleIdentifier("com.other.application"), "wildcard rejects another bundle");
material.CheckDevice("00000001-0000000000000001"); Check(true, "registered device accepted");
Reject(() => material.CheckDevice("other"), "unregistered device rejected");
Reject(() => SigningMaterial.Load(p12, profile, "wrong"), "wrong P12 password rejected");
Reject(() => SigningMaterial.Load(p12, Profile(expired: true), password), "expired profile rejected");
Reject(() => SigningMaterial.Load(p12, Profile(appStore: true), password), "App Store profile rejected");
Reject(() => SigningMaterial.Load(p12, Profile(mismatch: true), password), "unmatched certificate rejected");
Reject(() => SigningMaterial.Load(p12, "<plist/>"u8.ToArray(), password), "unsigned profile rejected");
var corrupted = profile.ToArray();
var marker = Encoding.UTF8.GetBytes("Test Development");
var contentOffset = corrupted.AsSpan().IndexOf(marker);
corrupted[contentOffset] ^= 1;
Reject(() => SigningMaterial.Load(p12, corrupted, password), "tampered signed profile rejected");
using (var enterprise = SigningMaterial.Load(p12, Profile(all: true), password)) { enterprise.CheckDevice("any-device"); Check(true, "enterprise accepts device"); }
var testRoot = Path.Combine(AppContext.BaseDirectory, "test-data-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(testRoot);
try
{
    var files = material.WriteToDirectory(testRoot);
    using var exported = SigningMaterial.Load(files.P12Path, files.ProfilePath, "");
    Check(exported.Metadata.TeamId == material.Metadata.TeamId, "temporary P12 signs without command-line password");
    Check(originalP12Hash.AsSpan().SequenceEqual(SHA256.HashData(p12)), "source P12 remains byte-for-byte unchanged");
    Check(profile.AsSpan().SequenceEqual(File.ReadAllBytes(files.ProfilePath)), "profile temporary copy is exact");
    var entitlements = XDocument.Load(material.WriteEntitlements(testRoot, "com.example.application"));
    var entitlementElements = entitlements.Root!.Element("dict")!.Elements().ToArray();
    var entitlementValues = Enumerable.Range(0, entitlementElements.Length / 2).ToDictionary(i => entitlementElements[i * 2].Value, i => entitlementElements[i * 2 + 1]);
    Check(entitlementValues["application-identifier"].Value == "OLDPREFIX1.com.example.application", "resolved application identifier uses actual legacy prefix");
    Check(entitlementValues["com.apple.developer.team-identifier"].Value == "TEAM123456", "resolved entitlements preserve actual Team ID");
    Check(entitlementValues["keychain-access-groups"].Elements().Select(e => e.Value).SequenceEqual(["OLDPREFIX1.com.example.application", "TEAM123456.shared-explicit"]), "keychain wildcard resolves and explicit shared group is preserved");
    Reject(() => material.WriteEntitlements(testRoot, "com.other.app"), "entitlements reject unpermitted bundle identifier");
    using (var ambiguous = SigningMaterial.Load(p12, Profile(keychainPattern: "TEAM123456.*"), password))
        Reject(() => ambiguous.WriteEntitlements(testRoot, "com.example.app"), "keychain wildcard with incompatible prefix fails clearly");
    var vault = new CertificateVault(Path.Combine(testRoot, "vault"));
    try
    {
        var saved = vault.Save("Мой сертификат", material);
        Check(vault.List().Single().Name == "Мой сертификат", "named vault list");
        using var loaded = vault.Load(saved.Id);
        Check(loaded.Metadata.TeamId == material.Metadata.TeamId, "DPAPI save and load round trip");
        var disk = File.ReadAllBytes(Directory.GetFiles(Path.Combine(testRoot, "vault"), "*.tdcert").Single());
        Check(disk.AsSpan().IndexOf(Encoding.UTF8.GetBytes(password)) < 0 && disk.AsSpan().IndexOf(p12.AsSpan(0, Math.Min(64, p12.Length))) < 0, "vault does not contain plaintext password or P12");
        Reject(() => vault.Save("МОЙ СЕРТИФИКАТ", material), "duplicate name rejected");
        Reject(() => vault.Save("\n", material), "empty name rejected");
        vault.Delete(saved.Id); Check(vault.List().Count == 0, "vault deletion bypasses Recycle Bin");
    }
    catch (System.ComponentModel.Win32Exception e) when (e.NativeErrorCode == 2)
    { Console.WriteLine("SKIP DPAPI runtime not available in sandbox: error 2"); }
}
finally
{
    var full = Path.GetFullPath(testRoot);
    if (full.StartsWith(Path.GetFullPath(AppContext.BaseDirectory), StringComparison.OrdinalIgnoreCase) && Path.GetFileName(full).StartsWith("test-data-")) Directory.Delete(full, true);
    CryptographicOperations.ZeroMemory(p12);
}
Console.WriteLine($"Passed {passed} checks.");
