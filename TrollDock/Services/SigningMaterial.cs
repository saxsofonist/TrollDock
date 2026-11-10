using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using Org.BouncyCastle.Cms;

namespace TrollDock.Services;

public sealed record SigningMetadata(
    string Name, string TeamId, string ApplicationIdentifier, DateTimeOffset ExpiresAt,
    string CertificateSubject, IReadOnlyList<string> DeviceUdids, bool ProvisionsAllDevices)
{
    public string Summary => $"{Name} · до {ExpiresAt.LocalDateTime:dd.MM.yyyy}";
}

public sealed record SigningMaterialFiles(string P12Path, string ProfilePath);

/// <summary>
/// Holds credentials in memory and imports keys ephemerally. Profile signature integrity,
/// profile membership and validity are checked locally; Apple trust/revocation is ultimately
/// enforced by iOS during installation. This is not an online certificate-status check.
/// </summary>
public sealed class SigningMaterial : IDisposable
{
    private readonly byte[] _p12;
    private readonly byte[] _profile;
    private readonly string _password;
    private bool _disposed;
    public SigningMetadata Metadata { get; }
    internal byte[] P12Bytes { get { ObjectDisposedException.ThrowIf(_disposed, this); return _p12; } }
    internal byte[] ProfileBytes { get { ObjectDisposedException.ThrowIf(_disposed, this); return _profile; } }
    internal string Password { get { ObjectDisposedException.ThrowIf(_disposed, this); return _password; } }
    private const int MaximumMaterialBytes = 16 * 1024 * 1024;

    private SigningMaterial(byte[] p12, byte[] profile, string password, SigningMetadata metadata)
    { _p12 = p12; _profile = profile; _password = password; Metadata = metadata; }

    public static SigningMaterial Load(string p12Path, string profilePath, string password)
    {
        var p12 = ReadLimitedFile(p12Path);
        try
        {
            var profile = ReadLimitedFile(profilePath);
            try { return Load(p12, profile, password); }
            finally { CryptographicOperations.ZeroMemory(profile); }
        }
        finally { CryptographicOperations.ZeroMemory(p12); }
    }

    public static SigningMaterial Load(byte[] p12, byte[] profile, string password)
    {
        ArgumentNullException.ThrowIfNull(p12);
        ArgumentNullException.ThrowIfNull(profile);
        ArgumentNullException.ThrowIfNull(password);
        if (p12.Length is 0 or > MaximumMaterialBytes || profile.Length is 0 or > MaximumMaterialBytes)
            throw new InvalidDataException("Файлы сертификата и профиля должны быть непустыми и не больше 16 МБ.");
        var dictionary = ReadSignedProfile(profile);
        var expiry = ReadDate(dictionary, "ExpirationDate");
        var now = DateTimeOffset.UtcNow;
        if (expiry <= now) throw new InvalidDataException("Срок действия профиля .mobileprovision истёк.");
        if (dictionary.TryGetValue("CreationDate", out var created) && ParseDate(created) > now.AddMinutes(5))
            throw new InvalidDataException("Профиль ещё не действует. Проверьте дату и время на компьютере.");
        var entitlements = ReadDictionary(Required(dictionary, "Entitlements"));
        var applicationId = ReadString(entitlements, "application-identifier");
        var teamIds = ReadStrings(Required(dictionary, "TeamIdentifier"));
        if (teamIds.Length != 1 || string.IsNullOrWhiteSpace(teamIds[0]))
            throw new InvalidDataException("Не удалось определить команду разработчика в профиле.");
        var prefixIndex = applicationId.IndexOf('.');
        if (prefixIndex <= 0 || prefixIndex == applicationId.Length - 1)
            throw new InvalidDataException("В профиле неверный application-identifier.");
        // Older Apple accounts may use an App ID prefix different from their Team ID.
        var appPrefixes = dictionary.TryGetValue("ApplicationIdentifierPrefix", out var prefixes)
            ? ReadStrings(prefixes) : teamIds;
        if (!appPrefixes.Contains(applicationId[..prefixIndex], StringComparer.Ordinal))
            throw new InvalidDataException("Префикс приложения не соответствует профилю.");
        if (entitlements.TryGetValue("com.apple.developer.team-identifier", out var teamEntitlement)
            && teamEntitlement.Value != teamIds[0])
            throw new InvalidDataException("Идентификаторы команды в профиле не совпадают.");
        var devices = dictionary.TryGetValue("ProvisionedDevices", out var devicesNode)
            ? ReadStrings(devicesNode) : [];
        var allDevices = dictionary.TryGetValue("ProvisionsAllDevices", out var all) && all.Name.LocalName == "true";
        if (!allDevices && devices.Length == 0)
            throw new InvalidDataException("Это профиль для App Store. Для установки с ПК нужен Development, Ad Hoc или Enterprise .mobileprovision.");
        var developerCertificates = Required(dictionary, "DeveloperCertificates");
        if (developerCertificates.Name.LocalName != "array") throw new InvalidDataException("В профиле нет списка сертификатов.");
        var expectedCerts = developerCertificates.Elements().Select(element =>
        {
            if (element.Name.LocalName != "data") throw new InvalidDataException("Некорректный сертификат в профиле.");
            try { return Convert.FromBase64String(element.Value); }
            catch (FormatException e) { throw new InvalidDataException("Повреждён сертификат в профиле.", e); }
        }).ToArray();

        var certificates = ImportP12(p12, password);
        try
        {
            var candidates = certificates.Cast<X509Certificate2>()
                .Where(c => c.HasPrivateKey && expectedCerts.Any(expected => c.RawData.AsSpan().SequenceEqual(expected)))
                .ToArray();
            if (candidates.Length == 0)
                throw new InvalidDataException("В P12 нет закрытого ключа сертификата, указанного в этом .mobileprovision. Выберите соответствующую пару файлов.");
            var signingCertificate = candidates.FirstOrDefault(c => c.NotBefore.ToUniversalTime() <= now.UtcDateTime && c.NotAfter.ToUniversalTime() > now.UtcDateTime)
                ?? throw new InvalidDataException("Сертификат из P12 истёк или ещё не действует.");
            VerifyPrivateKey(signingCertificate);
            if (signingCertificate.NotAfter.ToUniversalTime() < expiry.UtcDateTime)
                expiry = new DateTimeOffset(signingCertificate.NotAfter.ToUniversalTime());
            var metadata = new SigningMetadata(ReadString(dictionary, "Name"), teamIds[0], applicationId, expiry,
                signingCertificate.GetNameInfo(X509NameType.SimpleName, false), Array.AsReadOnly(devices), allDevices);
            return new SigningMaterial(p12.ToArray(), profile.ToArray(), password, metadata);
        }
        finally { foreach (var certificate in certificates) certificate.Dispose(); }
    }

    public void CheckDevice(string udid)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (string.IsNullOrWhiteSpace(udid)) throw new InvalidDataException("Не удалось прочитать UDID подключённого iPhone.");
        if (!Metadata.ProvisionsAllDevices && !Metadata.DeviceUdids.Contains(udid, StringComparer.OrdinalIgnoreCase))
            throw new InvalidDataException("Этот iPhone не включён в выбранный профиль. Добавьте его UDID в профиль разработчика и скачайте новый .mobileprovision.");
    }

    public bool AllowsBundleIdentifier(string bundleIdentifier)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (string.IsNullOrWhiteSpace(bundleIdentifier)) return false;
        var allowed = Metadata.ApplicationIdentifier[(Metadata.ApplicationIdentifier.IndexOf('.') + 1)..];
        return allowed.EndsWith('*')
            ? bundleIdentifier.StartsWith(allowed[..^1], StringComparison.Ordinal)
            : allowed.Equals(bundleIdentifier, StringComparison.Ordinal);
    }

    /// <summary>Resolves profile wildcard identifiers for this app without assuming Team ID == App ID prefix.</summary>
    public string WriteEntitlements(string jobDirectory, string bundleIdentifier)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!AllowsBundleIdentifier(bundleIdentifier) || bundleIdentifier.Contains('*'))
            throw new InvalidDataException("Профиль не разрешает идентификатор выбранного приложения.");
        if (!Directory.Exists(jobDirectory)) throw new DirectoryNotFoundException("Временный каталог задания не существует.");
        var profile = ReadSignedProfile(_profile);
        var dictionary = new XElement(Required(profile, "Entitlements"));
        var entitlements = ReadDictionary(dictionary);
        var prefix = Metadata.ApplicationIdentifier[..Metadata.ApplicationIdentifier.IndexOf('.')];
        var exactIdentifier = prefix + "." + bundleIdentifier;
        Required(entitlements, "application-identifier").Value = exactIdentifier;
        if (entitlements.TryGetValue("keychain-access-groups", out var keychainGroups))
        {
            if (keychainGroups.Name.LocalName != "array") throw new InvalidDataException("В профиле некорректный список групп Keychain.");
            foreach (var group in keychainGroups.Elements())
            {
                if (group.Name.LocalName != "string" || string.IsNullOrWhiteSpace(group.Value))
                    throw new InvalidDataException("В профиле некорректная группа Keychain.");
                var pattern = group.Value;
                if (!pattern.Contains('*')) continue;
                if (!pattern.EndsWith('*') || pattern.Count(c => c == '*') != 1 || !exactIdentifier.StartsWith(pattern[..^1], StringComparison.Ordinal))
                    throw new InvalidDataException("Профиль содержит неоднозначную wildcard-группу Keychain. Выберите профиль с группой доступа для этого приложения.");
                group.Value = exactIdentifier;
            }
        }
        var path = Path.Combine(Path.GetFullPath(jobDirectory), "entitlements-" + Guid.NewGuid().ToString("N") + ".plist");
        var document = new XDocument(new XDeclaration("1.0", "UTF-8", null), new XElement("plist", new XAttribute("version", "1.0"), dictionary));
        using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
        using (var writer = XmlWriter.Create(output, new XmlWriterSettings { Encoding = new UTF8Encoding(false), Indent = true, NewLineChars = "\n" }))
            document.Save(writer);
        return path;
    }

    /// <summary>Writes an empty-password P12 in a private, unique child folder owned by the current job.
    /// The caller must delete the entire job folder in its finally block, including failures/cancellation.</summary>
    public SigningMaterialFiles WriteToDirectory(string jobDirectory)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!Directory.Exists(jobDirectory)) throw new DirectoryNotFoundException("Временный каталог задания не существует.");
        var directory = Path.Combine(Path.GetFullPath(jobDirectory), "material-" + Guid.NewGuid().ToString("N"));
        CertificateVault.CreatePrivateDirectory(directory);
        var certificates = ImportP12(_p12, _password);
        byte[]? exported = null;
        var p12Path = Path.Combine(directory, "signing.p12");
        var profilePath = Path.Combine(directory, "profile.mobileprovision");
        try
        {
            // Export only the matching identity. Some P12 files contain more than one key;
            // otherwise an external signer could pick an identity not allowed by this profile.
            var dictionary = ReadSignedProfile(_profile);
            var allowed = Required(dictionary, "DeveloperCertificates").Elements().Select(e => Convert.FromBase64String(e.Value)).ToArray();
            var selected = certificates.Cast<X509Certificate2>().First(c => c.HasPrivateKey
                && c.NotBefore.ToUniversalTime() <= DateTime.UtcNow && c.NotAfter.ToUniversalTime() > DateTime.UtcNow
                && allowed.Any(raw => c.RawData.AsSpan().SequenceEqual(raw)));
            var exportCertificates = new X509Certificate2Collection(selected);
            foreach (var certificate in certificates)
                if (!certificate.HasPrivateKey) exportCertificates.Add(certificate);
            exported = exportCertificates.Export(X509ContentType.Pkcs12, "")
                ?? throw new InvalidDataException("Не удалось подготовить P12 для подписи.");
            using (var output = new FileStream(p12Path, FileMode.CreateNew, FileAccess.Write, FileShare.None)) output.Write(exported);
            using (var output = new FileStream(profilePath, FileMode.CreateNew, FileAccess.Write, FileShare.None)) output.Write(_profile);
            return new(p12Path, profilePath);
        }
        catch
        {
            File.Delete(p12Path);
            File.Delete(profilePath);
            if (Directory.Exists(directory)) Directory.Delete(directory);
            throw;
        }
        finally
        {
            if (exported is not null) CryptographicOperations.ZeroMemory(exported);
            foreach (var certificate in certificates) certificate.Dispose();
        }
    }

    private static X509Certificate2Collection ImportP12(byte[] p12, string password)
    {
        try { return X509CertificateLoader.LoadPkcs12Collection(p12, password, X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable); }
        catch (CryptographicException e) { throw new InvalidDataException("Не удалось открыть P12/PFX. Проверьте пароль и файл сертификата.", e); }
    }

    private static void VerifyPrivateKey(X509Certificate2 certificate)
    {
        var challenge = RandomNumberGenerator.GetBytes(32);
        using var rsaPrivate = certificate.GetRSAPrivateKey();
        if (rsaPrivate is not null)
        {
            using var rsaPublic = certificate.GetRSAPublicKey();
            if (rsaPublic?.VerifyData(challenge, rsaPrivate.SignData(challenge, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1) == true) return;
        }
        using var ecPrivate = certificate.GetECDsaPrivateKey();
        if (ecPrivate is not null)
        {
            using var ecPublic = certificate.GetECDsaPublicKey();
            if (ecPublic?.VerifyData(challenge, ecPrivate.SignData(challenge, HashAlgorithmName.SHA256), HashAlgorithmName.SHA256) == true) return;
        }
        throw new InvalidDataException("Закрытый ключ не соответствует сертификату или его алгоритм не поддерживается.");
    }

    private static Dictionary<string, XElement> ReadSignedProfile(byte[] profile)
    {
        try
        {
            var signed = new CmsSignedData(profile);
            var signers = signed.GetSignerInfos().GetSigners();
            if (signed.SignedContent is null || signers.Count == 0)
                throw new InvalidDataException("В .mobileprovision отсутствует подпись CMS.");
            var certificateStore = signed.GetCertificates();
            foreach (SignerInformation signer in signers)
                if (!certificateStore.EnumerateMatches(signer.SignerID).Any(certificate => signer.Verify(certificate)))
                    throw new InvalidDataException("Подпись .mobileprovision повреждена или не соответствует содержимому.");
            using var source = new MemoryStream();
            signed.SignedContent.Write(source);
            if (source.Length > MaximumMaterialBytes) throw new InvalidDataException("Не удалось прочитать содержимое профиля.");
            source.Position = 0;
            using var reader = XmlReader.Create(source, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Ignore, XmlResolver = null,
                MaxCharactersInDocument = MaximumMaterialBytes, MaxCharactersFromEntities = 0
            });
            var document = XDocument.Load(reader);
            return ReadDictionary(document.Root?.Name.LocalName == "plist"
                ? document.Root.Element("dict") ?? throw new InvalidDataException("Профиль не содержит plist-словарь.")
                : throw new InvalidDataException("Профиль не содержит plist."));
        }
        catch (Exception e) when (e is CmsException or Org.BouncyCastle.Security.GeneralSecurityException or ArgumentException or XmlException or IOException)
        {
            if (e is InvalidDataException) throw;
            throw new InvalidDataException("Некорректный или повреждённый .mobileprovision.", e);
        }
    }

    private static Dictionary<string, XElement> ReadDictionary(XElement dictionary)
    {
        if (dictionary.Name.LocalName != "dict") throw new InvalidDataException("Ожидался plist-словарь.");
        var elements = dictionary.Elements().ToArray();
        if (elements.Length % 2 != 0) throw new InvalidDataException("Повреждён plist-словарь профиля.");
        var result = new Dictionary<string, XElement>(StringComparer.Ordinal);
        for (var i = 0; i < elements.Length; i += 2)
            if (elements[i].Name.LocalName != "key" || !result.TryAdd(elements[i].Value, elements[i + 1]))
                throw new InvalidDataException("Повторяющийся или некорректный ключ в профиле.");
        return result;
    }
    private static XElement Required(Dictionary<string, XElement> dictionary, string key) => dictionary.TryGetValue(key, out var value)
        ? value : throw new InvalidDataException($"В профиле отсутствует {key}.");
    private static string ReadString(Dictionary<string, XElement> dictionary, string key)
    {
        var value = Required(dictionary, key);
        return value.Name.LocalName == "string" && !string.IsNullOrWhiteSpace(value.Value)
            ? value.Value : throw new InvalidDataException($"В профиле неверное значение {key}.");
    }
    private static string[] ReadStrings(XElement array)
    {
        if (array.Name.LocalName != "array" || array.Elements().Any(e => e.Name.LocalName != "string" || string.IsNullOrWhiteSpace(e.Value)))
            throw new InvalidDataException("Некорректный список в профиле.");
        return array.Elements().Select(e => e.Value).ToArray();
    }
    private static DateTimeOffset ReadDate(Dictionary<string, XElement> dictionary, string key) => ParseDate(Required(dictionary, key));
    private static DateTimeOffset ParseDate(XElement value) => value.Name.LocalName == "date"
        && DateTimeOffset.TryParse(value.Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var result)
            ? result : throw new InvalidDataException("В профиле неверная дата.");
    private static byte[] ReadLimitedFile(string path)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length is 0 or > MaximumMaterialBytes) throw new InvalidDataException("Размер сертификата или профиля недопустим (максимум 16 МБ).");
        var bytes = new byte[(int)input.Length];
        input.ReadExactly(bytes);
        return bytes;
    }
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        CryptographicOperations.ZeroMemory(_p12);
        CryptographicOperations.ZeroMemory(_profile);
        // Managed strings cannot be reliably zeroed; the password is never written to disk or command lines.
    }
}
