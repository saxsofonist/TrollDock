using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace TrollDock.Services;

public sealed record SavedCertificateInfo(Guid Id, string Name, string Summary, DateTimeOffset ExpiresAt, bool Available = true);

/// <summary>Optional portable vault. Every saved record is DPAPI CurrentUser ciphertext;
/// copying it to another Windows account does not reveal the certificate or password.</summary>
public sealed class CertificateVault
{
    private readonly string _directory;
    private static readonly byte[] Magic = "TROLLDOCK-CERT-1\n"u8.ToArray();
    private const int MaximumRecordBytes = 64 * 1024 * 1024;
    public CertificateVault(string? directory = null) => _directory = Path.GetFullPath(directory
        ?? Path.Combine(AppContext.BaseDirectory, "data", "certificates"));

    public IReadOnlyList<SavedCertificateInfo> List()
    {
        if (!Directory.Exists(_directory)) return [];
        var entries = new List<SavedCertificateInfo>();
        foreach (var file in Directory.EnumerateFiles(_directory, "*.tdcert", SearchOption.TopDirectoryOnly))
        {
            if (!Guid.TryParseExact(Path.GetFileNameWithoutExtension(file), "N", out var id)) continue;
            try
            {
                using var record = Read(id);
                entries.Add(record.Info);
            }
            catch (Exception e) when (e is IOException or CryptographicException or Win32Exception or JsonException or UnauthorizedAccessException)
            { entries.Add(new(id, "Недоступный сертификат", "Не удалось расшифровать: другой пользователь Windows или повреждённый файл.", DateTimeOffset.MinValue, false)); }
        }
        return entries.OrderBy(e => e.Name, StringComparer.CurrentCultureIgnoreCase).ToArray();
    }

    public SavedCertificateInfo Save(string name, string p12Path, string profilePath, string password)
    {
        using var material = SigningMaterial.Load(p12Path, profilePath, password);
        return Save(name, material);
    }

    public SavedCertificateInfo Save(string name, SigningMaterial material)
    {
        ArgumentNullException.ThrowIfNull(material);
        name = (name ?? "").Trim();
        if (name.Length is 0 or > 80 || name.Any(char.IsControl))
            throw new ArgumentException("Введите имя сертификата от 1 до 80 символов.", nameof(name));
        if (List().Any(info => info.Name.Equals(name, StringComparison.OrdinalIgnoreCase)))
            throw new InvalidOperationException("Сертификат с таким именем уже сохранён. Выберите другое имя.");
        CreatePrivateDirectory(_directory);
        var id = Guid.NewGuid();
        var info = new SavedCertificateInfo(id, name, material.Metadata.Summary, material.Metadata.ExpiresAt);
        var record = new VaultRecord { Info = info, P12 = material.P12Bytes, Profile = material.ProfileBytes, Password = material.Password };
        var clear = JsonSerializer.SerializeToUtf8Bytes(record);
        byte[]? encrypted = null;
        var temporary = Path.Combine(_directory, id.ToString("N") + ".tmp");
        try
        {
            encrypted = Protect(clear, true);
            using (var stream = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            { stream.Write(Magic); stream.Write(encrypted); stream.Flush(true); }
            File.Move(temporary, RecordPath(id), false);
            return info;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clear);
            if (encrypted is not null) CryptographicOperations.ZeroMemory(encrypted);
            File.Delete(temporary);
        }
    }

    public SigningMaterial Load(Guid id)
    {
        using var record = Read(id);
        return SigningMaterial.Load(record.P12, record.Profile, record.Password);
    }

    public void Delete(Guid id) => File.Delete(RecordPath(id));

    private string RecordPath(Guid id)
    {
        if (id == Guid.Empty) throw new ArgumentException("Не выбран сохранённый сертификат.", nameof(id));
        return Path.Combine(_directory, id.ToString("N") + ".tdcert");
    }

    private VaultRecord Read(Guid id)
    {
        using var input = new FileStream(RecordPath(id), FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length <= Magic.Length || input.Length > MaximumRecordBytes)
            throw new InvalidDataException("Некорректный сохранённый сертификат.");
        Span<byte> prefix = stackalloc byte[Magic.Length];
        input.ReadExactly(prefix);
        if (!prefix.SequenceEqual(Magic)) throw new InvalidDataException("Неизвестный формат хранилища сертификатов.");
        var encrypted = new byte[checked((int)input.Length - Magic.Length)];
        input.ReadExactly(encrypted);
        var clear = Protect(encrypted, false);
        try
        {
            var record = JsonSerializer.Deserialize<VaultRecord>(clear) ?? throw new InvalidDataException("Пустой сохранённый сертификат.");
            if (record.Info.Id != id || record.P12.Length == 0 || record.Profile.Length == 0)
            { record.Dispose(); throw new InvalidDataException("Повреждён сохранённый сертификат."); }
            return record;
        }
        finally { CryptographicOperations.ZeroMemory(clear); CryptographicOperations.ZeroMemory(encrypted); }
    }

    internal static void CreatePrivateDirectory(string directory)
    {
        Directory.CreateDirectory(directory);
        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
            throw new IOException("Каталог сертификатов не может быть символической ссылкой.");
        var identity = WindowsIdentity.GetCurrent().User ?? throw new IOException("Не удалось определить пользователя Windows.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(identity, FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        new DirectoryInfo(directory).SetAccessControl(security);
    }

    private sealed class VaultRecord : IDisposable
    {
        public SavedCertificateInfo Info { get; set; } = new(Guid.Empty, "", "", DateTimeOffset.MinValue);
        public byte[] P12 { get; set; } = [];
        public byte[] Profile { get; set; } = [];
        public string Password { get; set; } = "";
        public void Dispose() { CryptographicOperations.ZeroMemory(P12); CryptographicOperations.ZeroMemory(Profile); Password = ""; }
    }

    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptProtectData(ref Blob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);
    private static byte[] Protect(byte[] bytes, bool encrypt)
    {
        var input = new Blob { Length = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
        try
        {
            Marshal.Copy(bytes, 0, input.Data, bytes.Length);
            Blob output;
            // CRYPTPROTECT_UI_FORBIDDEN, without LOCAL_MACHINE: encrypted only for CurrentUser.
            var ok = encrypt ? CryptProtectData(ref input, "TrollDock certificate", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), "Windows не смогла защитить или прочитать сертификат для текущего пользователя.");
            try
            {
                var result = new byte[output.Length];
                Marshal.Copy(output.Data, result, 0, result.Length);
                if (!encrypt) ZeroUnmanaged(output.Data, output.Length);
                return result;
            }
            finally { LocalFree(output.Data); }
        }
        finally { if (encrypt) ZeroUnmanaged(input.Data, input.Length); Marshal.FreeHGlobal(input.Data); }
    }
    private static void ZeroUnmanaged(IntPtr pointer, int length)
    {
        var zeros = new byte[Math.Min(length, 4096)];
        for (var offset = 0; offset < length; offset += zeros.Length)
            Marshal.Copy(zeros, 0, IntPtr.Add(pointer, offset), Math.Min(zeros.Length, length - offset));
    }
}
