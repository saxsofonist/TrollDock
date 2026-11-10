using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace TrollDock.Services;

public sealed class AppSettings
{
    public string Username { get; set; } = "root";
    public string EncryptedPassword { get; set; } = "";
    public string LastSerial { get; set; } = "";
    public Dictionary<string, string> HostKeys { get; set; } = new();
    public string StartupMode { get; set; } = "trollstore";
    public List<string> ModeOrder { get; set; } = ["trollstore", "deb", "certificate"];
    public static string SettingsPath => Path.Combine(AppContext.BaseDirectory, "data", "settings.json");
    public static AppSettings Load()
    {
        if (!File.Exists(SettingsPath)) return new();
        var settings = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath))
            ?? throw new IOException("Не удалось прочитать настройки TrollDock.");
        settings.NormalizeModes();
        return settings;
    }
    public void Save()
    {
        NormalizeModes();
        Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
        var temporary = SettingsPath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temporary, SettingsPath, true);
    }
    public void NormalizeModes()
    {
        string[] known = ["trollstore", "deb", "certificate"];
        ModeOrder = (ModeOrder ?? []).Where(known.Contains).Distinct().Concat(known).Distinct().ToList();
        if (!known.Contains(StartupMode)) StartupMode = ModeOrder[0];
        HostKeys ??= new();
    }
    public string ReadPassword() => string.IsNullOrEmpty(EncryptedPassword) ? "" : Encoding.UTF8.GetString(Dpapi(Convert.FromBase64String(EncryptedPassword), false));
    public void SetPassword(string password, bool remember) => EncryptedPassword = remember ? Convert.ToBase64String(Dpapi(Encoding.UTF8.GetBytes(password), true)) : "";
    public void VerifyHostKey(string identity, byte[] key)
    {
        var fingerprint = "SHA256:" + Convert.ToBase64String(SHA256.HashData(key)).TrimEnd('=');
        lock (HostKeys)
        {
            if (HostKeys.TryGetValue(identity, out var known) && known != fingerprint)
                throw new IOException("SSH-ключ устройства изменился. Подключение остановлено. Если OpenSSH переустановлен, закройте программу и удалите старую запись HostKeys в data/settings.json.");
            if (!HostKeys.ContainsKey(identity)) { HostKeys[identity] = fingerprint; Save(); }
        }
    }
    [StructLayout(LayoutKind.Sequential)] private struct Blob { public int Length; public IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool CryptProtectData(ref Blob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true)] private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, uint flags, out Blob output);
    [DllImport("kernel32.dll")] private static extern IntPtr LocalFree(IntPtr pointer);
    private static byte[] Dpapi(byte[] bytes, bool protect)
    {
        var input = new Blob { Length = bytes.Length, Data = Marshal.AllocHGlobal(bytes.Length) };
        try
        {
            Marshal.Copy(bytes, 0, input.Data, bytes.Length);
            Blob output;
            var ok = protect ? CryptProtectData(ref input, "TrollDock", IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "Не удалось обработать сохранённый пароль Windows.");
            try { var result = new byte[output.Length]; Marshal.Copy(output.Data, result, 0, result.Length); return result; }
            finally { LocalFree(output.Data); }
        }
        finally { Marshal.FreeHGlobal(input.Data); CryptographicOperations.ZeroMemory(bytes); }
    }
}
