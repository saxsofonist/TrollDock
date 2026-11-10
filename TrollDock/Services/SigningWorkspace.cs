using System.Security.AccessControl;
using System.Security.Principal;

namespace TrollDock.Services;

/// <summary>App-owned staging only. Direct deletion never uses the Windows Recycle Bin.</summary>
public sealed class SigningWorkspace : IDisposable
{
    private const string Marker = ".trolldock-signing-job";
    private FileStream? lease;
    public string DirectoryPath { get; }
    public static string DefaultRoot => Path.Combine(AppContext.BaseDirectory, "data", "signing-jobs");
    public SigningWorkspace(string? root = null)
    {
        root = Path.GetFullPath(root ?? DefaultRoot);
        Directory.CreateDirectory(root); EnsureOrdinaryDirectory(root);
        DirectoryPath = Path.Combine(root, "job-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(DirectoryPath);
        try
        {
            if (OperatingSystem.IsWindows())
            {
                var security = new DirectorySecurity(); security.SetAccessRuleProtection(true, false);
                security.AddAccessRule(new FileSystemAccessRule(WindowsIdentity.GetCurrent().User!, FileSystemRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
                new DirectoryInfo(DirectoryPath).SetAccessControl(security);
            }
            File.WriteAllText(Path.Combine(DirectoryPath, Marker), "TrollDock signing workspace v1");
            lease = new FileStream(Path.Combine(DirectoryPath, ".lock"), FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None);
        }
        catch { Directory.Delete(DirectoryPath, true); throw; }
    }
    public string FilePath(string filename)
    {
        if (Path.GetFileName(filename) != filename || filename is "." or "..") throw new ArgumentException("Invalid staging filename.");
        return Path.Combine(DirectoryPath, filename);
    }
    public void Dispose()
    {
        lease?.Dispose(); lease = null;
        DeleteOwnedDirectory(DirectoryPath);
    }
    public static IReadOnlyList<string> CleanupAbandoned(string? root = null)
    {
        var failures = new List<string>(); root = Path.GetFullPath(root ?? DefaultRoot);
        if (!Directory.Exists(root)) return failures;
        EnsureOrdinaryDirectory(root);
        foreach (var directory in Directory.GetDirectories(root, "job-*", SearchOption.TopDirectoryOnly))
        {
            if (!IsOwnedJob(directory)) continue;
            try
            {
                using (new FileStream(Path.Combine(directory, ".lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None)) { }
            }
            catch (IOException) { continue; } // Another running instance holds this workspace.
            try { DeleteOwnedDirectory(directory); }
            catch { failures.Add(directory); }
        }
        return failures;
    }
    private static bool IsOwnedJob(string directory) => Path.GetFileName(directory).StartsWith("job-", StringComparison.Ordinal)
        && Guid.TryParseExact(Path.GetFileName(directory)[4..], "N", out _)
        && !new DirectoryInfo(directory).Attributes.HasFlag(FileAttributes.ReparsePoint)
        && File.Exists(Path.Combine(directory, Marker));
    private static void EnsureOrdinaryDirectory(string directory)
    {
        for (var info = new DirectoryInfo(directory); info != null; info = info.Parent)
            if (info.Attributes.HasFlag(FileAttributes.ReparsePoint)) throw new IOException("Папка временной подписи не должна быть ссылкой или перенаправлением.");
    }
    private static void DeleteOwnedDirectory(string directory)
    {
        if (!Directory.Exists(directory)) return;
        EnsureOrdinaryDirectory(directory);
        if (!IsOwnedJob(directory)) throw new IOException("Отказ удаления: папка не принадлежит операции подписи TrollDock.");
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                DeleteContents(directory, true);
                File.Delete(Path.Combine(directory, Marker));
                try { Directory.Delete(directory); return; }
                catch { if (Directory.Exists(directory)) File.WriteAllText(Path.Combine(directory, Marker), "TrollDock signing workspace v1"); throw; }
            }
            catch (Exception ex) when ((ex is IOException or UnauthorizedAccessException) && attempt < 5) { Thread.Sleep(200 * (attempt + 1)); }
        }
    }
    private static void DeleteContents(string directory, bool preserveMarker = false)
    {
        foreach (var file in Directory.GetFiles(directory))
        {
            if (preserveMarker && Path.GetFileName(file) == Marker) continue;
            // Delete the link itself. Do not change attributes through a file reparse point.
            if (!File.GetAttributes(file).HasFlag(FileAttributes.ReparsePoint)) File.SetAttributes(file, FileAttributes.Normal);
            File.Delete(file);
        }
        foreach (var child in Directory.GetDirectories(directory))
        {
            var attributes = File.GetAttributes(child);
            if (!attributes.HasFlag(FileAttributes.ReparsePoint)) DeleteContents(child);
            Directory.Delete(child);
        }
    }
}
