namespace TrollDock.Services;

public interface ICertificateInstallTools
{
    Task VerifyToolsAsync(CancellationToken token);
    Task SignAsync(string input, string p12, string profile, string output, string job, Action<string> log, CancellationToken token, string? entitlementsPath = null);
    Task InstallAsync(string ipa, string udid, Action<string> log);
    Task<bool> VerifyInstalledAsync(string bundle, string udid);
}

public sealed class BundledCertificateTools(CertificateToolRunner? runner = null) : ICertificateInstallTools
{
    private readonly CertificateToolRunner tools = runner ?? new();
    public Task VerifyToolsAsync(CancellationToken token) => tools.VerifyToolsAsync(token);
    public Task SignAsync(string input, string p12, string profile, string output, string job, Action<string> log, CancellationToken token, string? entitlementsPath = null) => tools.SignAsync(input, p12, profile, output, job, log, token, entitlementsPath);
    public Task InstallAsync(string ipa, string udid, Action<string> log) => tools.InstallAsync(ipa, udid, log);
    public Task<bool> VerifyInstalledAsync(string bundle, string udid) => tools.VerifyInstalledAsync(bundle, udid);
}

public sealed class CertificateInstallWorkflow(ICertificateInstallTools? tools = null, string? stagingRoot = null)
{
    private readonly ICertificateInstallTools tools = tools ?? new BundledCertificateTools();
    public async Task InstallAsync(string originalIpa, SigningMaterial material, string udid,
        IProgress<TransferProgress> progress, Action<string> log, CancellationToken token)
    {
        progress.Report(new("Проверка сертификата", "Проверяю IPA, профиль и выбранный iPhone…", -1, true));
        material.CheckDevice(udid);
        var metadata = await Task.Run(() => IpaInspection.Read(originalIpa), token);
        await tools.VerifyToolsAsync(token);
        token.ThrowIfCancellationRequested();
        SigningWorkspace? workspace = null; bool installed = false; Exception? operationFailure = null; string? cleanupFailure = null;
        string finalDetail = "Приложение установлено. Подписанная временная IPA удалена без корзины. Исходная IPA сохранена.";
        try
        {
            workspace = new SigningWorkspace(stagingRoot);
            var input = workspace.FilePath("input.ipa"); var signed = workspace.FilePath("signed.ipa");
            await using (var original = new FileStream(originalIpa, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                var drive = new DriveInfo(Path.GetPathRoot(workspace.DirectoryPath)!);
                var required = checked(original.Length * 3 + metadata.UnpackedBytes * 2 + 100_000_000);
                if (drive.AvailableFreeSpace < required) throw new IOException("На ПК мало свободного места для рабочей копии, распаковки и подписи IPA.");
                progress.Report(new("Подготовка IPA", "Создаю временную рабочую копию. Исходный файл остаётся нетронутым.", -1, true));
                await using var copy = new FileStream(input, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, FileOptions.Asynchronous);
                await original.CopyToAsync(copy, token);
            }
            var files = material.WriteToDirectory(workspace.DirectoryPath);
            progress.Report(new("Подпись IPA", "Подписываю приложение выбранным сертификатом…", -1, true));
            // The signer preserves IPA bundle IDs and derives signing entitlements from the
            // profile. An explicit application-identifier need not equal CFBundleIdentifier.
            await tools.SignAsync(input, files.P12Path, files.ProfilePath, signed, workspace.DirectoryPath, log, token);
            var signedMetadata = await Task.Run(() => IpaInspection.Read(signed), token);
            if (signedMetadata.BundleIdentifier != metadata.BundleIdentifier || signedMetadata.Version != metadata.Version
                || !signedMetadata.ExtensionIdentifiers.Order().SequenceEqual(metadata.ExtensionIdentifiers.Order()))
                throw new IOException("После подписи неожиданно изменились идентификаторы или версия приложения.");
            token.ThrowIfCancellationRequested();
            progress.Report(new("Установка по USB", "iPhone устанавливает подписанное приложение. Дождитесь завершения.", -1, false));
            await tools.InstallAsync(signed, udid, log);
            installed = true;
            try
            {
                if (!await tools.VerifyInstalledAsync(metadata.BundleIdentifier, udid))
                    finalDetail = "iPhone подтвердил установку, но приложение пока не найдено в списке. Проверьте экран iPhone. Временная IPA удалена без корзины.";
            }
            catch (Exception ex)
            {
                log("Установка подтверждена, дополнительная проверка недоступна: " + ex.Message);
                finalDetail = "iPhone подтвердил установку. Проверьте приложение на экране: получить список приложений не удалось. Временная IPA удалена без корзины.";
            }
        }
        catch (Exception ex) { operationFailure = ex; }
        finally
        {
            if (workspace != null)
            {
                progress.Report(new("Очистка временных файлов", "Удаляю подписанную IPA и временные данные сертификата без корзины…", -1, false));
                try { await Task.Run(workspace.Dispose); log("Подписанная IPA и временные файлы удалены напрямую, без корзины."); }
                catch (Exception ex) { cleanupFailure = workspace.DirectoryPath; log("Не удалось удалить временную папку " + cleanupFailure + ": " + ex.Message); }
            }
        }
        if (cleanupFailure != null)
            throw new IOException((installed ? "Приложение установлено, но " : "Операция не завершена; ") + "Windows не дал удалить временные файлы. Закройте программу, блокирующую папку, и перезапустите TrollDock для повторной очистки: " + cleanupFailure, operationFailure);
        if (operationFailure != null) System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(operationFailure).Throw();
        progress.Report(new("Установлено", finalDetail, 100, false));
    }
}
