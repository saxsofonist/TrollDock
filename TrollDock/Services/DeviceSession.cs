using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Renci.SshNet;
using TrollDock.Transport;

namespace TrollDock.Services;

public sealed record ConnectionOptions(UsbDevice? Device, bool AutoUsb, string Host, int Port, string Username, string Password);
public sealed record TransferProgress(string Stage, string Detail, double Percent, bool CanCancel);
public sealed class DeviceSession : IAsyncDisposable
{
    private readonly AppSettings settings;
    private readonly Action<string> log;
    private UsbSshTunnel? tunnel;
    private SshClient? ssh;
    private SftpClient? sftp;
    public string TrollStorePath { get; private set; } = "";
    public string Architecture { get; private set; } = "";
    public bool Connected => ssh?.IsConnected == true && sftp?.IsConnected == true;
    public DeviceSession(AppSettings settings, Action<string> log) { this.settings = settings; this.log = log; }

    public async Task ConnectAsync(ConnectionOptions options, CancellationToken token)
    {
        await DisposeAsync();
        string host = options.Host; int port = options.Port; string identity;
        if (options.AutoUsb)
        {
            token.ThrowIfCancellationRequested();
            var device = options.Device ?? throw new IOException("Выберите подключённый iPhone. Разблокируйте его и подтвердите доверие компьютеру.");
            tunnel = new UsbSshTunnel(new UsbMuxClient(), device, 22);
            tunnel.ConnectionFailed += ex => log("USB: " + ex.Message);
            // The tunnel belongs to this session, not to a later upload cancellation token.
            // ConnectAsync cancellation is handled by the SSH client and the catch below.
            await tunnel.StartAsync();
            host = "127.0.0.1"; port = tunnel.LocalPort; identity = "usb:" + device.SerialNumber;
            log("USB-туннель открыт программой.");
        }
        else
        {
            if (!IPAddress.TryParse(host, out var ip) || !IPAddress.IsLoopback(ip))
                throw new IOException("Для готового USB-туннеля укажите локальный адрес 127.0.0.1 или ::1.");
            identity = $"tunnel:{host}:{port}";
        }
        try
        {
            await Task.Run(async () =>
            {
                token.ThrowIfCancellationRequested();
                ssh = new SshClient(host, port, options.Username, options.Password);
                ssh.ConnectionInfo.Timeout = TimeSpan.FromSeconds(12);
                ssh.KeepAliveInterval = TimeSpan.FromSeconds(15);
                Exception? keyError = null;
                ssh.HostKeyReceived += (_, e) => { try { settings.VerifyHostKey(identity, e.HostKey); e.CanTrust = true; } catch (Exception ex) { keyError = ex; e.CanTrust = false; } };
                try { await ssh.ConnectAsync(token).ConfigureAwait(false); } catch when (keyError != null) { throw keyError; }
                token.ThrowIfCancellationRequested();
                var info = Run("id -u; uname -m; if [ -x /var/jb/usr/bin/dpkg ]; then /var/jb/usr/bin/dpkg --print-architecture; fi", 25, token);
                if (info.Output.Split('\n')[0].Trim() != "0") throw new IOException("Для установки нужен вход SSH под root. Укажите пользователя root и его пароль.");
                Architecture = info.Output.Trim();
                log("SSH подключён. Права root подтверждены.");
                var discovered = Run("find /var/containers/Bundle/Application /Applications /var/jb/Applications -type f -name trollstorehelper 2>/dev/null; :", 45, token);
                var paths = discovered.Output.Split('\n', StringSplitOptions.RemoveEmptyEntries)
                    .Select(s => s.Trim()).Where(s => s.StartsWith('/') && (s.EndsWith("/TrollStore.app/trollstorehelper") || s.EndsWith("/TrollStoreLite.app/trollstorehelper")) && !s.Contains('\r')).Distinct().ToList();
                if (paths.Count == 1) { TrollStorePath = paths[0]; log("TrollStore: " + TrollStorePath); }
                else if (paths.Count > 1) log("Найдено несколько TrollStore. IPA-установка остановится, чтобы не выбрать чужую копию.");
                else log("TrollStore не найден. Режим DEB остаётся доступен.");
                sftp = new SftpClient(host, port, options.Username, options.Password);
                sftp.ConnectionInfo.Timeout = TimeSpan.FromSeconds(12);
                sftp.OperationTimeout = TimeSpan.FromSeconds(45);
                sftp.KeepAliveInterval = TimeSpan.FromSeconds(15);
                sftp.HostKeyReceived += (_, e) => { try { settings.VerifyHostKey(identity, e.HostKey); e.CanTrust = true; } catch (Exception ex) { keyError = ex; e.CanTrust = false; } };
                try { await sftp.ConnectAsync(token).ConfigureAwait(false); } catch when (keyError != null) { throw keyError; }
                token.ThrowIfCancellationRequested();
            }, token);
        }
        catch { await DisposeAsync(); throw; }
    }

    public static void ValidateFile(string path, bool deb) => PackageFileValidator.Validate(path, deb);

    public async Task<DebBatchInstallResult> InstallDebBatchAsync(IReadOnlyList<string> paths, IProgress<TransferProgress> progress, CancellationToken token)
    {
        ArgumentNullException.ThrowIfNull(paths);
        if (!Connected) throw new IOException("Нет подключения к телефону.");
        if (paths.Count == 0) throw new ArgumentException("Выберите хотя бы один DEB-пакет.", nameof(paths));
        var localPaths = paths.Select(Path.GetFullPath).ToArray();
        if (localPaths.Distinct(StringComparer.OrdinalIgnoreCase).Count() != localPaths.Length)
            throw new IOException("В очереди повторяется один и тот же DEB-файл.");
        await Task.Run(() =>
        {
            foreach (var path in localPaths) { token.ThrowIfCancellationRequested(); ValidateFile(path, true); }
        }, token);
        var directory = "/var/mobile/Media/TrollDock-" + Guid.NewGuid().ToString("N");
        var remotePaths = localPaths.Select((_, index) => directory + "/package-" + index + ".deb").ToArray();
        bool created = false, installationStarted = false, installationCompleted = false;
        var files = new List<FileStream>();
        try
        {
            return await Task.Run(async () =>
            {
                token.ThrowIfCancellationRequested();
                // Read handles remain open for the entire batch, preventing modification
                // of source files while they are uploaded and checked.
                foreach (var path in localPaths) files.Add(File.OpenRead(path));
                var totalLength = files.Aggregate(0L, (sum, file) => checked(sum + file.Length));
                progress.Report(new("Проверка DEB", $"Проверяю место для {files.Count} пакетов…", 0, true));
                var space = Run("df -Pk /var/mobile/Media | tail -n 1", 20, token);
                var columns = Regex.Split(space.Output.Trim(), @"\s+");
                if (columns.Length >= 4 && long.TryParse(columns[3], out var availableKb) && availableKb < (totalLength * 2.0 + 100_000_000) / 1024)
                    throw new IOException("На iPhone мало свободного места для передачи и распаковки выбранных пакетов.");
                MustSucceed(Run("mkdir -m 755 " + Q(directory), 20, token));
                created = true;
                for (int index = 0; index < files.Count; index++)
                {
                    token.ThrowIfCancellationRequested();
                    var detail = $"{index + 1}/{files.Count} · {Path.GetFileName(localPaths[index])}";
                    await UploadAndVerifyAsync(files[index], remotePaths[index], detail, progress, token).ConfigureAwait(false);
                }
                token.ThrowIfCancellationRequested();
                progress.Report(new("Проверка DEB", "Проверяю архитектуру всех пакетов и общие зависимости…", -1, true));
                MustSucceed(Run(DebWorkflow.GetBatchPreflightScript(remotePaths), 300, token));
                token.ThrowIfCancellationRequested();
                progress.Report(new("Установка DEB", $"APT устанавливает {files.Count} пакетов одной операцией. Дождитесь завершения.", -1, false));
                installationStarted = true;
                // Cancellation must never interrupt an active dpkg/APT transaction.
                var result = Run(DebWorkflow.GetBatchInstallScript(remotePaths), 3600);
                installationCompleted = result.ExitCode >= 0;
                var batch = DebWorkflow.ParseBatchResult(localPaths, result.ExitCode, result.Output, result.Error);
                foreach (var item in batch.Items) log(Path.GetFileName(item.LocalPath) + ": " + item.Message);
                if (batch.Error != null) log(batch.Error);
                var installed = batch.Items.Count(item => item.Installed);
                progress.Report(new(batch.Success ? "Установлено" : "Проверка завершена",
                    $"Подтверждена установка: {installed} из {files.Count}. Respring можно выполнить отдельно.", 100, false));
                return batch;
            }, token);
        }
        finally
        {
            foreach (var file in files) file.Dispose();
            if (created && installationStarted && !installationCompleted)
                log("Результат установки DEB не получен. Временные файлы сохранены: " + directory + ". Проверьте состояние пакетов на iPhone перед повторной попыткой.");
            else if (created && ssh?.IsConnected == true)
                try
                {
                    await Task.Run(() => MustSucceed(Run("rm -f " + string.Join(" ", remotePaths.Select(Q)) + "; rmdir " + Q(directory), 30)));
                }
                catch (Exception ex) { log("Не удалось убрать временные DEB из " + directory + ": " + ex.Message); }
            else if (created)
                log("SSH-соединение потеряно: не удалось убрать временные DEB из " + directory + ".");
        }
    }

    private async Task UploadAndVerifyAsync(FileStream file, string remote, string detail, IProgress<TransferProgress> progress, CancellationToken token)
    {
        var fileLength = file.Length;
        progress.Report(new("Передача DEB", detail, 0, true));
        var watch = System.Diagnostics.Stopwatch.StartNew();
        long lastReport = -1000;
        var progressGate = new object();
        bool uploading = true;
        var uploadProgress = new InlineProgress<UploadFileProgressReport>(report =>
        {
            lock (progressGate)
            {
                if (!uploading || token.IsCancellationRequested) return;
                var bytes = report.TotalBytesUploaded;
                if (watch.ElapsedMilliseconds - lastReport < 150 && bytes < (ulong)fileLength) return;
                lastReport = watch.ElapsedMilliseconds;
                var speed = bytes / Math.Max(watch.Elapsed.TotalSeconds, .1) / 1048576;
                progress.Report(new("Передача DEB", $"{detail} · {bytes / 1048576.0:N1} / {fileLength / 1048576.0:N1} МБ · {speed:N1} МБ/с", 100.0 * bytes / fileLength, true));
            }
        });
        try { await sftp!.UploadFileAsync(file, remote, uploadProgress, token).ConfigureAwait(false); }
        catch (OperationCanceledException) { sftp?.Dispose(); sftp = null; throw; }
        finally { lock (progressGate) uploading = false; }
        token.ThrowIfCancellationRequested();
        if (sftp.GetAttributes(remote).Size != fileLength) throw new IOException("Передан не весь DEB-файл. Повторите установку.");
        MustSucceed(Run("chmod 644 " + Q(remote), 15, token));
        progress.Report(new("Проверка передачи", detail + " · сверяю SHA-256…", -1, true));
        file.Position = 0;
        var localHash = Convert.ToHexString(await SHA256.HashDataAsync(file, token).ConfigureAwait(false)).ToLowerInvariant();
        var hashResult = Run("PATH=/var/jb/usr/bin:/usr/bin:/bin:$PATH; if command -v sha256sum >/dev/null 2>&1; then sha256sum " + Q(remote) + "; elif command -v shasum >/dev/null 2>&1; then shasum -a 256 " + Q(remote) + "; else exit 127; fi", 180, token);
        if (hashResult.ExitCode == 127)
        {
            using var remoteStream = sftp.OpenRead(remote);
            var actual = Convert.ToHexString(await SHA256.HashDataAsync(remoteStream, token).ConfigureAwait(false)).ToLowerInvariant();
            if (actual != localHash) throw new IOException("Контрольная сумма DEB-файла на iPhone не совпала.");
        }
        else
        {
            MustSucceed(hashResult);
            if (!hashResult.Output.TrimStart().StartsWith(localHash, StringComparison.OrdinalIgnoreCase)) throw new IOException("Контрольная сумма DEB-файла на iPhone не совпала.");
        }
        log(detail + " · SHA-256 совпадает: " + localHash);
    }

    public async Task InstallAsync(string path, bool deb, IProgress<TransferProgress> progress, CancellationToken token)
    {
        if (!Connected) throw new IOException("Нет подключения к телефону.");
        await Task.Run(() => ValidateFile(path, deb), token);
        if (!deb && string.IsNullOrWhiteSpace(TrollStorePath)) throw new IOException("Не найден единственный TrollStore. Проверьте его установку на телефоне.");
        var directory = "/var/mobile/Media/TrollDock-" + Guid.NewGuid().ToString("N");
        var remote = directory + (deb ? "/package.deb" : "/package.ipa");
        bool created = false;
        bool installationStarted = false;
        bool installationCompleted = false;
        try
        {
            await Task.Run(async () =>
            {
                token.ThrowIfCancellationRequested();
                progress.Report(new("Проверка файла", "Проверяю свободное место на iPhone…", 0, true));
                using var file = File.OpenRead(path);
                var fileLength = file.Length;
                var space = Run("df -Pk /var/mobile/Media | tail -n 1", 20, token);
                var columns = Regex.Split(space.Output.Trim(), @"\s+");
                if (columns.Length >= 4 && long.TryParse(columns[3], out var availableKb) && availableKb * 1024 < fileLength * 2 + 100_000_000)
                    throw new IOException("На iPhone мало свободного места: нужны место для передачи и распаковки файла.");
                MustSucceed(Run("mkdir " + Q(directory) + " && chmod 755 " + Q(directory), 20)); created = true;
                progress.Report(new("Передача на iPhone", Path.GetFileName(path), 0, true));
                var watch = System.Diagnostics.Stopwatch.StartNew(); long lastReport = -1000;
                var progressGate = new object();
                bool uploading = true;
                var uploadProgress = new InlineProgress<UploadFileProgressReport>(report =>
                {
                    // SSH.NET invokes progress on its response thread. Never throw or
                    // reference a possibly disposed input stream from this callback.
                    lock (progressGate)
                    {
                        if (!uploading || token.IsCancellationRequested) return;
                        var bytes = report.TotalBytesUploaded;
                        if (watch.ElapsedMilliseconds - lastReport < 150 && bytes < (ulong)fileLength) return;
                        lastReport = watch.ElapsedMilliseconds;
                        var speed = bytes / Math.Max(watch.Elapsed.TotalSeconds, .1) / 1048576;
                        progress.Report(new("Передача на iPhone", $"{bytes / 1048576.0:N1} / {fileLength / 1048576.0:N1} МБ · {speed:N1} МБ/с", 100.0 * bytes / fileLength, true));
                    }
                });
                try { await sftp!.UploadFileAsync(file, remote, uploadProgress, token).ConfigureAwait(false); }
                catch (OperationCanceledException) { sftp?.Dispose(); sftp = null; throw; }
                finally { lock (progressGate) uploading = false; }
                token.ThrowIfCancellationRequested();
                if (sftp.GetAttributes(remote).Size != fileLength) throw new IOException("Передан не весь файл. Повторите установку.");
                MustSucceed(Run("chmod 644 " + Q(remote), 15, token));
                progress.Report(new("Проверка передачи", "Сверяю SHA-256 файла…", -1, true));
                file.Position = 0;
                var localHash = Convert.ToHexString(await SHA256.HashDataAsync(file, token).ConfigureAwait(false)).ToLowerInvariant();
                token.ThrowIfCancellationRequested();
                var hashResult = Run("PATH=/var/jb/usr/bin:/usr/bin:/bin:$PATH; if command -v sha256sum >/dev/null 2>&1; then sha256sum " + Q(remote) + "; elif command -v shasum >/dev/null 2>&1; then shasum -a 256 " + Q(remote) + "; else exit 127; fi", 180, token);
                if (hashResult.ExitCode == 127)
                {
                    using var remoteStream = sftp.OpenRead(remote);
                    var actual = Convert.ToHexString(await SHA256.HashDataAsync(remoteStream, token).ConfigureAwait(false)).ToLowerInvariant();
                    if (actual != localHash) throw new IOException("Контрольная сумма файла на iPhone не совпала.");
                }
                else
                {
                    MustSucceed(hashResult);
                    if (!hashResult.Output.TrimStart().StartsWith(localHash, StringComparison.OrdinalIgnoreCase)) throw new IOException("Контрольная сумма файла на iPhone не совпала.");
                }
                log("SHA-256 совпадает: " + localHash);
                token.ThrowIfCancellationRequested();
                if (deb)
                {
                    progress.Report(new("Проверка DEB", "Проверяю архитектуру и зависимости…", -1, true));
                    MustSucceed(Run(DebWorkflow.GetPreflightScript(remote), 180, token));
                }
                token.ThrowIfCancellationRequested();
                progress.Report(new("Установка", deb ? "APT устанавливает пакет и зависимости. Дождитесь завершения." : "TrollStore устанавливает приложение. Дождитесь завершения.", -1, false));
                installationStarted = true;
                // Once device-side mutation starts, cancellation is intentionally disabled.
                var result = deb ? Run(DebWorkflow.GetInstallScript(remote), 900)
                    : Run(Q(TrollStorePath) + " install " + Q(remote), 900);
                installationCompleted = result.ExitCode >= 0;
                string resultMessage;
                if (deb)
                {
                    MustSucceed(result);
                    resultMessage = "Пакет установлен. При необходимости нажмите «Перезапустить интерфейс».";
                }
                else
                {
                    if (!TrollStoreResults.IsInstalled(result.ExitCode)) throw new IOException(TrollStoreResults.FailureMessage(result.ExitCode));
                    resultMessage = TrollStoreResults.SuccessMessage(result.ExitCode);
                }
                log(deb ? "APT успешно завершил установку." : resultMessage);
                progress.Report(new("Установлено", resultMessage, 100, false));
            }, token);
        }
        finally
        {
            if (created && installationStarted && !installationCompleted)
                log("Результат установки не получен. Временный файл сохранён: " + remote + ". Проверьте состояние установки на iPhone перед повторной попыткой.");
            else if (created && ssh?.IsConnected == true)
                try { await Task.Run(() => MustSucceed(Run("rm -f " + Q(remote) + "; rmdir " + Q(directory), 20))); }
                catch (Exception ex) { log("Не удалось убрать временный файл " + remote + ": " + ex.Message); }
        }
    }

    public Task RespringAsync() => Task.Run(() => { if (!Connected) throw new IOException("Нет подключения."); MustSucceed(Run(DebWorkflow.GetRespringScript(), 45)); });
    private static string Q(string value) => DebWorkflow.Quote(value);
    private (int ExitCode, string Output, string Error) Run(string script, int timeout, CancellationToken token = default)
    {
        token.ThrowIfCancellationRequested();
        var prepared = "PATH=/var/jb/usr/sbin:/var/jb/usr/bin:/var/jb/sbin:/var/jb/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH; export PATH;\n" + script.Replace("\r\n", "\n");
        var argument = Q(prepared);
        using var command = ssh!.CreateCommand("if [ -x /var/jb/bin/sh ]; then exec /var/jb/bin/sh -c " + argument + "; else exec /bin/sh -c " + argument + "; fi");
        command.CommandTimeout = TimeSpan.FromSeconds(timeout);
        command.ExecuteAsync(token).GetAwaiter().GetResult();
        var output = command.Result;
        if (!string.IsNullOrWhiteSpace(output)) log(output.Length > 64000 ? output[^64000..] : output.TrimEnd());
        if (!string.IsNullOrWhiteSpace(command.Error)) log(command.Error.Length > 64000 ? command.Error[^64000..] : command.Error.TrimEnd());
        return (command.ExitStatus ?? -1, output, command.Error);
    }
    private sealed class InlineProgress<T>(Action<T> handler) : IProgress<T>
    {
        public void Report(T value)
        {
            // Keep observer exceptions out of the SSH protocol receive thread.
            try { handler(value); } catch { }
        }
    }
    private static void MustSucceed((int ExitCode, string Output, string Error) result)
    {
        if (result.ExitCode == 0) return;
        var message = (result.Error + "\n" + result.Output).Split('\n').LastOrDefault(s => s.StartsWith("TROLLDOCK_ERROR:"));
        if (message != null && message.Contains('|')) throw new IOException(message[(message.IndexOf('|') + 1)..]);
        throw new IOException($"Команда на iPhone завершилась с кодом {result.ExitCode}. Подробности — в журнале. Успешная установка не подтверждена.");
    }
    public async ValueTask DisposeAsync()
    {
        sftp?.Dispose(); sftp = null; ssh?.Dispose(); ssh = null;
        if (tunnel != null) { await tunnel.DisposeAsync(); tunnel = null; }
        TrollStorePath = "";
    }
}
