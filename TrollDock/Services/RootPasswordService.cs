using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Renci.SshNet;
using Renci.SshNet.Common;
using TrollDock.Transport;

namespace TrollDock.Services;

public sealed record RootPasswordProgress(string Stage, string Detail, bool CanCancel);
public sealed record RootPasswordResult(bool Verified, bool PasswordChanged, string Message, bool MayHaveChanged = false);

/// <summary>Runs the system passwd utility over SSH stdin, then verifies a fresh root login.
/// No secret is interpolated into a command, written to disk, or included in diagnostics.</summary>
public sealed class RootPasswordService
{
    private readonly AppSettings settings;
    private readonly Func<string, int, string, string, Action<byte[]>, CancellationToken, Task<IRootPasswordSsh>> connect;
    public RootPasswordService(AppSettings settings) : this(settings, ConnectSshAsync) { }
    internal RootPasswordService(AppSettings settings,
        Func<string, int, string, string, Action<byte[]>, CancellationToken, Task<IRootPasswordSsh>> connect)
    { this.settings = settings; this.connect = connect; }

    public static void ValidatePasswords(string mobilePassword, string newRootPassword)
    {
        if (string.IsNullOrEmpty(mobilePassword) || Encoding.UTF8.GetByteCount(mobilePassword) > 1024 || mobilePassword.Any(char.IsControl))
            throw new ArgumentException("Введите пароль mobile без переводов строки и управляющих символов.");
        if (string.IsNullOrEmpty(newRootPassword) || Encoding.UTF8.GetByteCount(newRootPassword) > 128 || newRootPassword.Any(char.IsControl))
            throw new ArgumentException("Введите новый пароль root: не более 128 байт UTF-8, без управляющих символов.");
    }

    public async Task<RootPasswordResult> SetAsync(ConnectionOptions mobileOptions, string newRootPassword,
        IProgress<RootPasswordProgress> progress, CancellationToken cancellationToken = default)
    {
        ValidatePasswords(mobileOptions.Password, newRootPassword);
        if (mobileOptions.Username != "mobile") throw new ArgumentException("Для настройки root используйте учётную запись mobile.");
        UsbSshTunnel? tunnel = null;
        var host = mobileOptions.Host; var port = mobileOptions.Port;
        string identity;
        byte[]? sessionKey = null;
        bool mayHaveChanged = false;
        void Trust(byte[] key)
        {
            if (sessionKey != null && !CryptographicOperations.FixedTimeEquals(sessionKey, key))
                throw new RootPasswordProtocolException("SSH-ключ изменился между входами mobile и root. Проверка остановлена.");
            settings.VerifyHostKey(identity, key);
            sessionKey ??= key.ToArray();
        }
        identity = mobileOptions.AutoUsb ? "usb:" + mobileOptions.Device?.SerialNumber : $"tunnel:{host}:{port}";
        try
        {
            cancellationToken.ThrowIfCancellationRequested();
            progress.Report(new("Подключение mobile", "Открываю SSH к выбранному iPhone…", true));
            if (mobileOptions.AutoUsb)
            {
                var device = mobileOptions.Device ?? throw new RootPasswordProtocolException("Выберите подключённый iPhone.");
                tunnel = new UsbSshTunnel(new UsbMuxClient(), device, 22);
                await tunnel.StartAsync();
                host = "127.0.0.1"; port = tunnel.LocalPort;
            }
            else if (port is < 1 or > 65535 || !IPAddress.TryParse(host, out var address) || !IPAddress.IsLoopback(address))
                throw new RootPasswordProtocolException("Для готового SSH-туннеля нужны локальный адрес и корректный порт.");

            using var mobile = await connect(host, port, "mobile", mobileOptions.Password, Trust, cancellationToken);
            if ((await mobile.ReadCommandAsync("id -un", cancellationToken)).Trim() != "mobile")
                throw new RootPasswordProtocolException("SSH-сеанс не подтвердил вход под mobile.");
            var marker = "__TROLLDOCK_" + Guid.NewGuid().ToString("N") + "_";
            progress.Report(new("Проверка sudo", "Проверяю возможность задать пароль root…", true));
            using var channel = mobile.StartCommand(BuildCommand(marker));
            string? changeError = null;
            try
            {
                await RootPasswordConversation.RunAsync(channel, marker, mobileOptions.Password, newRootPassword, () =>
                {
                    mayHaveChanged = true;
                    progress.Report(new("Настройка root", "Передаю новый пароль системной утилите. Дождитесь проверки входа.", false));
                }, cancellationToken);
            }
            catch (Exception ex) when (mayHaveChanged)
            {
                // Lost acknowledgement cannot prove the account remained unchanged.
                changeError = ex is RootPasswordProtocolException ? ex.Message : "Ответ утилиты смены пароля не получен полностью.";
            }
            if (!mayHaveChanged) throw new RootPasswordProtocolException("Новый пароль не был передан. Изменение не выполнено.");
            progress.Report(new("Проверка root", "Открываю отдельное SSH-соединение с новым паролем и проверяю UID 0…", false));
            try
            {
                using var root = await connect(host, port, "root", newRootPassword, Trust, CancellationToken.None);
                if ((await root.ReadCommandAsync("id -u", CancellationToken.None)).Trim() != "0")
                    throw new RootPasswordProtocolException("Проверка UID 0 не пройдена.");
                return new(true, true, "Пароль root задан. Отдельный вход по SSH и права root подтверждены.");
            }
            catch
            {
                return new(false, false,
                    "Новый пароль передан, но вход под root не подтверждён. Пароль мог измениться. Проверьте SSH с новым паролем; автоматически повторять смену не нужно."
                    + (changeError == null ? "" : " " + changeError), true);
            }
        }
        catch (OperationCanceledException) when (!mayHaveChanged) { throw; }
        catch (RootPasswordProtocolException ex) { return new(false, false, ex.Message, mayHaveChanged); }
        catch (SshAuthenticationException) { return new(false, false, "Не удалось войти под mobile. Проверьте его пароль и активность jailbreak.", mayHaveChanged); }
        catch (Exception)
        {
            return new(false, false, mayHaveChanged
                ? "Соединение прервалось после передачи нового пароля. Он мог измениться; проверьте вход под root с новым паролем."
                : "Не удалось выполнить настройку. Проверьте USB, активность jailbreak и OpenSSH; пароль root не передавался.", mayHaveChanged);
        }
        finally { if (tunnel != null) await tunnel.DisposeAsync(); if (sessionKey != null) CryptographicOperations.ZeroMemory(sessionKey); }
    }

    internal static string BuildCommand(string marker)
    {
        if (!Regex.IsMatch(marker, "^__TROLLDOCK_[a-f0-9]{32}_$")) throw new ArgumentException("Invalid protocol marker.");
        // SSH exec does not start an interactive login shell, avoiding zsh first-run menus.
        // Procursus passwd uses OpenPAM's stdin fallback when no controlling terminal exists.
        var privileged = "PATH=/var/jb/usr/bin:/var/jb/bin:/usr/bin:/bin; export PATH; LC_ALL=C; export LC_ALL; "
            + "[ \"$(id -u)\" = 0 ] || exit 71; "
            + "if [ -x /var/jb/usr/bin/passwd ]; then P=/var/jb/usr/bin/passwd; elif [ -x /usr/bin/passwd ]; then P=/usr/bin/passwd; else exit 72; fi; "
            + "printf '%s\\n' '" + marker + "READY__'; exec \"$P\" root";
        return "if [ -x /var/jb/bin/sh ]; then S=/var/jb/bin/sh; else S=/bin/sh; fi; "
            + "if [ -x /var/jb/usr/bin/sudo ]; then U=/var/jb/usr/bin/sudo; elif [ -x /usr/bin/sudo ]; then U=/usr/bin/sudo; else exit 73; fi; "
            + "LC_ALL=C; export LC_ALL; exec \"$U\" -S -k -p '" + marker + "SUDO_%p__' -- \"$S\" -c " + Quote(privileged);
    }
    private static string Quote(string value) => "'" + value.Replace("'", "'\"'\"'") + "'";
    private static async Task<IRootPasswordSsh> ConnectSshAsync(string host, int port, string username, string password, Action<byte[]> trust, CancellationToken token)
    {
        var ssh = new SshClient(host, port, username, password);
        ssh.ConnectionInfo.Timeout = TimeSpan.FromSeconds(15);
        ssh.KeepAliveInterval = TimeSpan.FromSeconds(10);
        Exception? keyError = null;
        ssh.HostKeyReceived += (_, args) =>
        {
            try { trust(args.HostKey); args.CanTrust = true; }
            catch { keyError = new RootPasswordProtocolException("SSH-ключ устройства не совпадает с сохранённым. Подтвердите правильный iPhone и его ключ; старый ключ автоматически не удаляется."); args.CanTrust = false; }
        };
        try { await ssh.ConnectAsync(token); return new SshAdapter(ssh); }
        catch { ssh.Dispose(); if (keyError != null) throw keyError; throw; }
    }
    private sealed class SshAdapter(SshClient client) : IRootPasswordSsh
    {
        public async Task<string> ReadCommandAsync(string command, CancellationToken token)
        {
            using var operation = client.CreateCommand(command);
            operation.CommandTimeout = TimeSpan.FromSeconds(15);
            await operation.ExecuteAsync(token);
            if (operation.ExitStatus != 0) throw new RootPasswordProtocolException("Не удалось проверить учётную запись на iPhone.");
            return operation.Result;
        }
        public IRootPasswordChannel StartCommand(string command) => new SshChannel(client.CreateCommand(command));
        public void Dispose() => client.Dispose();
    }
    private sealed class SshChannel : IRootPasswordChannel
    {
        private readonly SshCommand command;
        public SshChannel(SshCommand command)
        {
            this.command = command; command.CommandTimeout = TimeSpan.FromSeconds(90);
            Completion = command.ExecuteAsync(); Input = command.CreateInputStream();
        }
        public Stream Input { get; }
        public Stream Output => command.OutputStream;
        public Stream Error => command.ExtendedOutputStream;
        public Task Completion { get; }
        public int? ExitCode => command.ExitStatus;
        public void Abort() { try { command.CancelAsync(false, 500); } catch { } }
        public void Dispose() { Input.Dispose(); command.Dispose(); }
    }
}

internal interface IRootPasswordSsh : IDisposable
{
    Task<string> ReadCommandAsync(string command, CancellationToken token);
    IRootPasswordChannel StartCommand(string command);
}
internal interface IRootPasswordChannel : IDisposable
{
    Stream Input { get; }
    Stream Output { get; }
    Stream Error { get; }
    Task Completion { get; }
    int? ExitCode { get; }
    void Abort();
}
internal sealed class RootPasswordProtocolException(string message) : IOException(message);

internal static class RootPasswordConversation
{
    internal static async Task RunAsync(IRootPasswordChannel channel, string marker, string mobilePassword, string newRootPassword,
        Action mutationStarting, CancellationToken token, TimeSpan? timeout = null)
    {
        var messages = Channel.CreateUnbounded<(int Source, string Text)>();
        using var lifetime = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(75));
        var total = 0;
        async Task Pump(Stream stream, int source)
        {
            var buffer = new byte[1024]; var decoder = Encoding.UTF8.GetDecoder(); var chars = new char[1024];
            for (;;)
            {
                var read = await stream.ReadAsync(buffer, lifetime.Token);
                if (read == 0) break;
                if (Interlocked.Add(ref total, read) > 32768) throw new RootPasswordProtocolException("Неожиданный объём ответа утилиты. Настройка остановлена.");
                var count = decoder.GetChars(buffer, 0, read, chars, 0, false);
                await messages.Writer.WriteAsync((source, new string(chars, 0, count)), lifetime.Token);
            }
        }
        var pumps = Task.WhenAll(Task.Run(() => Pump(channel.Output, 0)), Task.Run(() => Pump(channel.Error, 1)));
        _ = pumps.ContinueWith(task => messages.Writer.TryComplete(task.Exception), TaskScheduler.Default);
        string[] pending = ["", ""]; bool ready = false, sudoSent = false; int newPasswordCount = 0;
        var prompt = new Regex(@"(?:retype|repeat|confirm)\s+(?:the\s+)?(?:new\s+)?password\s*:|new\s+password\s*:|(?:old|current)(?:\s+unix)?\s+password\s*:", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        try
        {
            for (;;)
            {
                if (newPasswordCount == 0) token.ThrowIfCancellationRequested();
                using var readToken = newPasswordCount == 0 ? CancellationTokenSource.CreateLinkedTokenSource(token, lifetime.Token) : CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                if (!await messages.Reader.WaitToReadAsync(readToken.Token)) break;
                while (messages.Reader.TryRead(out var message))
                {
                    pending[message.Source] += message.Text;
                    var sudo = Regex.Match(pending[message.Source], Regex.Escape(marker) + "SUDO_([^_\\r\\n]+)__");
                    if (sudo.Success)
                    {
                        if (ready || sudoSent || sudo.Groups[1].Value != "mobile")
                            throw new RootPasswordProtocolException("sudo не принял пароль mobile или требует пароль другой учётной записи. Настройка остановлена.");
                        sudoSent = true;
                        await WriteSecretAsync(channel.Input, mobilePassword, readToken.Token);
                        pending[message.Source] = pending[message.Source].Remove(sudo.Index, sudo.Length);
                    }
                    var readyAt = pending[message.Source].IndexOf(marker + "READY__", StringComparison.Ordinal);
                    if (readyAt >= 0)
                    {
                        ready = true;
                        pending[message.Source] = pending[message.Source].Remove(readyAt, marker.Length + "READY__".Length);
                    }
                    // stdout and stderr readers can deliver out of order. Keep each byte stream
                    // separate and retain early prompts until the privileged READY marker arrives.
                    if (!ready) continue;
                    for (var source = 0; source < pending.Length; source++)
                    {
                      Match match;
                      while ((match = prompt.Match(pending[source])).Success)
                      {
                        var value = match.Value.ToLowerInvariant();
                        if (value.StartsWith("old") || value.StartsWith("current"))
                            throw new RootPasswordProtocolException("Системная утилита требует текущий пароль root. Эта операция предназначена для настройки через sudo; выполните смену вручную или проверьте права mobile.");
                        var confirmation = value.StartsWith("retype") || value.StartsWith("repeat") || value.StartsWith("confirm");
                        if (newPasswordCount != (confirmation ? 1 : 0))
                            throw new RootPasswordProtocolException("Утилита не приняла новый пароль или запросила его повторно. Проверьте требования к паролю.");
                        if (newPasswordCount == 0) { token.ThrowIfCancellationRequested(); mutationStarting(); }
                        newPasswordCount++;
                        await WriteSecretAsync(channel.Input, newRootPassword, lifetime.Token);
                        pending[source] = pending[source][(match.Index + match.Length)..];
                      }
                    }
                }
            }
            await channel.Completion.WaitAsync(lifetime.Token);
            if (!ready || newPasswordCount != 2 || channel.ExitCode != 0)
                throw new RootPasswordProtocolException(!ready
                    ? "sudo не разрешил смену пароля либо системная утилита passwd недоступна. Проверьте права mobile и bootstrap jailbreak."
                    : "Утилита не подтвердила полный обмен паролем. Проверьте вход с новым паролем.");
            // Apple's passwd main can exit 0 even after a PAM error. A complete exchange is
            // not proof of mutation; only a new root SSH authentication + UID 0 confirms it.
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
        { throw new RootPasswordProtocolException("Время ожидания ответа утилиты истекло. Проверьте состояние SSH."); }
        finally
        {
            if (!channel.Completion.IsCompleted) channel.Abort();
            lifetime.Cancel();
            try { await pumps.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
        }
    }
    private static async Task WriteSecretAsync(Stream input, string value, CancellationToken token)
    {
        var bytes = Encoding.UTF8.GetBytes(value + "\n");
        try { await input.WriteAsync(bytes, token); await input.FlushAsync(token); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }
}
