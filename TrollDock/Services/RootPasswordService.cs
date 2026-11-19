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

/// <summary>Runs the bootstrap pw utility over SSH stdin, then verifies a fresh root login.
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
        // Dopamine uses bootstrap pw usermod -h 0 to set passwords without PAM's old-password
        // conversation. Keep rootless helpers together: never change the rootful database
        // merely because a rootless helper is absent. SSH exec also avoids zsh first-run menus.
        var privileged = "PATH=/var/jb/usr/sbin:/var/jb/usr/bin:/var/jb/sbin:/var/jb/bin:/usr/sbin:/usr/bin:/sbin:/bin; export PATH; LC_ALL=C; export LC_ALL; "
            + "if [ \"$(id -u)\" != 0 ] || [ \"$(id -ru)\" != 0 ]; then printf '%s\\n' '" + marker + "NOT_ROOT__'; exit 71; fi; "
            + "if [ -d /var/jb ]; then P=/var/jb/usr/sbin/pw; else P=/usr/sbin/pw; fi; "
            + "if [ ! -x \"$P\" ]; then printf '%s\\n' '" + marker + "NO_PW__'; exit 72; fi; "
            + "printf '%s\\n' '" + marker + "READY_PW__'; "
            // pw reads its input with one read(). Buffer a complete SSH line before feeding
            // the short password through a local pipe; shell read -r preserves literal bytes.
            + "IFS= read -r NEW_ROOT || exit 74; printf '%s\\n' \"$NEW_ROOT\" | \"$P\" usermod root -h 0; RESULT=$?; unset NEW_ROOT; exit \"$RESULT\"";
        return "if [ -d /var/jb ]; then S=/var/jb/bin/sh; U=/var/jb/usr/bin/sudo; else S=/bin/sh; U=/usr/bin/sudo; fi; "
            + "[ -x \"$S\" ] && [ -x \"$U\" ] || exit 73; "
            + "LC_ALL=C; export LC_ALL; exec \"$U\" -S -k -u root -p '" + marker + "SUDO_%p__' -- \"$S\" -c " + Quote(privileged);
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
        string[] pending = ["", ""]; bool ready = false, sudoSent = false;
        try
        {
            for (;;)
            {
                if (!ready) token.ThrowIfCancellationRequested();
                using var readToken = !ready ? CancellationTokenSource.CreateLinkedTokenSource(token, lifetime.Token) : CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
                if (!await messages.Reader.WaitToReadAsync(readToken.Token)) break;
                while (messages.Reader.TryRead(out var message))
                {
                    pending[message.Source] += message.Text;
                    Match sudo;
                    while ((sudo = Regex.Match(pending[message.Source], Regex.Escape(marker) + "SUDO_([^_\\r\\n]+)__")).Success)
                    {
                        if (ready || sudoSent || sudo.Groups[1].Value != "mobile")
                            throw new RootPasswordProtocolException("sudo не принял пароль mobile или требует пароль другой учётной записи. Настройка остановлена.");
                        sudoSent = true;
                        await WriteSecretAsync(channel.Input, mobilePassword, readToken.Token);
                        pending[message.Source] = pending[message.Source].Remove(sudo.Index, sudo.Length);
                    }
                    if (pending[message.Source].Contains(marker + "NO_PW__", StringComparison.Ordinal))
                        throw new RootPasswordProtocolException("В bootstrap jailbreak не найдена утилита pw. Проверьте пакет system-cmds в Sileo или Zebra; новый пароль root не передавался.");
                    if (pending[message.Source].Contains(marker + "NOT_ROOT__", StringComparison.Ordinal))
                        throw new RootPasswordProtocolException("sudo не подтвердил полный доступ root. Проверьте права mobile; новый пароль root не передавался.");
                    int readyAt;
                    while ((readyAt = pending[message.Source].IndexOf(marker + "READY_PW__", StringComparison.Ordinal)) >= 0)
                    {
                        if (ready) throw new RootPasswordProtocolException("Утилита повторно запросила пароль. Автоматическая повторная смена остановлена; проверьте вход с новым паролем.");
                        token.ThrowIfCancellationRequested();
                        ready = true;
                        mutationStarting();
                        await WriteSecretAsync(channel.Input, newRootPassword, lifetime.Token);
                        pending[message.Source] = pending[message.Source].Remove(readyAt, marker.Length + "READY_PW__".Length);
                    }
                }
            }
            await channel.Completion.WaitAsync(lifetime.Token);
            if (!ready || channel.ExitCode != 0)
                throw new RootPasswordProtocolException(!ready
                    ? "sudo не разрешил смену пароля либо утилиты bootstrap недоступны. Проверьте права mobile и активность jailbreak."
                    : "Утилита pw не подтвердила смену пароля. Проверьте вход с новым паролем.");
            // Exit status alone is not proof of a usable password. Only a new root SSH
            // authentication followed by UID 0 confirms the result.
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
