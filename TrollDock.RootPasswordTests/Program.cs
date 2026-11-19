using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using TrollDock.Services;
using TrollDock.Transport;

await Tests.Run();

static class Tests
{
    const string Marker = "__TROLLDOCK_0123456789abcdef0123456789abcdef_";
    internal const string Mobile = "mobile-'$()\";synthetic";
    internal const string Root = "root-'$()\";synthetic";
    static int passed;
    static void Check(bool value, string message) { if (!value) throw new Exception(message); }
    static async Task Test(string name, Func<Task> body) { await body().WaitAsync(TimeSpan.FromSeconds(8)); passed++; Console.WriteLine("PASS " + name); }
    static void Throws(Action body) { try { body(); throw new Exception("Expected rejection"); } catch (ArgumentException) { } }
    static async Task ProtocolFails(FakeChannel channel, Action mutation, CancellationToken token = default, int timeoutMs = 1000)
    {
        try { await RootPasswordConversation.RunAsync(channel, Marker, Mobile, Root, mutation, token, TimeSpan.FromMilliseconds(timeoutMs)); throw new Exception("Expected protocol rejection"); }
        catch (RootPasswordProtocolException) { }
    }
    static Task<RootPasswordResult> Run(ServiceFixture fixture, CancellationToken token = default) => fixture.Service.SetAsync(new(null, false, "127.0.0.1", 22222, "mobile", Mobile), Root, fixture.Progress, token);
    internal static FakeChannel Conversation(string marker, string mode = "success", Action? onFirstNew = null)
    {
        var c = new FakeChannel();
        var stage = mode == "nopasswd" ? 1 : 0;
        void Ready()
        {
            if (mode == "missing") { c.Stdout.Push(marker + "NO_PW__\n"); c.End(72); }
            else if (mode == "notroot") { c.Stdout.Push(marker + "NOT_ROOT__\n"); c.End(71); }
            else if (mode == "old") { c.Stdout.Push(marker + "READY__\nOld Password: "); c.End(1); }
            else if (mode == "reversed")
            {
                c.Stderr.Push("bootstrap diagnostic before readiness\n");
                _ = Task.Run(async () => { await Task.Delay(50); c.Stdout.Push(marker + "READY_PW__\n"); });
            }
            else { c.Stdout.Push(marker[..19]); c.Stdout.Push(marker[19..] + "READY_PW__\n"); }
        }
        c.OnInput = value =>
        {
            if (stage++ == 0)
            {
                Check(value == Mobile + "\n", "sudo did not receive mobile password only");
                if (mode == "wrongmobile") c.Stderr.Push("Sorry, try again.\n" + marker + "SUDO_mobile__");
                else Ready();
            }
            else if (stage == 2)
            {
                Check(value == Root + "\n", "new password missing"); onFirstNew?.Invoke();
                if (mode == "writefailed") throw new IOException("synthetic partial stdin failure " + value);
                if (mode == "reject") c.Stderr.Push("pw: update failed\n");
                if (mode == "duplicate") c.Stdout.Push(marker + "READY_PW__\n");
                c.End(mode is "lostack" or "reject" ? 1 : 0);
            }
            else throw new Exception("Secret sent more than once to pw");
        };
        if (stage == 1) Ready();
        else { c.Stderr.Push(marker[..15]); c.Stderr.Push(marker[15..] + "SUDO_mobile__"); }
        return c;
    }
    public static async Task Run()
    {
        await Test("validation allows six-character, literal shell and exact 128-byte passwords", () => { RootPasswordService.ValidatePasswords("alpine", "alpine"); RootPasswordService.ValidatePasswords(Mobile, Root); RootPasswordService.ValidatePasswords(Mobile, new string('Ж', 64)); return Task.CompletedTask; });
        await Test("validation rejects empty control and oversized UTF8 inputs", () => { Throws(() => RootPasswordService.ValidatePasswords("", Root)); Throws(() => RootPasswordService.ValidatePasswords(Mobile, "")); Throws(() => RootPasswordService.ValidatePasswords("bad\nline", Root)); Throws(() => RootPasswordService.ValidatePasswords(Mobile, "bad\0line")); Throws(() => RootPasswordService.ValidatePasswords(Mobile, new string('Ж', 65))); return Task.CompletedTask; });
        await Test("password setup uses bootstrap pw without old-root PAM authentication", () => { var command = RootPasswordService.BuildCommand(Marker); Check(command.Contains("usermod root -h 0") && !command.Contains("/passwd"), "old-root-dependent passwd flow retained"); Check(command.Contains("-u root") && command.Contains("id -ru"), "full root identity not requested and checked"); Check(command.Contains("if [ -d /var/jb ]; then P=/var/jb/usr/sbin/pw; else P=/usr/sbin/pw; fi"), "rootless helper missing may fall back to wrong database"); Check(command.Contains("IFS= read -r NEW_ROOT || exit 74") && command.Contains("unset NEW_ROOT"), "input line not buffered and cleared"); Check(!command.Contains(Mobile) && !command.Contains(Root), "secret in command"); Throws(() => RootPasswordService.BuildCommand("bad;'marker")); return Task.CompletedTask; });
        await Test("sudo stdin plus one pw input line and independent root UID0 verification", async () => { var f = new ServiceFixture(); var r = await Run(f); Check(r.Verified && r.PasswordChanged && !r.MayHaveChanged, "success flags"); Check(f.Users.SequenceEqual(new[] { "mobile", "root" }), "fresh root login absent"); Check(f.Channel!.Writes.SequenceEqual(new[] { Mobile + "\n", Root + "\n" }), "stdin conversation"); Check(f.Stages.Any(p => !p.CanCancel), "mutation phase not guarded"); Check(f.MobileDisposed, "mobile connection leaked"); Check(!r.Message.Contains(Root) && !r.Message.Contains(Mobile), "secret in message"); });
        await Test("sudo NOPASSWD never sends mobile into pw", async () => { var f = new ServiceFixture("nopasswd"); var r = await Run(f); Check(r.Verified && f.Channel!.Writes.SequenceEqual(new[] { Root + "\n" }), "NOPASSWD routing"); });
        await Test("stderr output before stdout readiness does not mix protocol streams", async () => { var f = new ServiceFixture("reversed"); var r = await Run(f); Check(r.Verified, "cross-stream ordering failed"); });
        await Test("wrong sudo password is not retried or reused as root", async () => { var f = new ServiceFixture("wrongmobile"); var r = await Run(f); Check(!r.Verified && !r.MayHaveChanged && f.Users.Count == 1 && f.Channel!.Writes.Count == 1, "sudo failure handling"); });
        await Test("legacy passwd prompt never receives mobile or new root secret", async () => { var f = new ServiceFixture("old"); var r = await Run(f); Check(!r.Verified && !r.MayHaveChanged && f.Channel!.Writes.Count == 1 && f.Users.Count == 1, "legacy password handling"); });
        await Test("missing bootstrap pw fails before sending new password", async () => { var f = new ServiceFixture("missing"); var r = await Run(f); Check(!r.Verified && !r.MayHaveChanged && r.Message.Contains("не найдена утилита pw") && f.Channel!.Writes.Count == 1 && f.Users.Count == 1, "missing helper handling"); });
        await Test("real or effective non-root identity fails before password input", async () => { var f = new ServiceFixture("notroot"); var r = await Run(f); Check(!r.Verified && !r.MayHaveChanged && r.Message.Contains("полный доступ root") && f.Channel!.Writes.Count == 1 && f.Users.Count == 1, "privilege handling"); });
        await Test("sudo requesting another user's password is refused", async () => { using var c = new FakeChannel(); c.Stderr.Push(Marker + "SUDO_root__"); bool mutation = false; await ProtocolFails(c, () => mutation = true); Check(!mutation && c.Writes.Count == 0 && c.Aborted, "wrong sudo account disclosure"); });
        await Test("pw exit zero without fresh root authentication leaves explicit uncertainty", async () => { var f = new ServiceFixture() { RejectRoot = true }; var r = await Run(f); Check(!r.Verified && !r.PasswordChanged && r.MayHaveChanged, "failure uncertainty"); Check(f.Users.Count == 2 && f.Channel!.Writes.Count == 2, "mutation repeated"); });
        await Test("password rejection after first write does not retry change", async () => { var f = new ServiceFixture("reject") { RejectRoot = true }; var r = await Run(f); Check(r.MayHaveChanged && !r.Verified && f.Channel!.Writes.Count == 2 && f.Users.Count == 2, "rejection retried or ignored"); });
        await Test("duplicate readiness never sends a second new password", async () => { var f = new ServiceFixture("duplicate") { RejectRoot = true }; var r = await Run(f); Check(r.MayHaveChanged && !r.Verified && f.Channel!.Writes.Count == 2 && f.Users.Count == 2, "duplicate mutation"); });
        await Test("stdin failure after partial write attempts root verification without exposing input", async () => { var f = new ServiceFixture("writefailed") { RejectRoot = true }; var r = await Run(f); Check(r.MayHaveChanged && !r.Verified && f.Channel!.Writes.Count == 2 && f.Users.Count == 2, "partial write not verified"); Check(!r.Message.Contains(Mobile) && !r.Message.Contains(Root), "secret error leaked"); });
        await Test("lost pw acknowledgement can recover via independent root verification", async () => { var f = new ServiceFixture("lostack"); var r = await Run(f); Check(r.Verified && f.Channel!.Writes.Count == 2, "safe verification not attempted"); });
        await Test("root login without UID0 is refused", async () => { var f = new ServiceFixture() { RootUid = "501" }; var r = await Run(f); Check(!r.Verified && r.MayHaveChanged, "non-root UID accepted"); });
        await Test("mobile identity is verified before password mutation", async () => { var f = new ServiceFixture() { MobileName = "other" }; var r = await Run(f); Check(!r.Verified && !r.MayHaveChanged && f.Channel == null && f.Users.Count == 1, "incorrect mobile identity"); });
        await Test("known host-key mismatch prevents all secret stdin writes", async () => { var f = new ServiceFixture() { InitialKeyMismatch = true }; var r = await Run(f); Check(!r.Verified && !r.MayHaveChanged && f.Channel == null, "initial key mismatch ignored"); Check(f.Settings.HostKeys.Values.Single() == f.Pin, "pin overwritten"); });
        await Test("root verification pins the exact mobile-session host key", async () => { var f = new ServiceFixture() { RootKeyMismatch = true }; var r = await Run(f); Check(!r.Verified && r.MayHaveChanged, "root host key change accepted"); Check(f.Settings.HostKeys.Values.Single() == f.Pin, "pin overwritten"); });
        await Test("cancel before connection performs no operations", async () => { var f = new ServiceFixture(); using var cts = new CancellationTokenSource(); cts.Cancel(); try { await Run(f, cts.Token); throw new Exception("cancel ignored"); } catch (OperationCanceledException) { } Check(f.Users.Count == 0, "connected after cancellation"); });
        await Test("cancel before password prompt aborts channel without mutation", async () => { using var c = new FakeChannel(); using var cts = new CancellationTokenSource(50); bool mutation = false; try { await RootPasswordConversation.RunAsync(c, Marker, Mobile, Root, () => mutation = true, cts.Token); throw new Exception("cancel ignored"); } catch (OperationCanceledException) { } Check(c.Aborted && !mutation && c.Writes.Count == 0, "cancel wrote secret"); });
        await Test("cancel after mutation starts still completes bounded root verification", async () => { using var cts = new CancellationTokenSource(); var f = new ServiceFixture() { OnFirstNew = cts.Cancel }; var r = await Run(f, cts.Token); Check(r.Verified && f.Users.Count == 2, "partial mutation cancellation"); });
        await Test("unexpected prompt without READY has bounded timeout and sends no secrets", async () => { using var c = new FakeChannel(); c.Stdout.Push("New Password: "); bool mutation = false; await ProtocolFails(c, () => mutation = true, timeoutMs: 80); Check(!mutation && c.Writes.Count == 0 && c.Aborted, "unprivileged prompt wrote secret"); });
        await Test("output flood is bounded and does not expose output", async () => { using var c = new FakeChannel(); c.Stdout.Push(new string('x', 40000)); c.End(0); bool failed = false; try { await RootPasswordConversation.RunAsync(c, Marker, Mobile, Root, () => throw new Exception("mutation"), default, TimeSpan.FromSeconds(1)); } catch { failed = true; } Check(failed && c.Writes.Count == 0, "unbounded output accepted"); });
        await Test("remote endpoint is rejected before opening SSH", async () => { var f = new ServiceFixture(); var r = await f.Service.SetAsync(new(null, false, "192.0.2.1", 22, "mobile", Mobile), Root, f.Progress); Check(!r.Verified && f.Users.Count == 0, "nonloopback endpoint used"); });
        await Test("missing USB selection does not connect to an arbitrary device", async () => { var f = new ServiceFixture(); var r = await f.Service.SetAsync(new(null, true, "127.0.0.1", 22, "mobile", Mobile), Root, f.Progress); Check(!r.Verified && f.Users.Count == 0, "arbitrary USB device used"); });
        Console.WriteLine($"{passed} root password checks passed; fake transports only.");
    }
}

sealed class ServiceFixture
{
    readonly string mode;
    readonly byte[] key = Encoding.ASCII.GetBytes("synthetic-host-key");
    public AppSettings Settings { get; } = new();
    public string Pin { get; }
    public RootPasswordService Service { get; }
    public FakeChannel? Channel { get; private set; }
    public List<string> Users { get; } = [];
    public List<RootPasswordProgress> Stages { get; } = [];
    public IProgress<RootPasswordProgress> Progress { get; }
    public bool RejectRoot, InitialKeyMismatch, RootKeyMismatch, MobileDisposed;
    public string RootUid = "0", MobileName = "mobile";
    public Action? OnFirstNew;
    public ServiceFixture(string mode = "success")
    {
        this.mode = mode;
        Pin = "SHA256:" + Convert.ToBase64String(SHA256.HashData(key)).TrimEnd('=');
        Settings.HostKeys["tunnel:127.0.0.1:22222"] = Pin;
        Progress = new ImmediateProgress(Stages.Add);
        Service = new(Settings, Connect);
    }
    Task<IRootPasswordSsh> Connect(string host, int port, string user, string password, Action<byte[]> trust, CancellationToken token)
    {
        token.ThrowIfCancellationRequested(); Users.Add(user);
        if (host != "127.0.0.1" || port != 22222) throw new Exception("wrong endpoint");
        trust((user == "root" ? RootKeyMismatch : InitialKeyMismatch) ? [1, 2, 3] : key);
        if (password != (user == "root" ? Tests.Root : Tests.Mobile)) throw new Exception("wrong login secret");
        if (user == "root" && RejectRoot) throw new IOException("synthetic raw error: " + password);
        return Task.FromResult<IRootPasswordSsh>(new FakeSsh(this, user));
    }
    sealed class FakeSsh(ServiceFixture owner, string user) : IRootPasswordSsh
    {
        public Task<string> ReadCommandAsync(string command, CancellationToken token)
        {
            token.ThrowIfCancellationRequested();
            if (command != (user == "root" ? "id -u" : "id -un")) throw new Exception("wrong identity command");
            return Task.FromResult(user == "root" ? owner.RootUid : owner.MobileName);
        }
        public IRootPasswordChannel StartCommand(string command)
        {
            if (user != "mobile" || command.Contains(Tests.Root) || command.Contains(Tests.Mobile)) throw new Exception("secret in command");
            var marker = Regex.Match(command, @"__TROLLDOCK_[a-f0-9]{32}_").Value;
            if (marker.Length == 0 || !command.Contains("-S -k") || !command.Contains("SUDO_%p__")) throw new Exception("unsafe sudo command");
            return owner.Channel = Tests.Conversation(marker, owner.mode, owner.OnFirstNew);
        }
        public void Dispose() { if (user == "mobile") owner.MobileDisposed = true; }
    }
    sealed class ImmediateProgress(Action<RootPasswordProgress> action) : IProgress<RootPasswordProgress> { public void Report(RootPasswordProgress value) => action(value); }
}

sealed class FakeChannel : IRootPasswordChannel
{
    readonly TaskCompletionSource done = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public FeedStream Stdout { get; } = new();
    public FeedStream Stderr { get; } = new();
    public List<string> Writes { get; } = [];
    public Action<string>? OnInput;
    public bool Aborted;
    public FakeChannel() { Input = new SinkStream(value => { Writes.Add(value); OnInput?.Invoke(value); }); }
    public Stream Input { get; }
    public Stream Output => Stdout;
    public Stream Error => Stderr;
    public Task Completion => done.Task;
    public int? ExitCode { get; private set; }
    public void End(int status) { ExitCode = status; Stdout.End(); Stderr.End(); done.TrySetResult(); }
    public void Abort() { Aborted = true; End(130); }
    public void Dispose() { if (!done.Task.IsCompleted) Abort(); Input.Dispose(); Stdout.Dispose(); Stderr.Dispose(); }
}
sealed class FeedStream : Stream
{
    readonly Channel<byte[]> chunks = Channel.CreateUnbounded<byte[]>();
    byte[]? current; int offset;
    public void Push(string value) => chunks.Writer.TryWrite(Encoding.UTF8.GetBytes(value));
    public void End() => chunks.Writer.TryComplete();
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken token = default)
    {
        while (current == null || offset == current.Length)
        {
            if (!await chunks.Reader.WaitToReadAsync(token)) return 0;
            if (!chunks.Reader.TryRead(out current)) continue;
            offset = 0;
        }
        var n = Math.Min(buffer.Length, current.Length - offset); current.AsMemory(offset, n).CopyTo(buffer); offset += n; return n;
    }
    public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();
    public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { } public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException(); public override void SetLength(long v) => throw new NotSupportedException(); public override void Write(byte[] b, int o, int c) => throw new NotSupportedException();
}
sealed class SinkStream(Action<string> write) : Stream
{
    public override void Write(byte[] buffer, int offset, int count) => write(Encoding.UTF8.GetString(buffer, offset, count));
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken token = default) { token.ThrowIfCancellationRequested(); write(Encoding.UTF8.GetString(buffer.Span)); return ValueTask.CompletedTask; }
    public override bool CanRead => false; public override bool CanSeek => false; public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException(); public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override void Flush() { } public override long Seek(long o, SeekOrigin s) => throw new NotSupportedException(); public override void SetLength(long v) => throw new NotSupportedException(); public override int Read(byte[] b, int o, int c) => throw new NotSupportedException();
}
namespace TrollDock.Services
{
    public sealed record ConnectionOptions(UsbDevice? Device, bool AutoUsb, string Host, int Port, string Username, string Password);
}
