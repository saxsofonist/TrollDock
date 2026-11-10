using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;

namespace TrollDock.Services;

/// <summary>Runs the pinned, bundled signing and Apple USB installation tools. Never accepts a password.</summary>
public sealed class CertificateToolRunner
{
    public const string ZsignVersion = "1.1.3-trolldock.1";
    public const string GoIosVersion = "1.3.2";
    public const string ZsignSha256 = "710DC3718057531C7D048F8785E175EBC47E1F33E602D9AE3EE6A6C4490372D2";
    public const string GoIosSha256 = "C99B04F1D615FA716637EFAE457D5C554F32259F9D249375DE0086E3CC1A1DF5";
    private readonly string _toolRoot;

    public CertificateToolRunner(string? toolRoot = null) =>
        _toolRoot = Path.GetFullPath(toolRoot ?? Path.Combine(AppContext.BaseDirectory, "tools"));

    public async Task SignAsync(string originalIpa, string emptyPasswordP12, string profile,
        string signedIpa, string jobDir, Action<string> log, CancellationToken token = default, string? entitlementsPath = null)
    {
        // The caller supplies a private working copy, not the user-selected original.
        foreach (var path in new[] { originalIpa, emptyPasswordP12, profile, signedIpa })
            RequireContainedPath(jobDir, path);
        if (string.Equals(Path.GetFullPath(originalIpa), Path.GetFullPath(signedIpa), StringComparison.OrdinalIgnoreCase))
            throw new IOException("Исходная и подписанная IPA должны иметь разные пути.");
        if (File.Exists(signedIpa)) throw new IOException("Временный подписанный файл уже существует.");
        var arguments = new List<string>
        {
            "-f", "-k", Path.GetFullPath(emptyPasswordP12), "-m", Path.GetFullPath(profile),
            "-o", Path.GetFullPath(signedIpa), "-t", Path.GetFullPath(jobDir), "-z", "1"
        };
        if (entitlementsPath is not null)
        {
            RequireContainedPath(jobDir, entitlementsPath);
            arguments.Add("-e");
            arguments.Add(Path.GetFullPath(entitlementsPath));
        }
        arguments.Add(Path.GetFullPath(originalIpa));
        var result = await RunAsync("zsign", "zsign.exe", ZsignSha256,
            arguments,
            jobDir, log, token, TimeSpan.FromMinutes(60));
        EnsureExitSuccess(result, "Подпись IPA не завершена");
        if (!File.Exists(signedIpa) || new FileInfo(signedIpa).Length < 22)
            throw new IOException("Подписывающий модуль не создал IPA.");
    }

    public async Task InstallAsync(string signedIpa, string udid, Action<string> log, CancellationToken token = default)
    {
        RequireUdid(udid);
        token.ThrowIfCancellationRequested();
        var result = await RunAsync("go-ios", "ios.exe", GoIosSha256,
            ["--udid=" + udid, "install", "--path=" + Path.GetFullPath(signedIpa)],
            Path.GetDirectoryName(Path.GetFullPath(signedIpa))!, log,
            CancellationToken.None, TimeSpan.FromMinutes(45));
        EnsureExitSuccess(result, "iPhone не подтвердил установку");
        // An old copy found by `apps` is not evidence that this installation succeeded.
        if (!result.InstallationComplete || result.ErrorReported)
            throw new IOException("Нет подтверждения завершения установки от iPhone. Проверьте журнал и устройство.");
    }

    public async Task<bool> VerifyInstalledAsync(string bundleId, string udid, CancellationToken token = default)
    {
        RequireUdid(udid);
        if (string.IsNullOrWhiteSpace(bundleId)) throw new ArgumentException("Не задан идентификатор приложения.", nameof(bundleId));
        var result = await RunAsync("go-ios", "ios.exe", GoIosSha256,
            ["--udid=" + udid, "apps", "--all"], _toolRoot, _ => { }, token, TimeSpan.FromMinutes(2));
        EnsureExitSuccess(result, "Не удалось проверить список приложений");
        foreach (var line in result.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries))
        {
            if (!line.TrimStart().StartsWith('[')) continue;
            try
            {
                using var json = JsonDocument.Parse(line);
                if (json.RootElement.ValueKind != JsonValueKind.Array) continue;
                return json.RootElement.EnumerateArray().Any(app =>
                    app.ValueKind == JsonValueKind.Object && app.TryGetProperty("CFBundleIdentifier", out var id)
                    && id.ValueKind == JsonValueKind.String && id.GetString() == bundleId);
            }
            catch (JsonException) { }
        }
        throw new IOException("iPhone вернул неожиданный формат списка приложений.");
    }

    public async Task VerifyToolsAsync(CancellationToken token = default)
    {
        using var zsign = await OpenVerifiedToolAsync("zsign", "zsign.exe", ZsignSha256, token);
        using var goIos = await OpenVerifiedToolAsync("go-ios", "ios.exe", GoIosSha256, token);
    }

    private async Task<FileStream> OpenVerifiedToolAsync(string folder, string name, string expectedHash, CancellationToken token)
    {
        var path = Path.Combine(_toolRoot, folder, name);
        if (!File.Exists(path)) throw new FileNotFoundException("Не найден модуль " + name + ". Распакуйте весь ZIP TrollDock вместе с папкой tools.", path);
        // Keep a read-only sharing handle until the child exits: the checked image cannot be replaced meanwhile.
        var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 131072, FileOptions.Asynchronous | FileOptions.SequentialScan);
        try
        {
            var actualHash = Convert.ToHexString(await SHA256.HashDataAsync(stream, token));
            if (!string.Equals(actualHash, expectedHash, StringComparison.OrdinalIgnoreCase))
                throw new IOException("Проверка модуля " + name + " не пройдена. Заново распакуйте официальный ZIP TrollDock.");
            return stream;
        }
        catch { stream.Dispose(); throw; }
    }

    private async Task<ToolResult> RunAsync(string folder, string name, string expectedHash,
        IReadOnlyList<string> arguments, string jobDir, Action<string> log, CancellationToken token, TimeSpan timeout)
    {
        token.ThrowIfCancellationRequested();
        using var verifiedImage = await OpenVerifiedToolAsync(folder, name, expectedHash, token);
        using var childJob = new ChildProcessJob();
        var start = new ProcessStartInfo
        {
            FileName = Path.Combine(_toolRoot, folder, name),
            WorkingDirectory = Path.GetFullPath(jobDir),
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = true,
            // The patched signer declares UTF-8 in its Windows manifest; Go emits UTF-8.
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };
        foreach (var arg in arguments) start.ArgumentList.Add(arg);
        // zsign and Go both inherit this private directory for any intermediate files.
        foreach (var key in new[] { "TEMP", "TMP", "TMPDIR" }) start.Environment[key] = start.WorkingDirectory;
        foreach (var key in start.Environment.Keys.Where(k => k.StartsWith("GO_IOS_", StringComparison.OrdinalIgnoreCase)).ToArray())
            start.Environment.Remove(key);
        start.Environment.Remove("ENABLE_GO_IOS_AGENT");
        start.Environment.Remove("USBMUXD_SOCKET_ADDRESS");
        var result = new ToolResult();
        using var child = childJob.Start(start);
        var process = child.Process;
        try
        {
            var stdout = PumpAsync(child.StandardOutput, result, true, log);
            var stderr = PumpAsync(child.StandardError, result, false, log);
            using var timeoutSource = new CancellationTokenSource(timeout);
            using var linked = CancellationTokenSource.CreateLinkedTokenSource(token, timeoutSource.Token);
            try { await process.WaitForExitAsync(linked.Token); }
            catch (OperationCanceledException)
            {
                childJob.Dispose();
                Kill(process);
                await process.WaitForExitAsync(CancellationToken.None);
                await Task.WhenAll(stdout, stderr);
                if (token.IsCancellationRequested) throw new OperationCanceledException(token);
                throw new IOException(name == "ios.exe"
                    ? "iPhone слишком долго не отвечает. Результат установки неизвестен; проверьте устройство."
                    : "Подпись превысила допустимое время ожидания.");
            }
            // A completed child must not leave a descendant holding these pipes open.
            childJob.Dispose();
            await Task.WhenAll(stdout, stderr);
            result.ExitCode = process.ExitCode;
            return result;
        }
        catch
        {
            Kill(process);
            try { await process.WaitForExitAsync(CancellationToken.None); } catch (InvalidOperationException) { }
            throw;
        }
    }

    private static async Task PumpAsync(StreamReader reader, ToolResult result, bool standardOutput, Action<string> log)
    {
        while (await reader.ReadLineAsync() is { } raw)
        {
            var line = Regex.Replace(raw, "\\x1B\\[[0-?]*[ -/]*[@-~]", "");
            lock (result)
            {
                if (standardOutput && result.Output.Length < 16 * 1024 * 1024)
                    result.Output.AppendLine(line);
                result.Tail.Enqueue(line.Length > 4000 ? line[..4000] : line);
                while (result.Tail.Count > 14) result.Tail.Dequeue();
                if (TryReadLog(line, out var level, out var message))
                {
                    if (message == "installation successful" && level == "INFO") result.InstallationComplete = true;
                    if (level is "ERROR" or "FATAL") result.ErrorReported = true;
                    // This blanket upstream hint is irrelevant to installation over the existing Apple USB service.
                    if (message.StartsWith("go-ios agent is not running.", StringComparison.Ordinal)) continue;
                }
            }
            try { log(line); } catch (Exception) { /* A closed log view must not abandon a running installer. */ }
        }
    }

    internal static bool TryReadLog(string line, out string level, out string message)
    {
        level = message = "";
        try
        {
            using var json = JsonDocument.Parse(line);
            if (json.RootElement.ValueKind != JsonValueKind.Object) return false;
            if (json.RootElement.TryGetProperty("level", out var l) && l.ValueKind == JsonValueKind.String) level = l.GetString() ?? "";
            if (json.RootElement.TryGetProperty("msg", out var m) && m.ValueKind == JsonValueKind.String) message = m.GetString() ?? "";
            return true;
        }
        catch (JsonException) { return false; }
    }

    private static void EnsureExitSuccess(ToolResult result, string message)
    {
        if (result.ExitCode != 0 || result.ErrorReported)
            throw new IOException(message + " (код " + result.ExitCode + ").\n" + string.Join("\n", result.Tail));
    }

    private static void Kill(Process process)
    {
        try { if (!process.HasExited) process.Kill(entireProcessTree: true); }
        catch (InvalidOperationException) { }
        catch (Win32Exception) { }
    }

    private static void RequireUdid(string udid)
    {
        if (string.IsNullOrWhiteSpace(udid) || udid.Length > 80 || !Regex.IsMatch(udid, "\\A[A-Za-z0-9-]+\\z"))
            throw new ArgumentException("Выберите конкретный iPhone в списке USB-устройств.", nameof(udid));
    }

    internal static void RequireContainedPath(string directory, string path)
    {
        var root = Path.TrimEndingDirectorySeparator(Path.GetFullPath(directory)) + Path.DirectorySeparatorChar;
        if (!Path.GetFullPath(path).StartsWith(root, StringComparison.OrdinalIgnoreCase))
            throw new IOException("Подпись разрешена только внутри отдельной временной папки TrollDock.");
    }

    private sealed class ToolResult
    {
        public int ExitCode { get; set; }
        public StringBuilder Output { get; } = new();
        public string Stdout => Output.ToString();
        public Queue<string> Tail { get; } = new();
        public bool InstallationComplete { get; set; }
        public bool ErrorReported { get; set; }
    }

    /// <summary>Windows closes this handle on an application crash, terminating its owned child processes.</summary>
    internal sealed class ChildProcessJob : IDisposable
    {
        private readonly SafeFileHandle _handle;
        public ChildProcessJob()
        {
            _handle = CreateJobObject(IntPtr.Zero, null);
            if (_handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            var limits = new ExtendedLimitInformation();
            limits.BasicLimitInformation.LimitFlags = 0x00002000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if (!SetInformationJobObject(_handle, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimitInformation>()))
            {
                var error = Marshal.GetLastWin32Error();
                _handle.Dispose();
                throw new Win32Exception(error, "Не удалось настроить завершение вспомогательного процесса.");
            }
        }
        public NativeChild Start(ProcessStartInfo start)
        {
            // Associate the Job Object atomically in CreateProcess. Starting a process and
            // assigning it afterwards leaves a crash window and lets early descendants escape.
            using var output = new ChildPipe();
            using var error = new ChildPipe();
            using var input = new ChildPipe();
            input.Write.Dispose(); // The child sees EOF; no password is ever sent over stdin.
            if (!SetHandleInformation(input.Read, 1, 1)) throw new Win32Exception(Marshal.GetLastWin32Error());
            var handles = new[] { input.Read.DangerousGetHandle(), output.Write.DangerousGetHandle(), error.Write.DangerousGetHandle() };
            var size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
            var attributes = Marshal.AllocHGlobal(size);
            var jobPointer = Marshal.AllocHGlobal(IntPtr.Size);
            var handlesPointer = Marshal.AllocHGlobal(IntPtr.Size * handles.Length);
            var environment = IntPtr.Zero;
            var initialized = false;
            try
            {
                if (!InitializeProcThreadAttributeList(attributes, 2, 0, ref size)) throw new Win32Exception(Marshal.GetLastWin32Error());
                initialized = true;
                Marshal.WriteIntPtr(jobPointer, _handle.DangerousGetHandle());
                Marshal.Copy(handles, 0, handlesPointer, handles.Length);
                // PROC_THREAD_ATTRIBUTE_JOB_LIST and PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
                if (!UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x0002000d, jobPointer, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero)
                    || !UpdateProcThreadAttribute(attributes, 0, (IntPtr)0x00020002, handlesPointer, (IntPtr)(IntPtr.Size * handles.Length), IntPtr.Zero, IntPtr.Zero))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось изолировать вспомогательный процесс.");
                var startup = new StartupInfoEx();
                startup.StartupInfo.Size = Marshal.SizeOf<StartupInfoEx>();
                startup.StartupInfo.Flags = 0x100; // STARTF_USESTDHANDLES
                startup.StartupInfo.StandardInput = handles[0];
                startup.StartupInfo.StandardOutput = handles[1];
                startup.StartupInfo.StandardError = handles[2];
                startup.AttributeList = attributes;
                var entries = start.Environment.Where(e => e.Value is not null).OrderBy(e => e.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(e => e.Key + "=" + e.Value);
                environment = Marshal.StringToHGlobalUni(string.Join('\0', entries) + "\0\0");
                var command = new StringBuilder(QuoteArgument(start.FileName));
                foreach (var argument in start.ArgumentList) command.Append(' ').Append(QuoteArgument(argument));
                // Suspended until the managed Process owns its handle; the job already owns it.
                const uint flags = 0x08000000 | 0x00080000 | 0x00000400 | 0x00000004;
                if (!CreateProcess(start.FileName, command, IntPtr.Zero, IntPtr.Zero, true, flags, environment,
                    start.WorkingDirectory, ref startup, out var native))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Не удалось запустить вспомогательный процесс.");
                using var nativeProcess = new SafeFileHandle(native.Process, true);
                using var nativeThread = new SafeFileHandle(native.Thread, true);
                Process? process = null;
                try
                {
                    process = Process.GetProcessById(native.ProcessId);
                    _ = process.Handle;
                    if (ResumeThread(nativeThread) == uint.MaxValue) throw new Win32Exception(Marshal.GetLastWin32Error());
                    output.Write.Dispose();
                    error.Write.Dispose();
                    return new NativeChild(process, output.TakeReader(start.StandardOutputEncoding), error.TakeReader(start.StandardErrorEncoding));
                }
                catch
                {
                    TerminateProcess(nativeProcess, 1);
                    process?.Dispose();
                    throw;
                }
            }
            finally
            {
                if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
                if (initialized) DeleteProcThreadAttributeList(attributes);
                Marshal.FreeHGlobal(handlesPointer);
                Marshal.FreeHGlobal(jobPointer);
                Marshal.FreeHGlobal(attributes);
                GC.KeepAlive(_handle);
            }
        }
        public void Dispose() => _handle.Dispose();

        internal static string QuoteArgument(string argument)
        {
            // Windows CommandLineToArgvW / CRT quoting, including quotes and trailing slashes.
            var quoted = new StringBuilder("\"");
            var slashes = 0;
            foreach (var c in argument)
            {
                if (c == '\\') { slashes++; continue; }
                quoted.Append('\\', c == '"' ? slashes * 2 + 1 : slashes).Append(c);
                slashes = 0;
            }
            return quoted.Append('\\', slashes * 2).Append('"').ToString();
        }

        internal sealed class NativeChild(Process process, StreamReader stdout, StreamReader stderr) : IDisposable
        {
            public Process Process { get; } = process;
            public StreamReader StandardOutput { get; } = stdout;
            public StreamReader StandardError { get; } = stderr;
            public void Dispose() { StandardOutput.Dispose(); StandardError.Dispose(); Process.Dispose(); }
        }

        private sealed class ChildPipe : IDisposable
        {
            public SafeFileHandle Read { get; }
            public SafeFileHandle Write { get; }
            private bool _readTransferred;
            public ChildPipe()
            {
                var security = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), InheritHandle = true };
                if (!CreatePipe(out var read, out var write, ref security, 0)) throw new Win32Exception(Marshal.GetLastWin32Error());
                Read = read;
                Write = write;
                if (!SetHandleInformation(Read, 1, 0))
                {
                    var error = Marshal.GetLastWin32Error();
                    Dispose();
                    throw new Win32Exception(error);
                }
            }
            public StreamReader TakeReader(Encoding? encoding)
            {
                var reader = new StreamReader(new FileStream(Read, FileAccess.Read), encoding ?? Encoding.UTF8);
                _readTransferred = true;
                return reader;
            }
            public void Dispose() { Write.Dispose(); if (!_readTransferred) Read.Dispose(); }
        }

        [StructLayout(LayoutKind.Sequential)] private struct SecurityAttributes
        {
            public int Length;
            public IntPtr SecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool InheritHandle;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)] private struct StartupInfo
        {
            public int Size;
            public IntPtr Reserved, Desktop, Title;
            public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
            public short ShowWindow, ReservedBytes;
            public IntPtr ReservedPointer, StandardInput, StandardOutput, StandardError;
        }
        [StructLayout(LayoutKind.Sequential)] private struct StartupInfoEx
        {
            public StartupInfo StartupInfo;
            public IntPtr AttributeList;
        }
        [StructLayout(LayoutKind.Sequential)] private struct ProcessInformation
        {
            public IntPtr Process, Thread;
            public int ProcessId, ThreadId;
        }

        [StructLayout(LayoutKind.Sequential)] private struct BasicLimitInformation
        {
            public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass, SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)] private struct IoCounters
        {
            public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount,
                ReadTransferCount, WriteTransferCount, OtherTransferCount;
        }
        [StructLayout(LayoutKind.Sequential)] private struct ExtendedLimitInformation
        {
            public BasicLimitInformation BasicLimitInformation;
            public IoCounters IoInfo;
            public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern SafeFileHandle CreateJobObject(IntPtr attributes, string? name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(SafeFileHandle job, int informationClass,
            ref ExtendedLimitInformation information, uint informationLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SecurityAttributes attributes, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returnedSize);
        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, EntryPoint = "CreateProcessW")]
        private static extern bool CreateProcess(string application, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes,
            bool inheritHandles, uint flags, IntPtr environment, string currentDirectory, ref StartupInfoEx startup, out ProcessInformation process);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(SafeFileHandle thread);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool TerminateProcess(SafeFileHandle process, uint exitCode);
    }
}


