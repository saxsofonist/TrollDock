using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

namespace TrollDock.Transport;

/// <summary>A process-free, loopback-only SSH tunnel bound to one selected USB device.</summary>
public sealed class UsbSshTunnel : IAsyncDisposable
{
    private readonly UsbMuxClient _mux;
    private readonly UsbDevice _device;
    private readonly int _remotePort;
    private readonly ConcurrentDictionary<long, Task> _connections = new();
    private readonly object _lifecycle = new();
    private CancellationTokenSource? _lifetime;
    private TcpListener? _listener;
    private Task? _acceptTask;
    private long _nextConnection;
    private bool _disposed;

    public int LocalPort { get; private set; }
    public event Action<Exception>? ConnectionFailed;

    public UsbSshTunnel(UsbMuxClient mux, UsbDevice device, int remotePort = 22)
    {
        ArgumentNullException.ThrowIfNull(mux);
        ArgumentNullException.ThrowIfNull(device);
        if (remotePort is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(remotePort));
        _mux = mux;
        _device = device;
        _remotePort = remotePort;
    }

    public Task StartAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_lifecycle)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_listener != null) throw new InvalidOperationException("USB-туннель уже запущен.");
            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            _listener = listener;
            LocalPort = ((IPEndPoint)listener.LocalEndpoint).Port;
            _lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            _acceptTask = AcceptAsync(listener, _lifetime.Token);
        }
        return Task.CompletedTask;
    }

    private async Task AcceptAsync(TcpListener listener, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                var local = await listener.AcceptTcpClientAsync(token).ConfigureAwait(false);
                local.NoDelay = true;
                var id = Interlocked.Increment(ref _nextConnection);
                var task = ForwardAsync(local, token);
                _connections[id] = task;
                _ = task.ContinueWith(_ => _connections.TryRemove(id, out var ignored),
                    CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
            }
        }
        catch (Exception ex) when (token.IsCancellationRequested && ex is OperationCanceledException or SocketException or ObjectDisposedException)
        {
            // Cancellation is normal when a window/session closes.
        }
        catch (Exception ex)
        {
            NotifyFailure(ex);
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task ForwardAsync(TcpClient local, CancellationToken token)
    {
        using (local)
        using (var connectionLifetime = CancellationTokenSource.CreateLinkedTokenSource(token))
        {
            try
            {
                using var remote = await _mux.ConnectAsync(_device, _remotePort, connectionLifetime.Token)
                    .ConfigureAwait(false);
                using var closeOnCancel = connectionLifetime.Token.Register(() =>
                {
                    local.Dispose();
                    remote.Dispose();
                });
                var upload = CopyWithHalfCloseAsync(local, remote, connectionLifetime.Token);
                var download = CopyWithHalfCloseAsync(remote, local, connectionLifetime.Token);
                var first = await Task.WhenAny(upload, download).ConfigureAwait(false);
                if (!first.IsCompletedSuccessfully)
                {
                    if (!token.IsCancellationRequested && first.Exception is { } error)
                        NotifyFailure(error.GetBaseException());
                    connectionLifetime.Cancel();
                }
                await Task.WhenAll(upload, download).ConfigureAwait(false);
            }
            catch (Exception ex) when (connectionLifetime.IsCancellationRequested && ex is OperationCanceledException or IOException or SocketException or ObjectDisposedException)
            {
                // All sockets are disposed and both copy tasks observed before returning.
            }
            catch (Exception ex)
            {
                NotifyFailure(ex);
            }
        }
    }

    private static async Task CopyWithHalfCloseAsync(TcpClient source, TcpClient destination, CancellationToken token)
    {
        await source.GetStream().CopyToAsync(destination.GetStream(), 81920, token).ConfigureAwait(false);
        try { destination.Client.Shutdown(SocketShutdown.Send); }
        catch (SocketException) { }
        catch (ObjectDisposedException) { }
    }

    private void NotifyFailure(Exception exception)
    {
        // A UI logging callback must not fault the listener or leave sockets behind.
        try { ConnectionFailed?.Invoke(exception); }
        catch { }
    }

    public async ValueTask DisposeAsync()
    {
        Task? acceptTask;
        CancellationTokenSource? lifetime;
        lock (_lifecycle)
        {
            if (_disposed) return;
            _disposed = true;
            lifetime = _lifetime;
            acceptTask = _acceptTask;
            lifetime?.Cancel();
            _listener?.Stop();
            LocalPort = 0;
        }
        if (acceptTask != null) await acceptTask.ConfigureAwait(false);
        // The accept loop has ended, so no further connections can be added here.
        await Task.WhenAll(_connections.Values.ToArray()).ConfigureAwait(false);
        lifetime?.Dispose();
    }
}
