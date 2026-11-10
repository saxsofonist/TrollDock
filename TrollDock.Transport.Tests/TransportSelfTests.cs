#if TRANSPORT_SELF_TEST
global using System;
global using System.Collections.Generic;
global using System.IO;
global using System.Linq;
global using System.Threading;
global using System.Threading.Tasks;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml.Linq;
using TrollDock.Transport;

static class TransportSelfTests
{
    private static readonly UsbDevice Device = new(7, "USB-SERIAL-1234", "Test phone");

    public static async Task<int> Main(string[] args)
    {
        if (args.Contains("--real-list"))
        {
            try
            {
                var devices = await new UsbMuxClient().ListDevicesAsync();
                Console.WriteLine($"USB device count: {devices.Count}");
                foreach (var device in devices) Console.WriteLine($"DeviceID={device.DeviceId}, Name={device.Name}");
                return 0;
            }
            catch (Exception ex) { Console.WriteLine($"{ex.GetType().Name}: {ex.Message}"); return 2; }
        }

        await ListDevices();
        await ConnectPayload();
        await RefusedConnection();
        await InvalidHeader();
        await TimeoutAndCancellation();
        await TunnelDuplexAndDisposal();
        Console.WriteLine("PASS: 6 USB transport tests");
        return 0;
    }

    private static async Task ListDevices()
    {
        await WithServer(async (stream, request, tag) =>
        {
            Equal("ListDevices", Value(request, "MessageType"));
            await Reply(stream, tag, new XElement("dict", new XElement("key", "DeviceList"),
                new XElement("array", DeviceEntry(7, "USB", "USB-SERIAL-1234"),
                    DeviceEntry(8, "Network", "WIFI-SERIAL-5678"), DeviceEntry(9, "USB", "SECOND-USB"))));
        }, async mux =>
        {
            var devices = await mux.ListDevicesAsync();
            Equal(2, devices.Count);
            Equal(7, devices[0].DeviceId);
            Equal("USB-SERIAL-1234", devices[0].SerialNumber);
            Equal(9, devices[1].DeviceId);
        });
        Console.WriteLine("PASS USB filtering and multiple devices");
    }

    private static async Task ConnectPayload()
    {
        await WithServer(async (stream, request, tag) =>
        {
            Equal("Connect", Value(request, "MessageType"));
            Equal("7", Value(request, "DeviceID"));
            Equal("5632", Value(request, "PortNumber"));
            var result = Packet(tag, Result(0));
            var banner = Encoding.ASCII.GetBytes("SSH-2.0-Test\r\n");
            await stream.WriteAsync(result.Concat(banner).ToArray());
        }, async mux =>
        {
            using var tcp = await mux.ConnectAsync(Device);
            var bytes = new byte[14];
            await tcp.GetStream().ReadExactlyAsync(bytes);
            Equal("SSH-2.0-Test\r\n", Encoding.ASCII.GetString(bytes));
        });
        Console.WriteLine("PASS port htons and exact response boundary");
    }

    private static async Task RefusedConnection()
    {
        await WithServer((stream, _, tag) => Reply(stream, tag, Result(3)), async mux =>
        {
            try { using var tcp = await mux.ConnectAsync(Device); throw new Exception("Expected refusal"); }
            catch (UsbMuxException ex) { Equal(3, ex.ResultCode); }
        });
        Console.WriteLine("PASS connection refusal mapping");
    }

    private static async Task InvalidHeader()
    {
        await WithServer(async (stream, _, tag) =>
        {
            var bytes = Packet(tag + 1, Result(0));
            await stream.WriteAsync(bytes);
        }, async mux =>
        {
            try { using var tcp = await mux.ConnectAsync(Device); throw new Exception("Expected header rejection"); }
            catch (UsbMuxException ex) { True(ex.Message.Contains("заголовок")); }
        });
        Console.WriteLine("PASS mismatched packet tag rejected");
    }

    private static async Task TimeoutAndCancellation()
    {
        await WithServer(async (stream, _, tag) => { await Task.Delay(250); }, async mux =>
        {
            try { await mux.ListDevicesAsync(); throw new Exception("Expected timeout"); }
            catch (UsbMuxException ex) { True(ex.InnerException is OperationCanceledException); }
        }, TimeSpan.FromMilliseconds(80));
        await WithServer(async (stream, _, tag) => { await Task.Delay(250); }, async mux =>
        {
            using var cancel = new CancellationTokenSource(80);
            try { await mux.ListDevicesAsync(cancel.Token); throw new Exception("Expected cancellation"); }
            catch (OperationCanceledException) { }
        });
        Console.WriteLine("PASS distinct timeout and user cancellation");
    }

    private static async Task TunnelDuplexAndDisposal()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var server = Task.Run(async () =>
            {
                using var remote = await listener.AcceptTcpClientAsync();
                var stream = remote.GetStream();
                var (request, tag) = await ReadRequest(stream);
                Equal("Connect", Value(request, "MessageType"));
                await Reply(stream, tag, Result(0));
                var bytes = new byte[9];
                await stream.ReadExactlyAsync(bytes);
                Equal("upload123", Encoding.ASCII.GetString(bytes));
                await stream.WriteAsync(Encoding.ASCII.GetBytes("download456"));
                var end = new byte[1];
                Equal(0, await stream.ReadAsync(end));
            });
            var mux = new UsbMuxClient(port: ((IPEndPoint)listener.LocalEndpoint).Port);
            await using var tunnel = new UsbSshTunnel(mux, Device);
            Exception? fault = null;
            tunnel.ConnectionFailed += ex => fault = ex;
            await tunnel.StartAsync();
            True(tunnel.LocalPort > 0);
            using var local = new TcpClient();
            await local.ConnectAsync(IPAddress.Loopback, tunnel.LocalPort);
            await local.GetStream().WriteAsync(Encoding.ASCII.GetBytes("upload123"));
            var bytes = new byte[11];
            await local.GetStream().ReadExactlyAsync(bytes);
            Equal("download456", Encoding.ASCII.GetString(bytes));
            await tunnel.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(3));
            await server.WaitAsync(TimeSpan.FromSeconds(3));
            Equal(0, tunnel.LocalPort);
            True(fault == null);
        }
        finally { listener.Stop(); }
        Console.WriteLine("PASS bidirectional tunnel and active-session disposal");
    }

    private static async Task WithServer(Func<NetworkStream, XElement, uint, Task> responder,
        Func<UsbMuxClient, Task> clientAction, TimeSpan? timeout = null)
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var server = Task.Run(async () =>
            {
                using var tcp = await listener.AcceptTcpClientAsync();
                var stream = tcp.GetStream();
                var (request, tag) = await ReadRequest(stream);
                await responder(stream, request, tag);
            });
            var mux = new UsbMuxClient(port: ((IPEndPoint)listener.LocalEndpoint).Port, requestTimeout: timeout);
            await clientAction(mux).WaitAsync(TimeSpan.FromSeconds(5));
            await server.WaitAsync(TimeSpan.FromSeconds(5));
        }
        finally { listener.Stop(); }
    }

    private static async Task<(XElement, uint)> ReadRequest(NetworkStream stream)
    {
        var header = new byte[16];
        await stream.ReadExactlyAsync(header);
        Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4, 4)));
        Equal(8u, BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(8, 4)));
        var payload = new byte[BinaryPrimitives.ReadUInt32LittleEndian(header) - 16];
        await stream.ReadExactlyAsync(payload);
        return (XDocument.Parse(Encoding.UTF8.GetString(payload)).Root!.Element("dict")!,
            BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12, 4)));
    }

    private static async Task Reply(NetworkStream stream, uint tag, XElement dictionary)
    {
        var bytes = Packet(tag, dictionary);
        // Deliberate fragmentation catches implementations assuming one Read == a packet.
        for (var index = 0; index < bytes.Length; index += 7)
            await stream.WriteAsync(bytes.AsMemory(index, Math.Min(7, bytes.Length - index)));
    }

    private static byte[] Packet(uint tag, XElement dictionary)
    {
        var payload = Encoding.UTF8.GetBytes(new XElement("plist", dictionary).ToString(SaveOptions.DisableFormatting));
        var packet = new byte[16 + payload.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(packet, (uint)packet.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(8, 4), 8);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(12, 4), tag);
        payload.CopyTo(packet, 16);
        return packet;
    }

    private static XElement Result(int code) => new("dict", new XElement("key", "MessageType"),
        new XElement("string", "Result"), new XElement("key", "Number"), new XElement("integer", code));

    private static XElement DeviceEntry(int id, string connection, string serial) => new("dict",
        new XElement("key", "DeviceID"), new XElement("integer", id),
        new XElement("key", "Properties"), new XElement("dict",
            new XElement("key", "ConnectionType"), new XElement("string", connection),
            new XElement("key", "SerialNumber"), new XElement("string", serial)));

    private static string Value(XElement dictionary, string key) => dictionary.Elements("key")
        .Single(element => element.Value == key).ElementsAfterSelf().First().Value;
    private static void Equal<T>(T expected, T actual)
    { if (!EqualityComparer<T>.Default.Equals(expected, actual)) throw new Exception($"Expected {expected}, got {actual}"); }
    private static void True(bool value) { if (!value) throw new Exception("Assertion failed"); }
}
#endif
