using System.Buffers.Binary;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Xml;
using System.Xml.Linq;

namespace TrollDock.Transport;

/// <summary>
/// A minimal implementation of the public usbmux plist protocol. Each request uses
/// its own connection, so an established Connect stream becomes raw SSH traffic.
/// No pairing records, credentials, or external executables are needed here.
/// </summary>
public sealed class UsbMuxClient
{
    private const uint PlistMessage = 8;
    private const uint ResultMessage = 1;
    private const int HeaderSize = 16;
    private const int MaxPacketSize = 4 * 1024 * 1024;
    private readonly IPAddress _address;
    private readonly int _port;
    private readonly TimeSpan _requestTimeout;
    private int _nextTag;

    public UsbMuxClient(string host = "127.0.0.1", int port = 27015, TimeSpan? requestTimeout = null)
    {
        if (!IPAddress.TryParse(host, out var address) || !IPAddress.IsLoopback(address))
            throw new ArgumentException("Служба USB должна находиться на локальном компьютере.", nameof(host));
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        _address = address;
        _port = port;
        _requestTimeout = requestTimeout ?? TimeSpan.FromSeconds(8);
        if (_requestTimeout <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(requestTimeout));
    }

    public async Task<IReadOnlyList<UsbDevice>> ListDevicesAsync(CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_requestTimeout);
        try
        {
            using var tcp = await OpenServiceAsync(timeout.Token).ConfigureAwait(false);
            var response = await RequestAsync(tcp.GetStream(), CreateMessage("ListDevices"), timeout.Token)
                .ConfigureAwait(false);
            ThrowIfError(response, "получить список устройств");
            if (!response.TryGetValue("DeviceList", out var list) || list.Name.LocalName != "array")
                throw new UsbMuxException("Служба Apple вернула некорректный список USB-устройств.");

            var devices = new List<UsbDevice>();
            foreach (var element in list.Elements("dict"))
            {
                var entry = ReadDictionary(element);
                if (!entry.TryGetValue("Properties", out var propertiesElement)) continue;
                var properties = ReadDictionary(propertiesElement);
                // Do not silently route to a Wi-Fi device when the user requested USB.
                if (ReadString(properties, "ConnectionType") != "USB") continue;
                var id = ReadInteger(entry, "DeviceID") ?? ReadInteger(properties, "DeviceID");
                var serial = ReadString(properties, "SerialNumber");
                if (id is null or <= 0 or > int.MaxValue || string.IsNullOrWhiteSpace(serial)) continue;
                var name = ReadString(properties, "DeviceName");
                if (string.IsNullOrWhiteSpace(name))
                    name = $"iPhone / iPad · …{serial[^Math.Min(8, serial.Length)..]}";
                devices.Add(new UsbDevice((int)id.Value, serial, name));
            }
            return devices.DistinctBy(device => device.DeviceId).ToArray();
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            throw new UsbMuxException("Служба Apple не ответила вовремя. Переподключите устройство по USB.", inner: ex);
        }
    }

    /// <summary>The caller owns the returned socket and must dispose it.</summary>
    public async Task<TcpClient> ConnectAsync(UsbDevice device, int port = 22,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(device);
        if (device.DeviceId <= 0) throw new ArgumentOutOfRangeException(nameof(device));
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_requestTimeout);
        TcpClient? tcp = null;
        try
        {
            tcp = await OpenServiceAsync(timeout.Token).ConfigureAwait(false);
            var request = CreateMessage("Connect");
            request.Add(new XElement("key", "DeviceID"), new XElement("integer", device.DeviceId));
            // usbmux PortNumber is htons(port), even though the outer packet is little-endian.
            var networkOrderPort = BinaryPrimitives.ReverseEndianness((ushort)port);
            request.Add(new XElement("key", "PortNumber"), new XElement("integer", networkOrderPort));
            var response = await RequestAsync(tcp.GetStream(), request, timeout.Token).ConfigureAwait(false);
            ThrowIfError(response, $"открыть SSH на порту {port}");
            if (ReadInteger(response, "Number") != 0)
                throw new UsbMuxException("Служба Apple не подтвердила открытие USB-соединения.");
            return tcp;
        }
        catch (OperationCanceledException ex) when (!cancellationToken.IsCancellationRequested)
        {
            tcp?.Dispose();
            throw new UsbMuxException("Устройство не ответило при открытии SSH по USB.", inner: ex);
        }
        catch
        {
            tcp?.Dispose();
            throw;
        }
    }

    private async Task<TcpClient> OpenServiceAsync(CancellationToken token)
    {
        var tcp = new TcpClient(_address.AddressFamily) { NoDelay = true };
        try
        {
            await tcp.ConnectAsync(_address, _port, token).ConfigureAwait(false);
            return tcp;
        }
        catch (SocketException ex)
        {
            tcp.Dispose();
            throw new UsbMuxException("Служба Apple Mobile Device недоступна. Установите или запустите Apple Devices / iTunes и подключите iPhone кабелем.", inner: ex);
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    private async Task<Dictionary<string, XElement>> RequestAsync(NetworkStream stream, XElement dictionary,
        CancellationToken token)
    {
        var document = new XDocument(new XDeclaration("1.0", "UTF-8", null),
            new XElement("plist", new XAttribute("version", "1.0"), dictionary));
        var payload = Encoding.UTF8.GetBytes(document.ToString(SaveOptions.DisableFormatting));
        var tag = unchecked((uint)Interlocked.Increment(ref _nextTag));
        var packet = new byte[HeaderSize + payload.Length];
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(0, 4), (uint)packet.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(4, 4), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(8, 4), PlistMessage);
        BinaryPrimitives.WriteUInt32LittleEndian(packet.AsSpan(12, 4), tag);
        payload.CopyTo(packet, HeaderSize);
        await stream.WriteAsync(packet, token).ConfigureAwait(false);

        var header = new byte[HeaderSize];
        await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        var length = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(0, 4));
        var version = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4, 4));
        var type = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(8, 4));
        var responseTag = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(12, 4));
        if (length < HeaderSize || length > MaxPacketSize || version > 1 || responseTag != tag)
            throw new UsbMuxException("Служба Apple вернула некорректный заголовок ответа.");
        var responsePayload = new byte[(int)length - HeaderSize];
        await stream.ReadExactlyAsync(responsePayload, token).ConfigureAwait(false);
        if (type == ResultMessage && responsePayload.Length == 4)
        {
            return new Dictionary<string, XElement>
            {
                ["Number"] = new("integer", BinaryPrimitives.ReadUInt32LittleEndian(responsePayload))
            };
        }
        if (type != PlistMessage) throw new UsbMuxException("Служба Apple вернула неизвестный тип сообщения.");
        try
        {
            using var memory = new MemoryStream(responsePayload, writable: false);
            using var reader = XmlReader.Create(memory, new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Ignore,
                XmlResolver = null,
                MaxCharactersInDocument = MaxPacketSize
            });
            var responseDocument = XDocument.Load(reader);
            var root = responseDocument.Root;
            if (root?.Name.LocalName != "plist" || root.Element("dict") is not { } rootDictionary)
                throw new UsbMuxException("Служба Apple вернула некорректный plist.");
            return ReadDictionary(rootDictionary);
        }
        catch (XmlException ex)
        {
            throw new UsbMuxException("Не удалось прочитать ответ службы Apple.", inner: ex);
        }
    }

    private static XElement CreateMessage(string messageType) => new("dict",
        new XElement("key", "BundleID"), new XElement("string", "local.trolldock"),
        new XElement("key", "ClientVersionString"), new XElement("string", "TrollDock 1.0"),
        new XElement("key", "MessageType"), new XElement("string", messageType),
        new XElement("key", "ProgName"), new XElement("string", "TrollDock"),
        new XElement("key", "kLibUSBMuxVersion"), new XElement("integer", 3));

    private static Dictionary<string, XElement> ReadDictionary(XElement element)
    {
        if (element.Name.LocalName != "dict") throw new UsbMuxException("Ожидался словарь plist.");
        var result = new Dictionary<string, XElement>(StringComparer.Ordinal);
        var elements = element.Elements().ToArray();
        if (elements.Length % 2 != 0) throw new UsbMuxException("Неполный словарь в ответе службы Apple.");
        for (var index = 0; index < elements.Length; index += 2)
        {
            if (elements[index].Name.LocalName != "key") throw new UsbMuxException("Некорректный ключ plist.");
            if (!result.TryAdd(elements[index].Value, elements[index + 1]))
                throw new UsbMuxException("Повторяющийся ключ в ответе службы Apple.");
        }
        return result;
    }

    private static string? ReadString(Dictionary<string, XElement> dictionary, string key) =>
        dictionary.TryGetValue(key, out var element) && element.Name.LocalName == "string" ? element.Value : null;

    private static long? ReadInteger(Dictionary<string, XElement> dictionary, string key) =>
        dictionary.TryGetValue(key, out var element) && element.Name.LocalName == "integer"
            && long.TryParse(element.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var value)
                ? value : null;

    private static void ThrowIfError(Dictionary<string, XElement> response, string action)
    {
        var code = ReadInteger(response, "Number");
        if (code is null or 0) return;
        var detail = code switch
        {
            2 => "Устройство было отключено. Обновите список и подключите его снова.",
            3 => "Устройство отклонило соединение. Проверьте, что джейлбрейк активен и OpenSSH запущен.",
            6 => "Служба Apple не поддерживает эту версию протокола.",
            _ => $"Код службы Apple: {code}."
        };
        throw new UsbMuxException($"Не удалось {action}. {detail}", code <= int.MaxValue ? (int)code : null);
    }
}
