namespace TrollDock.Transport;

/// <summary>A physical USB device reported by Apple's local usbmux service.</summary>
public sealed record UsbDevice(int DeviceId, string SerialNumber, string Name)
{
    public override string ToString() => Name;
}

public sealed class UsbMuxException : IOException
{
    public int? ResultCode { get; }

    public UsbMuxException(string message, int? resultCode = null, Exception? inner = null)
        : base(message, inner) => ResultCode = resultCode;
}
