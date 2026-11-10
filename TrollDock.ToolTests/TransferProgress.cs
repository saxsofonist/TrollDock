namespace TrollDock.Services;
public sealed record TransferProgress(string Stage, string Detail, double Percent, bool CanCancel);
