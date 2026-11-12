using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Runtime.CompilerServices;

namespace TrollDock.Services;

public enum InstallQueueState { Waiting, Running, Succeeded, Failed, Canceled }

public sealed class InstallQueueItem : INotifyPropertyChanged
{
    private int number;
    private InstallQueueState state;
    private string detail = "";
    public string Path { get; }
    public string FileName => System.IO.Path.GetFileName(Path);
    public long Length { get; }
    public int Number { get => number; internal set { number = value; Changed(); } }
    public InstallQueueState State => state;
    public string Detail => detail;
    public string Status => state switch
    {
        InstallQueueState.Running => "Выполняется",
        InstallQueueState.Succeeded => "Установлено",
        InstallQueueState.Failed => "Ошибка",
        InstallQueueState.Canceled => "Отменено",
        _ => "Ожидает"
    };
    public InstallQueueItem(string path, long length) { Path = path; Length = length; }
    public void SetState(InstallQueueState value, string message = "")
    {
        state = value; detail = message;
        Changed(nameof(State)); Changed(nameof(Status)); Changed(nameof(Detail));
    }
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed([CallerMemberName] string? name = null) => PropertyChanged?.Invoke(this, new(name));
}

public sealed record InstallQueueOutcome(string Path, bool Installed, string Message);
public sealed record InstallQueueBatchOutcome(IReadOnlyList<InstallQueueOutcome> Items, string? Error = null);
public sealed record InstallQueueRunResult(bool Stopped, Exception? Error);
/// <summary>The device confirmed installation, but required post-install work failed.</summary>
public sealed class InstallationCompletedException(string message, Exception? inner = null) : IOException(message, inner);

/// <summary>Retains successful entries so a retry runs only unfinished files.</summary>
public sealed class InstallQueue
{
    public ObservableCollection<InstallQueueItem> Items { get; } = [];
    public int Remaining => Items.Count(item => item.State != InstallQueueState.Succeeded);
    public int Completed => Items.Count(item => item.State == InstallQueueState.Succeeded);

    public int AddFiles(IEnumerable<string> paths, string extension)
    {
        // Validate the whole selection before changing the queue.
        var candidates = paths.Select(Path.GetFullPath).Distinct(StringComparer.OrdinalIgnoreCase)
            .Select(path =>
            {
                if (!string.Equals(Path.GetExtension(path), extension, StringComparison.OrdinalIgnoreCase))
                    throw new IOException($"В одну очередь можно добавить только файлы {extension}.");
                var file = new FileInfo(path);
                if (!file.Exists) throw new FileNotFoundException("Файл не найден.", path);
                return new InstallQueueItem(path, file.Length);
            }).ToArray();
        var added = 0;
        foreach (var item in candidates)
            if (!Items.Any(existing => string.Equals(existing.Path, item.Path, StringComparison.OrdinalIgnoreCase)))
            { Items.Add(item); added++; }
        Renumber();
        return added;
    }
    public void Remove(InstallQueueItem item) { Items.Remove(item); Renumber(); }
    public void Clear() => Items.Clear();
    private void Renumber() { for (var index = 0; index < Items.Count; index++) Items[index].Number = index + 1; }

    public async Task<InstallQueueRunResult> RunAsync(Func<InstallQueueItem, Task> install,
        Func<bool> stopRequested, CancellationToken cancellationToken)
    {
        foreach (var item in Items.Where(item => item.State != InstallQueueState.Succeeded).ToArray())
        {
            if (stopRequested() || cancellationToken.IsCancellationRequested) return new(true, null);
            item.SetState(InstallQueueState.Running);
            try
            {
                await install(item);
                item.SetState(InstallQueueState.Succeeded);
            }
            catch (OperationCanceledException)
            {
                item.SetState(InstallQueueState.Canceled, "Операция отменена. Можно повторить установку.");
                return new(true, null);
            }
            catch (InstallationCompletedException ex)
            {
                item.SetState(InstallQueueState.Succeeded, ex.Message);
                return new(false, ex);
            }
            catch (Exception ex)
            {
                item.SetState(InstallQueueState.Failed, ex.Message);
                return new(false, ex);
            }
        }
        return new(false, null);
    }

    public async Task<InstallQueueRunResult> RunBatchAsync(
        Func<IReadOnlyList<InstallQueueItem>, Task<InstallQueueBatchOutcome>> install,
        Func<bool> stopRequested, CancellationToken cancellationToken)
    {
        var pending = Items.Where(item => item.State != InstallQueueState.Succeeded).ToArray();
        if (stopRequested() || cancellationToken.IsCancellationRequested) return new(true, null);
        if (pending.Length == 0) return new(false, null);
        foreach (var item in pending) item.SetState(InstallQueueState.Running);
        try
        {
            var result = await install(pending);
            foreach (var item in pending)
            {
                var outcome = result.Items.FirstOrDefault(outcome => string.Equals(outcome.Path, item.Path, StringComparison.OrdinalIgnoreCase));
                item.SetState(outcome?.Installed == true ? InstallQueueState.Succeeded : InstallQueueState.Failed,
                    outcome?.Message ?? "Результат установки не подтверждён. Проверьте журнал.");
            }
            if (!string.IsNullOrWhiteSpace(result.Error)) return new(false, new IOException(result.Error));
            return pending.Any(item => item.State != InstallQueueState.Succeeded)
                ? new(false, new IOException("Не все пакеты установлены. Результат каждого файла указан в очереди; подробности — в журнале."))
                : new(false, null);
        }
        catch (OperationCanceledException)
        {
            foreach (var item in pending) item.SetState(InstallQueueState.Canceled, "Пакетная установка отменена до начала изменений.");
            return new(true, null);
        }
        catch (Exception ex)
        {
            foreach (var item in pending) item.SetState(InstallQueueState.Failed, ex.Message);
            return new(false, ex);
        }
    }
}
