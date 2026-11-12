using TrollDock.Services;

var checks = 0;
var folder = Path.Combine(Path.GetTempPath(), "TrollDock-batch-test-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(folder);
try
{
    var files = new[] { "one.ipa", "two.ipa", "three.ipa", "package.deb" }.Select(name => Path.Combine(folder, name)).ToArray();
    foreach (var file in files) File.WriteAllText(file, "fixture");
    InstallQueue Queue() { var queue = new InstallQueue(); queue.AddFiles(files[..3], ".ipa"); return queue; }
    void Check(bool condition, string message) { if (!condition) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
    var selection = Queue();
    Check(selection.AddFiles([files[0], files[1], files[0]], ".ipa") == 0 && selection.Items.Count == 3, "deduplicate existing and repeated selections");
    Check(selection.AddFiles([Path.Combine(folder, ".", "one.ipa")], ".ipa") == 0, "canonicalize Windows paths before deduplication");
    try { selection.AddFiles([files[0], files[3]], ".ipa"); throw new Exception("Mixed selection accepted"); } catch (IOException) { }
    Check(selection.Items.Count == 3, "mixed selection is rejected atomically");
    selection.Remove(selection.Items[1]);
    Check(selection.Items.Select(item => item.Number).SequenceEqual([1, 2]), "remove renumbers display order");
    var queue = Queue(); var order = new List<string>();
    var result = await queue.RunAsync(item => { order.Add(item.FileName); return Task.CompletedTask; }, () => false, default);
    Check(order.SequenceEqual(["one.ipa", "two.ipa", "three.ipa"]) && queue.Completed == 3 && result.Error is null, "sequential installation preserves selection order");
    await queue.RunAsync(_ => throw new Exception("A successful item was retried"), () => false, default);
    Check(queue.Completed == 3 && queue.Remaining == 0, "completed files are never reinstalled by retry");
    queue = Queue(); order.Clear();
    result = await queue.RunAsync(item => { order.Add(item.FileName); return item.Number == 2 ? Task.FromException(new IOException("failure")) : Task.CompletedTask; }, () => false, default);
    Check(order.SequenceEqual(["one.ipa", "two.ipa"]) && result.Error is IOException, "failure stops before subsequent item");
    Check(queue.Items[0].State == InstallQueueState.Succeeded && queue.Items[1].State == InstallQueueState.Failed && queue.Items[2].State == InstallQueueState.Waiting, "retain completed, failed and not-started states");
    order.Clear();
    await queue.RunAsync(item => { order.Add(item.FileName); return Task.CompletedTask; }, () => false, default);
    Check(order.SequenceEqual(["two.ipa", "three.ipa"]), "retry installs only unfinished items in order");
    queue = Queue(); var stop = false;
    result = await queue.RunAsync(item => { stop = true; return Task.CompletedTask; }, () => stop, default);
    Check(result.Stopped && queue.Completed == 1 && queue.Items[1].State == InstallQueueState.Waiting, "stop during noncancellable installation finishes it and prevents next");
    queue = Queue(); using var cancellation = new CancellationTokenSource();
    result = await queue.RunAsync(_ => { cancellation.Cancel(); return Task.FromCanceled(cancellation.Token); }, () => false, cancellation.Token);
    Check(result.Stopped && queue.Items[0].State == InstallQueueState.Canceled && queue.Items[1].State == InstallQueueState.Waiting, "cancellation during preparation keeps later items untouched");
    queue = Queue();
    result = await queue.RunAsync(_ => throw new InstallationCompletedException("cleanup blocked"), () => false, default);
    Check(result.Error is InstallationCompletedException && queue.Completed == 1 && queue.Remaining == 2, "confirmed installation with cleanup error stops but is retained as completed");
    order.Clear();
    await queue.RunAsync(item => { order.Add(item.FileName); return Task.CompletedTask; }, () => false, default);
    Check(order.SequenceEqual(["two.ipa", "three.ipa"]), "cleanup error never causes confirmed installation to be repeated");
    queue = Queue();
    result = await queue.RunBatchAsync(items => Task.FromResult(new InstallQueueBatchOutcome([
        new(items[0].Path, true, "confirmed"), new(items[1].Path, false, "not confirmed")])), () => false, default);
    Check(result.Error is IOException && queue.Completed == 1 && queue.Items[2].State == InstallQueueState.Failed, "shared transaction preserves confirmed partial success and marks missing results unconfirmed");
    order.Clear();
    await queue.RunBatchAsync(items => { order.AddRange(items.Select(item => item.FileName)); return Task.FromResult(new InstallQueueBatchOutcome(items.Select(item => new InstallQueueOutcome(item.Path, true, "confirmed")).ToArray())); }, () => false, default);
    Check(order.SequenceEqual(["two.ipa", "three.ipa"]) && queue.Completed == 3, "shared transaction retry excludes already confirmed installs");
    queue = Queue();
    result = await queue.RunBatchAsync(_ => throw new OperationCanceledException(), () => false, default);
    Check(result.Stopped && queue.Items.All(item => item.State == InstallQueueState.Canceled), "shared transaction cancellation leaves all eligible for retry");
    queue = Queue();
    result = await queue.RunBatchAsync(items => Task.FromResult(new InstallQueueBatchOutcome(items.Select(item => new InstallQueueOutcome(item.Path, true, "confirmed")).ToArray(), "APT post-hook failed")), () => false, default);
    Check(result.Error?.Message == "APT post-hook failed" && queue.Completed == 3, "batch-level APT failure remains visible even when every selected package was installed");
    Console.WriteLine($"Passed {checks} batch queue checks."); return 0;
}
catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
finally { Directory.Delete(folder, true); }
