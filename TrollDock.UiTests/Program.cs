using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Interop;
using System.Windows.Threading;
using TrollDock.Services;

namespace TrollDock.UiTests;

internal static class Program
{
    private static int checks;
    [STAThread] public static int Main()
    {
        var app = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        var previous = File.Exists(AppSettings.SettingsPath) ? File.ReadAllBytes(AppSettings.SettingsPath) : null;
        var fixtures = Path.Combine(Path.GetTempPath(), "TrollDock-ui-queue-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(fixtures);
            var firstIpa = Path.Combine(fixtures, "first.ipa"); var secondIpa = Path.Combine(fixtures, "second.ipa"); var deb = Path.Combine(fixtures, "package.deb");
            foreach (var path in new[] { firstIpa, secondIpa, deb }) File.WriteAllText(path, "UI fixture only");
            new AppSettings { StartupMode = "certificate", ModeOrder = ["certificate", "deb", "trollstore"] }.Save();
            var main = new MainWindow { ShowInTaskbar = false, Opacity = 0 };
            new WindowInteropHelper(main).EnsureHandle(); // Never show MainWindow; Loaded/device discovery does not run.
            Check(TabNames(main).SequenceEqual(["CertificateModeRadioButton", "DebModeRadioButton", "IpaModeRadioButton"]), "stored order is applied to actual WPF tab controls");
            Check(Control<RadioButton>(main, "CertificateModeRadioButton").IsChecked == true, "stored startup mode selects certificate tab");
            Exception? eventFailure = null;
            main.Dispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, new Action(() =>
            {
                var dialog = app.Windows.OfType<SettingsWindow>().Single();
                try
                {
                    dialog.Opacity = 0; dialog.ShowInTaskbar = false;
                    Descendants(dialog).OfType<ComboBox>().Single().SelectedValue = "deb";
                    Descendants(dialog).OfType<ListBox>().Single().SelectedIndex = 0;
                    Descendants(dialog).OfType<Button>().Single(b => Equals(b.Content, "↓ Ниже")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                    Descendants(dialog).OfType<Button>().Single(b => Equals(b.Content, "Сохранить")).RaiseEvent(new RoutedEventArgs(Button.ClickEvent));
                }
                catch (Exception e) { eventFailure = e; dialog.Close(); }
            }));
            Invoke(main, "Settings_Click", main, new RoutedEventArgs());
            if (eventFailure is not null) throw eventFailure;
            Check(TabNames(main).SequenceEqual(["DebModeRadioButton", "CertificateModeRadioButton", "IpaModeRadioButton"]), "settings dialog changes real tab order immediately");
            Check(Control<RadioButton>(main, "CertificateModeRadioButton").IsChecked == true, "changing startup tab keeps current mode until restart");
            var persisted = AppSettings.Load();
            Check(persisted.StartupMode == "deb" && persisted.ModeOrder.SequenceEqual(["deb", "certificate", "trollstore"]), "settings dialog persists startup and order through actual MainWindow handler");
            var reopened = new MainWindow { ShowInTaskbar = false, Opacity = 0 };
            Check(Control<RadioButton>(reopened, "DebModeRadioButton").IsChecked == true && TabNames(reopened)[0] == "DebModeRadioButton", "recreated window restores saved tab and order");
            reopened.Close();

            Invoke(main, "SelectFiles", (object)new[] { firstIpa, secondIpa });
            var queueItems = Control<ItemsControl>(main, "QueueItemsControl");
            Check(queueItems.Items.Count == 2 && Control<Button>(main, "InstallButton").IsEnabled, "multiple IPA files populate the visible queue and enable install");
            Invoke(main, "SelectFiles", (object)new[] { firstIpa });
            Check(queueItems.Items.Count == 2, "adding a duplicate leaves the visible queue unchanged");
            Control<RadioButton>(main, "IpaModeRadioButton").IsChecked = true;
            Check(queueItems.Items.Count == 0, "TrollStore has a separate queue from certificate mode");
            Invoke(main, "SelectFiles", (object)new[] { secondIpa });
            Control<RadioButton>(main, "CertificateModeRadioButton").IsChecked = true;
            Check(queueItems.Items.Count == 2, "switching modes restores the original certificate queue");
            Invoke(main, "SelectFiles", (object)new[] { firstIpa, deb });
            Check(queueItems.Items.Count == 2 && Control<RadioButton>(main, "CertificateModeRadioButton").IsChecked == true, "mixed IPA and DEB selection cannot silently change mode or modify its queue");
            Invoke(main, "SelectFiles", (object)new[] { deb });
            Check(Control<RadioButton>(main, "DebModeRadioButton").IsChecked == true && queueItems.Items.Count == 1, "DEB selection opens its own queue");
            Control<RadioButton>(main, "CertificateModeRadioButton").IsChecked = true;
            var firstItem = (InstallQueueItem)queueItems.Items[0];
            firstItem.SetState(InstallQueueState.Succeeded);
            Invoke(main, "UpdateQueueView");
            Check(Control<TextBlock>(main, "QueueSummaryText").Text.Contains("установлено: 1") && Control<Button>(main, "InstallButton").Content.ToString()!.Contains("Продолжить (1)"), "visible counts and retry button distinguish already installed files");
            Invoke(main, "RemoveQueueItem_Click", new Button { Tag = firstItem }, new RoutedEventArgs());
            Check(queueItems.Items.Count == 1 && ((InstallQueueItem)queueItems.Items[0]).Number == 1, "remove control removes only its targeted item and renumbers remaining items");

            var selection = Control<ComboBox>(main, "SavedCertificateComboBox");
            var placeholder = new SavedCertificateInfo(Guid.Empty, "New", "", DateTimeOffset.MaxValue);
            var saved = new SavedCertificateInfo(Guid.NewGuid(), "Saved test identity", "Summary", DateTimeOffset.UtcNow.AddDays(1));
            selection.ItemsSource = new[] { placeholder, saved };
            selection.SelectedItem = saved;
            Check(!Control<PasswordBox>(main, "CertificatePasswordBox").IsEnabled && Control<Button>(main, "DeleteCertificateButton").IsEnabled, "saved certificate disables password input and enables delete");
            Check(Control<TextBlock>(main, "CertificatePathText").Text == saved.Name && Control<TextBlock>(main, "ProvisionPathText").Text == saved.Summary, "saved certificate fields show selected identity");
            selection.SelectedItem = placeholder;
            Check(Control<PasswordBox>(main, "CertificatePasswordBox").IsEnabled && !Control<Button>(main, "DeleteCertificateButton").IsEnabled, "new certificate re-enables inputs and prevents saved deletion");
            Invoke(main, "SetBusy", true);
            Check(!Control<RadioButton>(main, "CertificateModeRadioButton").IsEnabled && !Control<Button>(main, "HeaderSettingsButton").IsEnabled && !Control<Border>(main, "CertificateCard").IsEnabled, "busy state locks certificate and mode controls");
            Check(!Control<Button>(main, "ClearQueueButton").IsEnabled && !queueItems.IsEnabled, "busy state prevents queue edits");
            Invoke(main, "SelectFiles", (object)new[] { firstIpa });
            Check(queueItems.Items.Count == 1, "files cannot be appended while installation is running");
            using var operation = new CancellationTokenSource();
            SetField(main, "operation", operation); SetField(main, "queueRunning", true); SetField(main, "installing", true);
            Invoke(main, "Cancel_Click", main, new RoutedEventArgs());
            Check(!operation.IsCancellationRequested && GetField<bool>(main, "stopRequested"), "stop during mutation requests queue stop without canceling current installation");
            SetField(main, "installing", false); SetField(main, "stopRequested", false);
            Invoke(main, "Cancel_Click", main, new RoutedEventArgs());
            Check(operation.IsCancellationRequested, "stop during preparation cancels the cancellable operation");
            SetField(main, "operation", null); SetField(main, "queueRunning", false); SetField(main, "stopRequested", false);
            Invoke(main, "SetBusy", false);
            Check(Control<RadioButton>(main, "CertificateModeRadioButton").IsEnabled && Control<Button>(main, "HeaderSettingsButton").IsEnabled && Control<Border>(main, "CertificateCard").IsEnabled, "completed or failed operation restores editable controls");
            Invoke(main, "ClearQueue_Click", main, new RoutedEventArgs());
            Check(queueItems.Items.Count == 0 && !Control<Button>(main, "InstallButton").IsEnabled && Control<Border>(main, "QueueCard").Visibility == Visibility.Collapsed, "clear queue hides it and disables install");
            main.Close();
            Console.WriteLine($"Passed {checks} WPF UI checks.");
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e); return 1; }
        finally
        {
            if (previous is null) File.Delete(AppSettings.SettingsPath); else File.WriteAllBytes(AppSettings.SettingsPath, previous);
            if (Directory.Exists(fixtures)) Directory.Delete(fixtures, true);
            app.Shutdown();
        }
    }
    private static void Check(bool condition, string message) { if (!condition) throw new Exception(message); checks++; Console.WriteLine("PASS " + message); }
    private static T Control<T>(MainWindow window, string name) where T : class => window.FindName(name) as T ?? throw new Exception("Missing " + name);
    private static string[] TabNames(MainWindow window) => Control<StackPanel>(window, "ModeTabsPanel").Children.OfType<RadioButton>().Select(b => b.Name).ToArray();
    private static void Invoke(object target, string method, params object[] args) => target.GetType().GetMethod(method, BindingFlags.Instance | BindingFlags.NonPublic)!.Invoke(target, args);
    private static void SetField(object target, string name, object? value) => target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.SetValue(target, value);
    private static T GetField<T>(object target, string name) => (T)target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)!.GetValue(target)!;
    private static IEnumerable<DependencyObject> Descendants(DependencyObject parent)
    {
        foreach (var child in LogicalTreeHelper.GetChildren(parent).OfType<DependencyObject>())
        { yield return child; foreach (var descendant in Descendants(child)) yield return descendant; }
    }
}
