using System.ComponentModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Microsoft.Win32;
using Renci.SshNet.Common;
using TrollDock.Services;
using TrollDock.Transport;

namespace TrollDock;

public partial class MainWindow : Window
{
    private AppSettings settings = new();
    private DeviceSession? session;
    private CancellationTokenSource? operation;
    private bool busy, installing, initialized, queueRunning, stopRequested;
    private readonly Dictionary<string, InstallQueue> queues = new()
    { ["trollstore"] = new(), ["certificate"] = new(), ["deb"] = new() };
    private string? certificatePath, provisionPath;
    private string mode = "trollstore";
    private readonly CertificateVault certificateVault = new();
    private readonly bool preview = Environment.GetCommandLineArgs().Contains("--preview");
    private bool IsDeb => mode == "deb";
    private bool IsCertificate => mode == "certificate";
    private string CurrentMode => mode;
    private InstallQueue CurrentQueue => queues[CurrentMode];
    public MainWindow()
    {
        InitializeComponent();
        Height = Math.Min(Height, Math.Max(MinHeight, SystemParameters.WorkArea.Height - 24));
        try { settings = AppSettings.Load(); }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Настройки TrollDock", MessageBoxButton.OK, MessageBoxImage.Error); IsEnabled = false; }
        UsernameBox.Text = settings.Username;
        try { PasswordBox.Password = settings.ReadPassword(); }
        catch { AddLog("Сохранённый пароль недоступен для этой учётной записи Windows. Введите его заново."); }
        RememberPasswordCheckBox.IsChecked = !string.IsNullOrEmpty(settings.EncryptedPassword);
        if (PasswordBox.Password.Length == 0) PasswordBox.Password = "alpine";
        DeviceComboBox.DisplayMemberPath = "Name";
        ApplyModeOrder();
        ModeButton(settings.StartupMode).IsChecked = true;
        initialized = true;
        Mode_Changed(this, new RoutedEventArgs());
        RefreshSavedCertificates();
        Loaded += async (_, _) =>
        {
            if (preview) { await RenderPreviewAsync(); return; }
            try
            {
                var failures = await Task.Run(() => SigningWorkspace.CleanupAbandoned());
                foreach (var folder in failures) AddLog("Windows не дал очистить оставшуюся временную папку подписи: " + folder);
                if (failures.Count > 0) { StageText.Text = "Не все временные файлы удалены"; DetailText.Text = "Закройте программу, блокирующую папку, и перезапустите TrollDock. Путь указан в журнале."; LogExpander.IsExpanded = true; }
            }
            catch (Exception ex) { AddLog("Очистка временных файлов: " + ex.Message); }
            await RefreshDevicesAsync();
        };
        Closing += Window_Closing;
    }
    private void AddLog(string message)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(() => AddLog(message)); return; }
        LogTextBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {message}\r\n");
        if (LogTextBox.Text.Length > 180000) LogTextBox.Text = LogTextBox.Text[^140000..];
        LogTextBox.ScrollToEnd();
    }
    private async Task RefreshDevicesAsync()
    {
        RefreshButton.IsEnabled = false;
        try
        {
            var serial = (DeviceComboBox.SelectedItem as UsbDevice)?.SerialNumber ?? settings.LastSerial;
            var devices = await new UsbMuxClient().ListDevicesAsync();
            DeviceComboBox.ItemsSource = devices;
            DeviceComboBox.SelectedItem = devices.FirstOrDefault(d => d.SerialNumber == serial) ?? (devices.Count == 1 ? devices[0] : null);
            if (devices.Count == 0) { ConnectionStatusText.Text = "Подключите iPhone по USB"; AddLog("iPhone не найден. Разблокируйте экран, подтвердите доверие компьютеру и нажмите «Обновить»."); }
            else if (session?.Connected != true) ConnectionStatusText.Text = devices.Count == 1 ? "iPhone найден · USB" : "Выберите iPhone";
        }
        catch (Exception ex) { ConnectionStatusText.Text = "USB пока недоступен"; AddLog("USB: " + ex.Message + " Нужен драйвер Apple Mobile Device (Apple Devices, iTunes или 3uTools). Можно использовать готовый локальный туннель в настройках."); }
        finally { RefreshButton.IsEnabled = !busy; }
    }
    private async void RefreshDevices_Click(object sender, RoutedEventArgs e) => await RefreshDevicesAsync();
    private void ChooseIpa_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Filter = IsDeb ? "Пакеты DEB (*.deb)|*.deb" : "Приложения IPA (*.ipa)|*.ipa", CheckFileExists = true, Multiselect = true };
        if (dialog.ShowDialog(this) == true) SelectFiles(dialog.FileNames);
    }
    private void SelectFiles(string[] paths)
    {
        if (busy || paths.Length == 0) return;
        try
        {
            var extensions = paths.Select(path => Path.GetExtension(path).ToLowerInvariant()).Distinct().ToArray();
            if (extensions.Length != 1 || extensions[0] is not ".ipa" and not ".deb")
                throw new IOException("Выберите несколько IPA или несколько DEB. Смешивать их в одной очереди нельзя.");
            if (extensions[0] == ".deb") DebModeRadioButton.IsChecked = true; else if (!IsCertificate) IpaModeRadioButton.IsChecked = true;
            var added = CurrentQueue.AddFiles(paths, extensions[0]);
            UpdateQueueView();
            StageText.Text = added > 0 ? "Файлы добавлены в очередь" : "Эти файлы уже в очереди";
            DetailText.Text = "Можно добавить ещё файлы или запустить установку.";
        }
        catch (Exception ex) { ShowError(ex); }
    }
    private void Mode_Changed(object sender, RoutedEventArgs e)
    {
        if (!initialized) return;
        mode = sender is RadioButton selected ? selected == DebModeRadioButton ? "deb" : selected == CertificateModeRadioButton ? "certificate" : "trollstore"
            : DebModeRadioButton.IsChecked == true ? "deb" : CertificateModeRadioButton.IsChecked == true ? "certificate" : "trollstore";
        // Keep a single selected mode even when tabs have just been reordered/reparented.
        foreach (var name in new[] { "trollstore", "certificate", "deb" }) ModeButton(name).IsChecked = name == mode;
        var type = IsDeb ? "DEB" : "IPA";
        FileTypeText.Text = type;
        ChooseIpaButton.Content = "Добавить " + type;
        System.Windows.Automation.AutomationProperties.SetName(ChooseIpaButton, "Добавить файлы " + type);
        StageText.Text = "Готовы к установке";
        DetailText.Text = IsDeb ? "Выберите DEB. Пакеты и их зависимости установятся одной операцией APT."
            : IsCertificate ? "Выберите IPA, сертификат и профиль. Копии подпишутся и установятся по очереди; временные файлы удалятся без корзины."
            : "Выберите IPA. Программа найдёт TrollStore и установит приложения по очереди.";
        InstallProgressBar.Value = 0; TransferText.Text = "";
        QueueHintText.Text = IsDeb ? "DEB устанавливаются вместе: выбранные пакеты могут зависеть друг от друга. Повтор пропускает подтверждённые установки."
            : "При ошибке очередь остановится. Повтор запускает только незавершённые файлы.";
        UpdateQueueView();
    }
    private void UpdateQueueView()
    {
        var queue = CurrentQueue;
        var type = IsDeb ? "DEB" : "IPA";
        QueueItemsControl.ItemsSource = queue.Items;
        QueueCard.Visibility = queue.Items.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        QueueSummaryText.Text = $"Файлов: {queue.Items.Count} · установлено: {queue.Completed} · осталось: {queue.Remaining}";
        IpaNameText.Text = queue.Items.Count == 0 ? $"Перетащите сюда файлы .{type.ToLowerInvariant()}" : $"В очереди: {queue.Items.Count} {type}";
        IpaPathText.Text = queue.Items.Count == 0 ? "Или выберите несколько файлов на компьютере" : "Добавляйте файлы кнопкой или перетаскиванием";
        IpaPathText.ToolTip = null;
        IpaSizeText.Text = queue.Items.Count == 0 ? "" : $"{queue.Items.Sum(item => item.Length) / 1048576.0:N1} МБ всего";
        ClearQueueButton.IsEnabled = !busy && queue.Items.Count > 0;
        QueueItemsControl.IsEnabled = !busy;
        InstallButton.IsEnabled = !busy && queue.Remaining > 0;
        InstallButton.Content = queue.Completed > 0 && queue.Remaining > 0 ? $"Продолжить ({queue.Remaining})  →"
            : IsCertificate ? "Подписать и установить  →" : "Установить на iPhone  →";
    }
    private void ClearQueue_Click(object sender, RoutedEventArgs e) { if (!busy) { CurrentQueue.Clear(); UpdateQueueView(); } }
    private void RemoveQueueItem_Click(object sender, RoutedEventArgs e)
    { if (!busy && sender is Button { Tag: InstallQueueItem item }) { CurrentQueue.Remove(item); UpdateQueueView(); } }
    private void Ipa_DragOver(object sender, DragEventArgs e) { e.Effects = !busy && e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None; e.Handled = true; }
    private void Ipa_Drop(object sender, DragEventArgs e)
    {
        if (!busy && e.Data.GetData(DataFormats.FileDrop) is string[] files) SelectFiles(files);
    }
    private void SetBusy(bool value)
    {
        busy = value;
        ChooseIpaButton.IsEnabled = RefreshButton.IsEnabled = ConnectButton.IsEnabled = DeviceComboBox.IsEnabled = !value;
        IpaModeRadioButton.IsEnabled = DebModeRadioButton.IsEnabled = CertificateModeRadioButton.IsEnabled = ConnectionSettingsExpander.IsEnabled = !value;
        HeaderSettingsButton.IsEnabled = CertificateCard.IsEnabled = !value;
        UpdateQueueView();
        CancelButton.IsEnabled = value && !stopRequested && (queueRunning || !installing);
        CancelButton.Content = queueRunning ? "Остановить" : "Отмена";
        RespringButton.IsEnabled = !value && session?.Connected == true;
        if (!value) InstallProgressBar.IsIndeterminate = false;
    }
    private async Task ConnectAsync(CancellationToken token)
    {
        ConnectionStatusText.Text = "Подключение…"; ConnectionDot.Fill = new SolidColorBrush(Color.FromRgb(232, 166, 54));
        if (!int.TryParse(TunnelPortBox.Text, out var port) || port < 1 || port > 65535) throw new IOException("Укажите корректный SSH-порт.");
        if (PasswordBox.Password.Length == 0) { ConnectionSettingsExpander.IsExpanded = true; throw new IOException("Введите пароль SSH в настройках подключения."); }
        if (AutoUsbRadioButton.IsChecked == true && DeviceComboBox.SelectedItem == null) await RefreshDevicesAsync();
        var options = new ConnectionOptions(DeviceComboBox.SelectedItem as UsbDevice, AutoUsbRadioButton.IsChecked == true,
            TunnelHostBox.Text.Trim(), port, UsernameBox.Text.Trim(), PasswordBox.Password);
        if (session != null) await session.DisposeAsync();
        session = new DeviceSession(settings, AddLog);
        await session.ConnectAsync(options, token);
        settings.Username = options.Username; settings.LastSerial = options.Device?.SerialNumber ?? "";
        try { settings.SetPassword(options.Password, RememberPasswordCheckBox.IsChecked == true); settings.Save(); }
        catch (Exception ex) { throw new IOException("Не удалось сохранить настройки или зашифровать пароль. Снимите галочку «Запомнить пароль» и убедитесь, что папка программы доступна для записи.", ex); }
        ConnectionStatusText.Text = "iPhone подключён · SSH"; ConnectionDot.Fill = new SolidColorBrush(Color.FromRgb(41, 174, 117));
        AddLog("Подключение готово. Пароль " + (RememberPasswordCheckBox.IsChecked == true ? "сохранён с шифрованием Windows." : "не сохраняется."));
    }
    private async void Connect_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return; operation = new(); installing = false; stopRequested = false; SetBusy(true);
        try { StageText.Text = "Проверка подключения"; DetailText.Text = "Подключаюсь и ищу TrollStore…"; await ConnectAsync(operation.Token); StageText.Text = "Связь проверена"; DetailText.Text = session!.TrollStorePath.Length > 0 ? "TrollStore найден. Можно устанавливать IPA и DEB." : "SSH работает. TrollStore не найден; доступна установка DEB."; }
        catch (Exception ex) { ShowError(ex); }
        finally { operation.Dispose(); operation = null; SetBusy(false); }
    }
    private async void Install_Click(object sender, RoutedEventArgs e)
    {
        if (busy || CurrentQueue.Remaining == 0) return;
        var queue = CurrentQueue; var deb = IsDeb; var certificateMode = IsCertificate;
        operation = new(); installing = false; stopRequested = false; queueRunning = true; SetBusy(true);
        InstallationStatusCard.BringIntoView();
        InstallQueueItem? activeItem = null;
        try
        {
            StageText.Text = "Подключение"; DetailText.Text = "Готовлю установку…";
            // Progress<T> posts asynchronously and can deliver a stale cancellable stage after
            // mutation has started. Dispatch synchronously to keep the stop button truthful.
            var progress = new SynchronousProgress<TransferProgress>(Dispatcher, p =>
            {
                StageText.Text = activeItem is null ? p.Stage : $"{activeItem.Number}/{queue.Items.Count} · {activeItem.FileName} · {p.Stage}";
                DetailText.Text = stopRequested ? "Остановимся после текущей операции. " + p.Detail : p.Detail;
                installing = !p.CanCancel;
                CancelButton.IsEnabled = busy && !stopRequested;
                CancelButton.Content = installing ? "После текущего" : "Остановить";
                CancelButton.ToolTip = installing ? "Завершить текущую установку и не начинать следующие файлы" : "Отменить текущую подготовку и остановить очередь";
                InstallProgressBar.IsIndeterminate = p.Percent < 0;
                if (p.Percent >= 0) InstallProgressBar.Value = p.Percent;
                TransferText.Text = $"{queue.Completed}/{queue.Items.Count}" + (p.Percent is >= 0 and < 100 ? $" · {p.Percent:N0}%" : "");
                QueueSummaryText.Text = $"Файлов: {queue.Items.Count} · установлено: {queue.Completed} · осталось: {queue.Remaining}";
                if (p.Stage == "Установлено") AddLog(p.Detail);
            });
            InstallQueueRunResult result;
            if (certificateMode)
            {
                if (DeviceComboBox.SelectedItem is not UsbDevice) await RefreshDevicesAsync();
                var device = DeviceComboBox.SelectedItem as UsbDevice ?? throw new IOException("Выберите нужный iPhone в списке USB-устройств.");
                using var material = await LoadSigningMaterialAsync();
                if (SaveCertificateCheckBox.IsChecked == true && SavedCertificateComboBox.SelectedItem is SavedCertificateInfo { Id: var savedId } && savedId == Guid.Empty)
                {
                    var name = CertificateNameBox.Text;
                    var saved = await Task.Run(() => certificateVault.Save(name, material)); RefreshSavedCertificates(saved.Id); SaveCertificateCheckBox.IsChecked = false;
                }
                settings.LastSerial = device.SerialNumber; settings.Save();
                ConnectionStatusText.Text = "iPhone выбран · USB";
                var workflow = new CertificateInstallWorkflow();
                result = await queue.RunAsync(async item =>
                {
                    activeItem = item; AddLog($"[{item.Number}/{queue.Items.Count}] {item.FileName}");
                    await workflow.InstallAsync(item.Path, material, device.SerialNumber, progress, AddLog, operation.Token);
                    AddLog("Установлено: " + item.FileName);
                }, () => stopRequested, operation.Token);
            }
            else
            {
                // One connection for the entire queue; capture the selected device and credentials.
                await ConnectAsync(operation.Token);
                if (deb)
                {
                    result = await queue.RunBatchAsync(async items =>
                    {
                        var batch = await session!.InstallDebBatchAsync(items.Select(item => item.Path).ToArray(), progress, operation.Token);
                        return new InstallQueueBatchOutcome(batch.Items.Select(item => new InstallQueueOutcome(item.LocalPath, item.Installed, item.Message)).ToArray(), batch.Error);
                    }, () => stopRequested, operation.Token);
                }
                else result = await queue.RunAsync(async item =>
                {
                    activeItem = item; AddLog($"[{item.Number}/{queue.Items.Count}] {item.FileName}");
                    await session!.InstallAsync(item.Path, false, progress, operation.Token);
                    AddLog("Установлено: " + item.FileName);
                }, () => stopRequested, operation.Token);
            }
            if (result.Error is not null) { ShowError(result.Error); AddLog("Очередь остановлена. Подтверждённые установки при повторе будут пропущены."); }
            else if (result.Stopped && queue.Remaining > 0)
            {
                StageText.Text = "Очередь остановлена";
                DetailText.Text = $"Установлено: {queue.Completed} из {queue.Items.Count}. Незавершённые файлы остались в очереди; можно продолжить.";
                AddLog(DetailText.Text);
            }
            else
            {
                StageText.Text = $"Установлено: {queue.Completed} из {queue.Items.Count}";
                DetailText.Text = deb ? "Пакеты установлены. Для твиков при необходимости перезапустите интерфейс iPhone."
                    : certificateMode ? "Приложения установлены. Временные подписанные IPA удалены без корзины; исходные файлы сохранены." : "Приложения установлены через TrollStore.";
                InstallProgressBar.Value = 100; AddLog(StageText.Text);
            }
        }
        catch (OperationCanceledException) { StageText.Text = "Очередь остановлена"; DetailText.Text = $"Подтверждено установок: {queue.Completed}. Остальные файлы остались в очереди."; AddLog("Операция отменена."); if (session?.Connected != true && !certificateMode) ConnectionStatusText.Text = "Соединение закрыто"; }
        catch (Exception ex) { ShowError(ex); }
        finally { installing = false; queueRunning = false; stopRequested = false; operation.Dispose(); operation = null; SetBusy(false); TransferText.Text = $"{queue.Completed}/{queue.Items.Count}"; }
    }
    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        if (!busy) return;
        if (queueRunning) stopRequested = true;
        if (!installing) operation?.Cancel();
        CancelButton.IsEnabled = false;
        DetailText.Text = installing ? "Текущая установка завершится. Следующие файлы запускаться не будут." : "Останавливаю подготовку. Дождитесь очистки временных файлов.";
    }
    private sealed class SynchronousProgress<T>(System.Windows.Threading.Dispatcher dispatcher, Action<T> report) : IProgress<T>
    {
        public void Report(T value)
        {
            if (dispatcher.CheckAccess()) report(value); else dispatcher.Invoke(() => report(value));
        }
    }
    private async void Respring_Click(object sender, RoutedEventArgs e)
    {
        if (busy || session?.Connected != true) return;
        SetBusy(true); installing = true; CancelButton.IsEnabled = false;
        try { StageText.Text = "Перезапуск интерфейса"; DetailText.Text = "Экран iPhone ненадолго погаснет."; await session.RespringAsync(); StageText.Text = "Команда отправлена"; DetailText.Text = "Дождитесь появления экрана блокировки iPhone."; }
        catch (Exception ex) { ShowError(ex); }
        finally { installing = false; SetBusy(false); }
    }
    private void ShowError(Exception ex)
    {
        var message = ex is SshAuthenticationException ? "Не подошли имя пользователя или пароль SSH. Исправьте их в настройках подключения." : ex.Message;
        if (ex is SshAuthenticationException) ConnectionSettingsExpander.IsExpanded = true;
        StageText.Text = "Не удалось завершить"; DetailText.Text = message; AddLog(message); LogExpander.IsExpanded = true;
        InstallProgressBar.IsIndeterminate = false;
        if (!IsCertificate && session?.Connected != true) { ConnectionStatusText.Text = "Нет подключения"; ConnectionDot.Fill = new SolidColorBrush(Color.FromRgb(194, 91, 77)); }
    }
    private async void Window_Closing(object? sender, CancelEventArgs e)
    {
        if (busy) { e.Cancel = true; DetailText.Text = installing ? "Идёт установка. Дождитесь её завершения перед закрытием программы." : "Сначала отмените текущую операцию."; return; }
        if (session != null) try { await session.DisposeAsync(); } catch { }
    }
    private async Task RenderPreviewAsync()
    {
        await Task.Delay(250);
        if (Environment.GetCommandLineArgs().Contains("--certificate")) CertificateModeRadioButton.IsChecked = true;
        if (Environment.GetCommandLineArgs().Contains("--batch"))
        {
            var extension = IsDeb ? ".deb" : ".ipa";
            foreach (var name in new[] { "Музыкальный плеер", "Приложение для заметок", "Карта путешествий" })
                CurrentQueue.Items.Add(new InstallQueueItem("C:\\Apps\\" + name + extension, 48_000_000) { Number = CurrentQueue.Items.Count + 1 });
            CurrentQueue.Items[0].SetState(InstallQueueState.Succeeded);
            CurrentQueue.Items[1].SetState(InstallQueueState.Failed, "Демонстрация состояния очереди");
            UpdateQueueView();
        }
        ConnectionStatusText.Text = "iPhone найден · USB";
        DeviceComboBox.ItemsSource = new[] { new UsbDevice(1, "preview", "iPhone · USB") }; DeviceComboBox.SelectedIndex = 0;
        UpdateLayout();
        Window rendered = this;
        if (Environment.GetCommandLineArgs().Contains("--settings")) { rendered = new SettingsWindow(settings) { Owner = this, Resources = Resources }; rendered.Show(); rendered.UpdateLayout(); }
        var visual = rendered.Content as FrameworkElement ?? rendered;
        var image = new RenderTargetBitmap((int)visual.ActualWidth, (int)visual.ActualHeight, 96, 96, PixelFormats.Pbgra32); image.Render(visual);
        var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(image));
        var args = Environment.GetCommandLineArgs(); var index = Array.IndexOf(args, "--preview");
        using (var output = File.Create(args[index + 1])) encoder.Save(output);
        if (rendered != this) rendered.Close();
        Close();
    }

    private RadioButton ModeButton(string mode) => mode switch { "deb" => DebModeRadioButton, "certificate" => CertificateModeRadioButton, _ => IpaModeRadioButton };
    private void ApplyModeOrder()
    {
        settings.NormalizeModes(); var buttons = settings.ModeOrder.Select(ModeButton).ToArray();
        ModeTabsPanel.Children.Clear(); foreach (var button in buttons) ModeTabsPanel.Children.Add(button);
    }
    private void Settings_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return;
        var dialog = new SettingsWindow(settings) { Owner = this, Resources = Resources };
        if (dialog.ShowDialog() != true) return;
        var previousMode = settings.StartupMode; var previousOrder = settings.ModeOrder;
        try { settings.StartupMode = dialog.SelectedStartup; settings.ModeOrder = dialog.SelectedOrder; settings.Save(); ApplyModeOrder(); AddLog("Настройки вкладок сохранены."); }
        catch (Exception ex) { settings.StartupMode = previousMode; settings.ModeOrder = previousOrder; ShowError(ex); }
    }
    private void RefreshSavedCertificates(Guid? select = null)
    {
        try
        {
            var list = new List<SavedCertificateInfo> { new(Guid.Empty, "Новый сертификат…", "Выберите P12/PFX и профиль", DateTimeOffset.MaxValue) };
            list.AddRange(certificateVault.List()); SavedCertificateComboBox.ItemsSource = list;
            SavedCertificateComboBox.SelectedItem = list.FirstOrDefault(c => c.Id == select) ?? list[0];
        }
        catch (Exception ex) { AddLog("Не удалось прочитать сохранённые сертификаты: " + ex.Message); }
    }
    private void SavedCertificate_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!initialized || SavedCertificateComboBox.SelectedItem is not SavedCertificateInfo saved) return;
        bool existing = saved.Id != Guid.Empty;
        DeleteCertificateButton.IsEnabled = existing;
        certificatePath = provisionPath = null; CertificatePasswordBox.Clear(); CertificatePasswordBox.IsEnabled = !existing;
        CertificatePathText.Text = existing ? saved.Name : "Сертификат не выбран";
        ProvisionPathText.Text = existing ? saved.Summary : "Профиль не выбран";
        SaveCertificateCheckBox.IsChecked = false; SaveCertificateCheckBox.IsEnabled = !existing;
        CertificateNameBox.Text = existing ? saved.Name : "";
    }
    private void ChooseCertificate_Click(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFileDialog { Filter = "Сертификат (*.p12;*.pfx)|*.p12;*.pfx", CheckFileExists = true };
        if (picker.ShowDialog(this) != true) return;
        if (SavedCertificateComboBox.SelectedItem is SavedCertificateInfo saved && saved.Id != Guid.Empty) SavedCertificateComboBox.SelectedIndex = 0;
        certificatePath = picker.FileName; CertificatePathText.Text = Path.GetFileName(certificatePath); CertificatePathText.ToolTip = certificatePath;
        if (string.IsNullOrWhiteSpace(CertificateNameBox.Text)) CertificateNameBox.Text = Path.GetFileNameWithoutExtension(certificatePath);
    }
    private void ChooseProvision_Click(object sender, RoutedEventArgs e)
    {
        var picker = new OpenFileDialog { Filter = "Профиль (*.mobileprovision)|*.mobileprovision", CheckFileExists = true };
        if (picker.ShowDialog(this) != true) return;
        if (SavedCertificateComboBox.SelectedItem is SavedCertificateInfo saved && saved.Id != Guid.Empty) SavedCertificateComboBox.SelectedIndex = 0;
        provisionPath = picker.FileName; ProvisionPathText.Text = Path.GetFileName(provisionPath); ProvisionPathText.ToolTip = provisionPath;
    }
    private Task<SigningMaterial> LoadSigningMaterialAsync()
    {
        if (SavedCertificateComboBox.SelectedItem is SavedCertificateInfo saved && saved.Id != Guid.Empty)
            return Task.Run(() => certificateVault.Load(saved.Id));
        var certificate = certificatePath ?? throw new IOException("Выберите сертификат .p12 или .pfx.");
        var profile = provisionPath ?? throw new IOException("Выберите профиль .mobileprovision.");
        var password = CertificatePasswordBox.Password;
        return Task.Run(() => SigningMaterial.Load(certificate, profile, password));
    }
    private async void SaveCertificate_Click(object sender, RoutedEventArgs e)
    {
        if (busy) return; SetBusy(true); CancelButton.IsEnabled = false;
        try
        {
            var name = CertificateNameBox.Text; using var material = await LoadSigningMaterialAsync();
            var saved = await Task.Run(() => certificateVault.Save(name, material)); RefreshSavedCertificates(saved.Id);
            StageText.Text = "Сертификат сохранён"; DetailText.Text = "«" + saved.Name + "» — " + saved.Summary; AddLog("Сертификат сохранён с шифрованием Windows: " + saved.Name);
        }
        catch (Exception ex) { ShowError(ex); }
        finally { SetBusy(false); }
    }
    private void DeleteCertificate_Click(object sender, RoutedEventArgs e)
    {
        if (busy || SavedCertificateComboBox.SelectedItem is not SavedCertificateInfo saved || saved.Id == Guid.Empty) return;
        try { certificateVault.Delete(saved.Id); RefreshSavedCertificates(); AddLog("Сохранённая копия сертификата удалена: " + saved.Name + ". Исходные файлы не изменялись."); }
        catch (Exception ex) { ShowError(ex); }
    }
}
