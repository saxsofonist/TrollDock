using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using TrollDock.Services;

namespace TrollDock;

public sealed class RootPasswordWindow : Window
{
    private readonly ConnectionOptions options;
    private readonly Func<ConnectionOptions, string, IProgress<RootPasswordProgress>, CancellationToken, Task<RootPasswordResult>> setPassword;
    private readonly PasswordBox mobilePassword, newPassword, confirmation;
    private readonly CheckBox remember;
    private readonly Button apply, cancel;
    private readonly TextBlock status;
    private readonly ProgressBar progress;
    private CancellationTokenSource? operation;
    private bool busy, canCancel = true, retryAllowed = true, closeWhenFinished, mutationStarted;
    private string verifiedPassword = "";
    public bool RememberPassword { get; private set; }

    public RootPasswordWindow(AppSettings settings, ConnectionOptions options, bool rememberPassword,
        Func<ConnectionOptions, string, IProgress<RootPasswordProgress>, CancellationToken, Task<RootPasswordResult>>? setPassword = null)
    {
        this.options = options with { Username = "mobile", Password = "" };
        this.setPassword = setPassword ?? new RootPasswordService(settings).SetAsync;
        Title = "Пароль root · TrollDock"; Width = 550; SizeToContent = SizeToContent.Height;
        MaxHeight = Math.Max(520, SystemParameters.WorkArea.Height - 32);
        ResizeMode = ResizeMode.NoResize; WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = new SolidColorBrush(Color.FromRgb(243, 246, 250));
        FontFamily = new FontFamily("Segoe UI"); FontSize = 13;
        NameScope.SetNameScope(this, new NameScope());
        var panel = new StackPanel { Margin = new Thickness(26) };
        Content = new ScrollViewer { Content = panel, Background = Background, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled };
        panel.Children.Add(new TextBlock { Text = "Задать пароль root", FontSize = 23, FontWeight = FontWeights.SemiBold });
        var target = options.AutoUsb ? options.Device?.Name ?? "iPhone не выбран" : $"Локальный туннель · {options.Host}:{options.Port}";
        panel.Children.Add(new TextBlock { Text = target, TextWrapping = TextWrapping.Wrap, Foreground = Brushes.SlateGray, Margin = new Thickness(0, 7, 0, 16) });
        panel.Children.Add(new TextBlock
        {
            Text = "Программа войдёт под mobile, задаст пароль root через sudo и проверит отдельный вход под root. Нужны активный jailbreak, OpenSSH и доступ mobile к sudo.",
            TextWrapping = TextWrapping.Wrap, Foreground = new SolidColorBrush(Color.FromRgb(82, 100, 126)), Margin = new Thickness(0, 0, 0, 18)
        });
        mobilePassword = AddPassword(panel, "MobilePasswordBox", "Пароль mobile", "Пароль, заданный при настройке jailbreak");
        newPassword = AddPassword(panel, "NewRootPasswordBox", "Новый пароль root", "Рекомендуем не менее 8 символов");
        confirmation = AddPassword(panel, "ConfirmRootPasswordBox", "Повторите новый пароль root", null);
        remember = new CheckBox { Name = "RememberRootPasswordCheckBox", Content = "Запомнить пароль root с шифрованием Windows", IsChecked = rememberPassword, Margin = new Thickness(0, 2, 0, 15) };
        RegisterName(remember.Name, remember); panel.Children.Add(remember);
        panel.Children.Add(new TextBlock { Text = "Пароль mobile не сохраняется. Пароль на iPhone изменится только после нажатия кнопки ниже.", TextWrapping = TextWrapping.Wrap, FontSize = 11, Foreground = Brushes.SlateGray, Margin = new Thickness(0, 0, 0, 15) });
        status = new TextBlock { Name = "RootPasswordStatusText", Text = "Введите пароль mobile и новый пароль root.", TextWrapping = TextWrapping.Wrap, Foreground = new SolidColorBrush(Color.FromRgb(65, 86, 113)), MinHeight = 38 };
        RegisterName(status.Name, status); panel.Children.Add(status);
        progress = new ProgressBar { Height = 4, Visibility = Visibility.Collapsed, Margin = new Thickness(0, 10, 0, 0) }; panel.Children.Add(progress);
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right, Margin = new Thickness(0, 18, 0, 0) };
        cancel = new Button { Name = "CancelRootPasswordButton", Content = "Отмена", Padding = new Thickness(18, 9, 18, 9), Margin = new Thickness(0, 0, 10, 0), IsCancel = false };
        apply = new Button { Name = "ApplyRootPasswordButton", Content = "Задать и проверить", Padding = new Thickness(18, 9, 18, 9), IsDefault = true, IsEnabled = false, Background = new SolidColorBrush(Color.FromRgb(33, 101, 232)), Foreground = Brushes.White };
        RegisterName(apply.Name, apply); RegisterName(cancel.Name, cancel);
        apply.Opacity = 0.45; apply.IsEnabledChanged += (_, _) => apply.Opacity = apply.IsEnabled ? 1 : 0.45;
        buttons.Children.Add(cancel); buttons.Children.Add(apply); panel.Children.Add(buttons);
        foreach (var input in new[] { mobilePassword, newPassword, confirmation }) input.PasswordChanged += (_, _) => UpdateValidation();
        apply.Click += async (_, _) => await ApplyAsync();
        cancel.Click += (_, _) => { if (busy) RequestCancel(false); else Close(); };
        PreviewKeyDown += (_, e) => { if (e.Key == System.Windows.Input.Key.Escape) { if (busy) RequestCancel(false); else Close(); e.Handled = true; } };
        Closing += OnClosing;
        Closed += (_, _) => { mobilePassword.Clear(); newPassword.Clear(); confirmation.Clear(); };
    }

    public string TakeVerifiedPassword() { var value = verifiedPassword; verifiedPassword = ""; return value; }

    private PasswordBox AddPassword(Panel panel, string name, string label, string? hint)
    {
        panel.Children.Add(new TextBlock { Text = label, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 0, 0, 6) });
        var box = new PasswordBox { Name = name, Padding = new Thickness(10, 8, 10, 8), MaxLength = 1024, Margin = new Thickness(0, 0, 0, hint is null ? 15 : 5) };
        System.Windows.Automation.AutomationProperties.SetName(box, label);
        RegisterName(name, box); panel.Children.Add(box);
        if (hint is not null) panel.Children.Add(new TextBlock { Text = hint, FontSize = 11, Foreground = Brushes.SlateGray, Margin = new Thickness(0, 0, 0, 15) });
        return box;
    }

    private string? ValidationError()
    {
        try { RootPasswordService.ValidatePasswords(mobilePassword.Password, newPassword.Password); }
        catch (ArgumentException ex) { return ex.Message; }
        if (newPassword.Password != confirmation.Password) return "Новые пароли root не совпадают.";
        return null;
    }

    private void UpdateValidation()
    {
        if (busy || !retryAllowed) return;
        var error = ValidationError(); apply.IsEnabled = error is null;
        status.Text = error ?? "Готово к настройке. Проверьте выбранный iPhone и нажмите «Задать и проверить».";
    }

    private void SetBusy(bool value)
    {
        busy = value;
        mobilePassword.IsEnabled = newPassword.IsEnabled = confirmation.IsEnabled = remember.IsEnabled = !value && retryAllowed;
        apply.IsEnabled = !value && retryAllowed && ValidationError() is null;
        cancel.IsEnabled = !value || canCancel;
        cancel.Content = value ? "Отменить" : "Закрыть";
        progress.Visibility = value ? Visibility.Visible : Visibility.Collapsed; progress.IsIndeterminate = value;
    }

    private void ReportProgress(RootPasswordProgress value)
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.Invoke(() => ReportProgress(value)); return; }
        canCancel = value.CanCancel;
        if (!canCancel) mutationStarted = true;
        status.Text = value.Stage + "\n" + value.Detail;
        cancel.IsEnabled = canCancel;
    }

    private async Task ApplyAsync()
    {
        if (busy || !retryAllowed) return;
        if (ValidationError() is { } error) { status.Text = error; return; }
        var mobile = mobilePassword.Password; var chosen = newPassword.Password;
        var selectedRemember = remember.IsChecked == true;
        operation = new CancellationTokenSource(); canCancel = true; mutationStarted = false; closeWhenFinished = false; SetBusy(true);
        bool verified = false;
        try
        {
            var result = await setPassword(options with { Password = mobile }, chosen, new InlineProgress(ReportProgress), operation.Token);
            status.Text = result.Message;
            retryAllowed = !result.Verified && !result.PasswordChanged && !result.MayHaveChanged;
            if (result.Verified) { verifiedPassword = chosen; RememberPassword = selectedRemember; verified = true; }
        }
        catch (OperationCanceledException)
        {
            retryAllowed = !mutationStarted;
            status.Text = mutationStarted ? "Подтверждение не получено. Пароль мог измениться; проверьте вход root с выбранным новым паролем. Повторная смена автоматически не выполняется." : "Подготовка отменена. Изменение пароля не началось.";
        }
        catch
        {
            retryAllowed = !mutationStarted;
            status.Text = mutationStarted ? "Подтверждение не получено. Пароль мог измениться; проверьте вход root с выбранным новым паролем."
                : "Не удалось подготовить настройку пароля. Проверьте USB, доступ mobile к SSH и sudo и повторите попытку.";
        }
        finally
        {
            operation.Dispose(); operation = null;
            mobilePassword.Clear(); newPassword.Clear(); confirmation.Clear();
            SetBusy(false);
        }
        if (verified && IsVisible) DialogResult = true;
        else if (closeWhenFinished) Close();
    }

    private void RequestCancel(bool closeAfter)
    {
        if (!canCancel) { status.Text = "Изменение пароля уже началось. Дождитесь проверки входа root."; return; }
        closeWhenFinished |= closeAfter;
        operation?.Cancel(); cancel.IsEnabled = false;
        status.Text = "Отменяю подготовку. Дождитесь закрытия соединения.";
    }

    private void OnClosing(object? sender, CancelEventArgs e)
    {
        if (!busy) return;
        e.Cancel = true; RequestCancel(true);
    }
    private sealed class InlineProgress(Action<RootPasswordProgress> report) : IProgress<RootPasswordProgress>
    { public void Report(RootPasswordProgress value) => report(value); }
}
