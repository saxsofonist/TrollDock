using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using TrollDock.Services;

namespace TrollDock;

public sealed class SettingsWindow : Window
{
    public record ModeChoice(string Id, string Name);
    public string SelectedStartup { get; private set; }
    public List<string> SelectedOrder { get; private set; }
    private readonly ObservableCollection<ModeChoice> choices;
    public SettingsWindow(AppSettings settings)
    {
        Title = "Настройки TrollDock"; Width = 490; Height = 520; ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner; Background = new SolidColorBrush(Color.FromRgb(243,245,249));
        FontFamily = new FontFamily("Segoe UI"); FontSize = 13;
        SelectedStartup = settings.StartupMode; SelectedOrder = [.. settings.ModeOrder];
        var all = new[] { new ModeChoice("trollstore", "IPA · TrollStore"), new ModeChoice("deb", "DEB · Dopamine"), new ModeChoice("certificate", "IPA · Сертификат") };
        choices = new(settings.ModeOrder.Select(id => all.Single(m => m.Id == id)));
        var panel = new StackPanel { Margin = new Thickness(26) }; Content = panel;
        panel.Children.Add(new TextBlock { Text = "Как открывать программу", FontSize = 20, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0,0,0,22) });
        panel.Children.Add(new TextBlock { Text = "Вкладка при запуске", Margin = new Thickness(0,0,0,8) });
        var startup = new ComboBox { ItemsSource = all, DisplayMemberPath = "Name", SelectedValuePath = "Id", SelectedValue = settings.StartupMode, Padding = new Thickness(8), Margin = new Thickness(0,0,0,22) };
        panel.Children.Add(startup);
        panel.Children.Add(new TextBlock { Text = "Порядок вкладок слева направо", Margin = new Thickness(0,0,0,8) });
        var row = new Grid(); row.ColumnDefinitions.Add(new()); row.ColumnDefinitions.Add(new() { Width = GridLength.Auto }); panel.Children.Add(row);
        var list = new ListBox { ItemsSource = choices, DisplayMemberPath = "Name", Height = 114, Padding = new Thickness(6), SelectedIndex = 0 };
        var itemStyle = new Style(typeof(ListBoxItem)); itemStyle.Setters.Add(new Setter(Control.PaddingProperty, new Thickness(7))); list.ItemContainerStyle = itemStyle;
        row.Children.Add(list);
        var arrows = new StackPanel { Margin = new Thickness(10,0,0,0) }; Grid.SetColumn(arrows, 1); row.Children.Add(arrows);
        var up = new Button { Content = "↑ Выше", Padding = new Thickness(12,8,12,8), Margin = new Thickness(0,0,0,8) };
        var down = new Button { Content = "↓ Ниже", Padding = new Thickness(12,8,12,8) };
        arrows.Children.Add(up); arrows.Children.Add(down);
        up.Click += (_, _) => { var i = list.SelectedIndex; if (i > 0) { choices.Move(i, i - 1); list.SelectedIndex = i - 1; } };
        down.Click += (_, _) => { var i = list.SelectedIndex; if (i >= 0 && i < choices.Count - 1) { choices.Move(i, i + 1); list.SelectedIndex = i + 1; } };
        panel.Children.Add(new TextBlock { Text = "Порядок изменится сразу. Выбранная стартовая вкладка откроется при следующем запуске.", TextWrapping = TextWrapping.Wrap, Foreground = Brushes.SlateGray, Margin = new Thickness(0,13,0,22) });
        var buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right }; panel.Children.Add(buttons);
        var cancel = new Button { Content = "Отмена", IsCancel = true, Padding = new Thickness(18,9,18,9), Margin = new Thickness(0,0,10,0) };
        var save = new Button { Content = "Сохранить", IsDefault = true, Padding = new Thickness(18,9,18,9), Background = new SolidColorBrush(Color.FromRgb(33,101,232)), Foreground = Brushes.White };
        buttons.Children.Add(cancel); buttons.Children.Add(save);
        save.Click += (_, _) => { SelectedStartup = (string)startup.SelectedValue; SelectedOrder = choices.Select(c => c.Id).ToList(); DialogResult = true; };
    }
}
