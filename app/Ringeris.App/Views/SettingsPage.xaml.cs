using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Ringeris.App.Localization;
using Ringeris.App.Services;

namespace Ringeris.App.Views;

public sealed partial class SettingsPage : Page
{
    private bool _initializing;

    public UiStrings L => LocalizationService.S;

    public SettingsService Vm { get; } = new();

    public ScheduleService Schedule { get; } = ScheduleService.Instance;

    public SettingsPage()
    {
        InitializeComponent();
        Vm.Load();
        _initializing = true;
        LanguageBox.SelectedIndex = Vm.Language.StartsWith("ru", StringComparison.OrdinalIgnoreCase) ? 0 : 1;
        if (TimeSpan.TryParseExact(Vm.ScheduleTime, @"hh\:mm", null, out var time))
        {
            ScheduleTimePicker.Time = time;
        }
        else
        {
            ScheduleTimePicker.Time = new TimeSpan(12, 0, 0);
        }
        _initializing = false;
    }

    private void OnLanguageChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_initializing)
        {
            return;
        }
        Vm.Language = LanguageBox.SelectedIndex == 0 ? "ru-RU" : "en-US";
        Vm.Saved = false;
    }

    private void OnScheduleTimeChanged(TimePicker sender, TimePickerSelectedValueChangedEventArgs args)
    {
        if (_initializing)
        {
            return;
        }
        Vm.ScheduleTime = sender.Time.ToString(@"hh\:mm");
        Vm.Saved = false;
    }

    private void OnRemoveExclusion(object sender, RoutedEventArgs e)
    {
        if (sender is FrameworkElement { Tag: string item })
        {
            Vm.RemoveExclusion(item);
        }
    }
}
