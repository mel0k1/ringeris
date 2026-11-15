using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.UI.Xaml;
using Ringeris.App.Localization;

namespace Ringeris.App.Services;

public sealed partial class ScheduleService : ObservableObject
{
    public static ScheduleService Instance { get; } = new();

    private DispatcherTimer? _timer;
    private DateOnly _lastRunDate;

    [ObservableProperty]
    private string _statusText = "";

    public string StatusLine => StatusText.Length == 0
        ? LocalizationService.S.ScheduleIdle
        : StatusText;

    partial void OnStatusTextChanged(string value)
    {
        OnPropertyChanged(nameof(StatusLine));
    }

    public void Start()
    {
        if (_timer is not null)
        {
            return;
        }
        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromSeconds(30)
        };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
        RefreshStatus();
    }

    private void Tick()
    {
        var settings = SettingsStore.Current;
        if (!settings.ScheduleEnabled)
        {
            RefreshStatus();
            return;
        }
        var now = DateTime.Now;
        if (DateOnly.FromDateTime(now) == _lastRunDate)
        {
            return;
        }
        if (!TryParseTime(settings.ScheduleTime, out var scheduled))
        {
            RefreshStatus();
            return;
        }
        var target = now.Date.Add(scheduled);
        if (now < target)
        {
            RefreshStatus();
            return;
        }
        _lastRunDate = DateOnly.FromDateTime(now);
        if (ScanService.Instance.IsScanning)
        {
            RefreshStatus();
            return;
        }
        StatusText = string.Format(LocalizationService.S.ScheduleRan, now.ToString("g"));
        _ = ScanService.Instance.StartQuickAsync();
    }

    private void RefreshStatus()
    {
        var settings = SettingsStore.Current;
        StatusText = settings.ScheduleEnabled
            ? string.Format(LocalizationService.S.ScheduleOn, settings.ScheduleTime)
            : LocalizationService.S.ScheduleOff;
    }

    private static bool TryParseTime(string text, out TimeSpan value)
    {
        return TimeSpan.TryParseExact(text, @"hh\:mm", null, out value);
    }
}
