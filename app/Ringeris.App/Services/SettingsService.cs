using System.Collections.ObjectModel;
using System.Text;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ringeris.App.Localization;

namespace Ringeris.App.Services;

public sealed partial class SettingsService : ObservableObject
{
    [ObservableProperty]
    private string _language = "ru-RU";

    [ObservableProperty]
    private bool _watchOnStart;

    [ObservableProperty]
    private bool _watchTemp;

    [ObservableProperty]
    private bool _watchDesktop;

    [ObservableProperty]
    private bool _scheduleEnabled;

    [ObservableProperty]
    private string _scheduleTime = "12:00";

    [ObservableProperty]
    private string _corePath = "";

    [ObservableProperty]
    private string _newExclusion = "";

    [ObservableProperty]
    private bool _saved;

    public ObservableCollection<string> Exclusions { get; } = new();

    public string[] Languages => new[] { "ru-RU", "en-US" };

    public void Load()
    {
        Language = SettingsStore.Current.Language;
        WatchOnStart = SettingsStore.Current.WatchOnStart;
        WatchTemp = SettingsStore.Current.WatchTemp;
        WatchDesktop = SettingsStore.Current.WatchDesktop;
        ScheduleEnabled = SettingsStore.Current.ScheduleEnabled;
        ScheduleTime = SettingsStore.Current.ScheduleTime;
        CorePath = SettingsStore.Current.CorePath;
        Exclusions.Clear();
        foreach (var item in SettingsStore.Current.Exclusions)
        {
            Exclusions.Add(item);
        }
        Saved = false;
    }

    [RelayCommand]
    public void AddExclusion()
    {
        var value = NewExclusion.Trim();
        if (value.Length == 0 || Exclusions.Contains(value))
        {
            return;
        }
        Exclusions.Add(value);
        NewExclusion = "";
        Saved = false;
    }

    [RelayCommand]
    public void RemoveExclusion(string item)
    {
        Exclusions.Remove(item);
        Saved = false;
    }

    [RelayCommand]
    public void Save()
    {
        SettingsStore.Current.Language = Language;
        SettingsStore.Current.WatchOnStart = WatchOnStart;
        SettingsStore.Current.WatchTemp = WatchTemp;
        SettingsStore.Current.WatchDesktop = WatchDesktop;
        SettingsStore.Current.ScheduleEnabled = ScheduleEnabled;
        SettingsStore.Current.ScheduleTime = string.IsNullOrWhiteSpace(ScheduleTime) ? "12:00" : ScheduleTime;
        SettingsStore.Current.CorePath = CorePath;
        SettingsStore.Current.Exclusions = Exclusions.ToList();
        SettingsStore.Save();
        Saved = true;
    }

    public static string BuildExcludeArgs()
    {
        if (SettingsStore.Current.Exclusions.Count == 0)
        {
            return "";
        }
        var builder = new StringBuilder();
        foreach (var exclusion in SettingsStore.Current.Exclusions)
        {
            if (string.IsNullOrWhiteSpace(exclusion))
            {
                continue;
            }
            builder.Append(" --exclude \"").Append(exclusion.Replace("\"", "")).Append('"');
        }
        return builder.ToString();
    }
}
