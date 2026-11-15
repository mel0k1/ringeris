using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ringeris.App.Localization;

namespace Ringeris.App.Services;

public sealed partial class DashboardService : ObservableObject
{
    [ObservableProperty]
    private long _signatures;

    private long _patterns;

    private long _sections;

    public long Patterns
    {
        get => _patterns;
        set
        {
            _patterns = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(PatternsText));
        }
    }

    public long Sections
    {
        get => _sections;
        set
        {
            _sections = value;
            OnPropertyChanged();
            OnPropertyChanged(nameof(SectionsText));
        }
    }

    public string PatternsText => Patterns.ToString("N0");

    public string SectionsText => Sections.ToString("N0");

    public string PatternsDetail => LocalizationService.S.PatternsDetail
        .Replace("{0}", Patterns.ToString("N0"))
        .Replace("{1}", Sections.ToString("N0"));


    [ObservableProperty]
    private string _dbUpdatedText = "";

    [ObservableProperty]
    private bool _dbMissing;

    [ObservableProperty]
    private bool _coreMissing;

    [ObservableProperty]
    private string _watchStatusText = "";

    public string SignaturesText => $"{LocalizationService.S.DbSignaturesLabel}: {Signatures}";

    public string DbUpdatedLabel => DbUpdatedText.Length > 0
        ? $"{LocalizationService.S.DbUpdatedLabel}: {DbUpdatedText}"
        : $"{LocalizationService.S.DbUpdatedLabel}: {LocalizationService.S.DbNeverUpdated}";

    partial void OnSignaturesChanged(long value)
    {
        OnPropertyChanged(nameof(SignaturesText));
        OnPropertyChanged(nameof(PatternsDetail));
    }

    partial void OnDbUpdatedTextChanged(string value)
    {
        OnPropertyChanged(nameof(DbUpdatedLabel));
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        var core = CoreLocator.Locate();
        if (core is null)
        {
            CoreMissing = true;
            DbMissing = true;
            return;
        }
        CoreMissing = false;
        try
        {
            var lines = await ProcessRunner.CollectAsync(core, $"info --db \"{CoreLocator.DbPath}\"", CancellationToken.None);
            ParseInfo(lines);
        }
        catch
        {
            DbMissing = true;
        }
        UpdateWatchStatus();
    }

    private void ParseInfo(List<string> lines)
    {
        foreach (var line in lines)
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }
            try
            {
                using var document = JsonDocument.Parse(line);
                var root = document.RootElement;
                if (root.GetProperty("type").GetString() != "db_info")
                {
                    continue;
                }
                Signatures = root.GetProperty("signatures").GetInt64();
                Patterns = root.TryGetProperty("patterns", out var patterns) ? patterns.GetInt64() : 0;
                Sections = root.TryGetProperty("sections", out var sections) ? sections.GetInt64() : 0;
                if (root.TryGetProperty("databases", out var databases) && databases.ValueKind == JsonValueKind.Array)
                {
                    string? newest = null;
                    foreach (var database in databases.EnumerateArray())
                    {
                        var name = database.GetProperty("file").GetString() ?? "";
                        var buildTime = database.GetProperty("build_time").GetString() ?? "";
                        var version = database.GetProperty("version").GetInt64();
                        if (name.StartsWith("daily", StringComparison.OrdinalIgnoreCase))
                        {
                            newest = $"{buildTime} ({version})";
                        }
                    }
                    DbUpdatedText = newest ?? "";
                }
                DbMissing = Signatures == 0;
            }
            catch
            {
            }
        }
    }

    private void UpdateWatchStatus()
    {
        WatchStatusText = WatchService.Instance.IsRunning
            ? LocalizationService.S.WatchOn
            : LocalizationService.S.WatchOff;
    }
}
