using System.Text;
using System.Collections.ObjectModel;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using Ringeris.App.Localization;

namespace Ringeris.App.Services;

public sealed class WatchResultItem
{
    public WatchResultItem(string path, string verdict, string? name, string? kind, long timeMs)
    {
        Path = path;
        Verdict = verdict;
        Name = name;
        Kind = kind;
        TimeMs = timeMs;
    }

    public string Path { get; }
    public string Verdict { get; }
    public string? Name { get; }
    public string? Kind { get; }
    public long TimeMs { get; }

    public string NameText => Name ?? Kind ?? "";

    public Visibility NameVisible => NameText.Length == 0 ? Visibility.Collapsed : Visibility.Visible;

    public string TimeHuman => DateTimeOffset.FromUnixTimeMilliseconds(TimeMs).LocalDateTime.ToString("g");

    public string VerdictText => Verdict switch
    {
        "threat" => LocalizationService.S.VerdictThreat,
        "error" => LocalizationService.S.VerdictError,
        _ => LocalizationService.S.VerdictClean,
    };

    public Brush VerdictBrush
    {
        get
        {
            var key = Verdict switch
            {
                "threat" => "SystemFillColorCriticalBrush",
                "error" => "SystemFillColorCautionBrush",
                _ => "SystemFillColorSuccessBrush",
            };
            if (Application.Current.Resources.TryGetValue(key, out var value) && value is Brush brush)
            {
                return brush;
            }
            return new SolidColorBrush(Microsoft.UI.Colors.Gray);
        }
    }
}

public sealed partial class WatchService : ObservableObject
{
    public static WatchService Instance { get; } = new();

    private CancellationTokenSource? _cancellation;

    [ObservableProperty]
    private bool _isRunning;

    [ObservableProperty]
    private string _watchingFolder = "";

    [ObservableProperty]
    private bool _coreMissing;

    public ObservableCollection<WatchResultItem> Events { get; } = new();

    public string ToggleText => IsRunning ? LocalizationService.S.DisableWatch : LocalizationService.S.EnableWatch;

    public string ToggleGlyph => IsRunning ? "\uE74D" : "\uE768";

    public Visibility StoppedVisible => IsRunning ? Visibility.Collapsed : Visibility.Visible;

    public bool StoppedOpen => !IsRunning;

    public bool CoreFound => !CoreMissing;

    public Visibility EventsEmptyVisible => Events.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

    partial void OnIsRunningChanged(bool value)
    {
        OnPropertyChanged(nameof(ToggleText));
        OnPropertyChanged(nameof(ToggleGlyph));
        OnPropertyChanged(nameof(StoppedVisible));
        OnPropertyChanged(nameof(StoppedOpen));
    }

    partial void OnCoreMissingChanged(bool value)
    {
        OnPropertyChanged(nameof(CoreFound));
    }

    [RelayCommand]
    public async Task ToggleAsync()
    {
        if (IsRunning)
        {
            _cancellation?.Cancel();
            return;
        }
        await StartAsync();
    }

    public static string BuildWatchArgs()
    {
        var settings = SettingsStore.Current;
        var builder = new StringBuilder();
        builder.Append($"watch --db \"{CoreLocator.DbPath}\"");
        var downloads = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            "Downloads");
        builder.Append($" --path \"{downloads}\"");
        if (settings.WatchTemp)
        {
            builder.Append($" --path \"{Path.GetTempPath().TrimEnd(Path.DirectorySeparatorChar)}\"");
        }
        if (settings.WatchDesktop)
        {
            builder.Append($" --path \"{Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory)}\"");
        }
        builder.Append(SettingsService.BuildExcludeArgs());
        return builder.ToString();
    }

    public async Task StartAsync()
    {
        if (IsRunning)
        {
            return;
        }
        var core = CoreLocator.Locate();
        if (core is null)
        {
            CoreMissing = true;
            return;
        }
        CoreMissing = false;
        Events.Clear();
        _cancellation = new CancellationTokenSource();
        IsRunning = true;
        try
        {
            await ProcessRunner.RunAsync(
                core,
                BuildWatchArgs(),
                line => App.Queue.TryEnqueue(() => HandleLine(line)),
                _cancellation.Token);
        }
        catch (OperationCanceledException)
        {
        }
        catch
        {
        }
        finally
        {
            IsRunning = false;
        }
    }

    private void HandleLine(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return;
        }
        try
        {
            using var document = JsonDocument.Parse(line);
            var root = document.RootElement;
            switch (root.GetProperty("type").GetString())
            {
                case "watch_started":
                    WatchingFolder = root.TryGetProperty("paths", out var paths) && paths.ValueKind == JsonValueKind.Array
                        ? string.Join(", ", paths.EnumerateArray().Select(p => p.GetString() ?? ""))
                        : "";
                    break;
                case "watch_event":
                    AddEvent(
                        root.GetProperty("path").GetString() ?? "",
                        root.GetProperty("verdict").GetString() ?? "",
                        root.TryGetProperty("name", out var name) ? name.GetString() : null,
                        root.TryGetProperty("kind", out var kind) ? kind.GetString() : null,
                        root.TryGetProperty("time_ms", out var time) ? time.GetInt64() : 0);
                    break;
            }
        }
        catch
        {
        }
    }

    private void AddEvent(string path, string verdict, string? name, string? kind, long timeMs)
    {
        Events.Insert(0, new WatchResultItem(path, verdict, name, kind, timeMs == 0 ? DateTimeOffset.Now.ToUnixTimeMilliseconds() : timeMs));
        OnPropertyChanged(nameof(EventsEmptyVisible));
    }
}
