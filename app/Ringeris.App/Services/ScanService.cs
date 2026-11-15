using System.Collections.ObjectModel;
using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Xaml;
using Ringeris.App.Localization;

namespace Ringeris.App.Services;

public sealed class ScanResultItem
{
    public ScanResultItem(string path, string name, string kind, long size, string hash)
    {
        Path = path;
        Name = name;
        Kind = kind;
        Size = size;
        Hash = hash;
    }

    public string Path { get; }
    public string Name { get; }
    public string Kind { get; }
    public long Size { get; }
    public string Hash { get; }
    public string SizeHuman => HumanSize.Convert(Size);

    public string KindText => Kind switch
    {
        "hash" => LocalizationService.S.KindHash,
        "pattern" => LocalizationService.S.KindPattern,
        "logical" => LocalizationService.S.KindLogical,
        "section" => LocalizationService.S.KindSection,
        _ => Kind,
    };
}

public sealed partial class ScanService : ObservableObject
{
    public static ScanService Instance { get; } = new();

    private CancellationTokenSource? _cancellation;

    [ObservableProperty]
    private bool _isScanning;

    [ObservableProperty]
    private long _scanned;

    [ObservableProperty]
    private long _threats;

    [ObservableProperty]
    private string _currentFile = "";

    [ObservableProperty]
    private string _statusText = "";

    [ObservableProperty]
    private bool _coreMissing;

    [ObservableProperty]
    private string _customFolder = "";

    public ObservableCollection<ScanResultItem> Results { get; } = new();

    public Visibility ScanningVisible => IsScanning ? Visibility.Visible : Visibility.Collapsed;

    public bool CanStart => !IsScanning;

    public string SummaryText => string.Format(LocalizationService.S.ResultsSummary, Scanned, Threats);

    partial void OnIsScanningChanged(bool value)
    {
        OnPropertyChanged(nameof(ScanningVisible));
        OnPropertyChanged(nameof(CanStart));
    }

    partial void OnScannedChanged(long value)
    {
        OnPropertyChanged(nameof(SummaryText));
    }

    partial void OnThreatsChanged(long value)
    {
        OnPropertyChanged(nameof(SummaryText));
    }

    [RelayCommand]
    public Task StartQuickAsync() => RunScanAsync("quick");

    [RelayCommand]
    public Task StartFullAsync() => RunScanAsync("full");

    [RelayCommand]
    public async Task StartCustomAsync()
    {
        if (string.IsNullOrWhiteSpace(CustomFolder) || !Directory.Exists(CustomFolder))
        {
            StatusText = LocalizationService.S.FolderInvalid;
            return;
        }
        await RunScanAsync($"scan --path \"{CustomFolder}\"");
    }

    [RelayCommand]
    public async Task PickFolderAsync()
    {
        if (App.Main is null)
        {
            return;
        }
        var folder = await FolderPickerHelper.PickAsync(App.Main);
        if (!string.IsNullOrWhiteSpace(folder))
        {
            CustomFolder = folder;
        }
    }

    [RelayCommand]
    public void CancelScan()
    {
        _cancellation?.Cancel();
    }

    private async Task RunScanAsync(string modeArgs)
    {
        if (IsScanning)
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
        Results.Clear();
        Scanned = 0;
        Threats = 0;
        CurrentFile = "";
        StatusText = "";
        _cancellation = new CancellationTokenSource();
        IsScanning = true;
        try
        {
            await ProcessRunner.RunAsync(
                core,
                $"{modeArgs} --db \"{CoreLocator.DbPath}\"{SettingsService.BuildExcludeArgs()}",
                line => App.Queue.TryEnqueue(() => HandleLine(line)),
                _cancellation.Token);
            StatusText = LocalizationService.S.ScanDoneText;
        }
        catch (OperationCanceledException)
        {
            StatusText = LocalizationService.S.ScanStoppedText;
        }
        catch (Exception ex)
        {
            StatusText = string.Format(LocalizationService.S.ScanErrorText, ex.Message);
        }
        finally
        {
            IsScanning = false;
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
                case "progress":
                    Scanned = root.GetProperty("scanned").GetInt64();
                    Threats = root.GetProperty("threats").GetInt64();
                    CurrentFile = root.GetProperty("current").GetString() ?? "";
                    break;
                case "threat":
                    Threats += 1;
                    AddThreat(root);
                    break;
                case "scan_done":
                    Scanned = root.GetProperty("scanned").GetInt64();
                    Threats = root.GetProperty("threats").GetInt64();
                    break;
                case "error":
                    StatusText = root.GetProperty("message").GetString() ?? "";
                    break;
            }
        }
        catch
        {
        }
    }

    private void AddThreat(JsonElement root)
    {
        var path = root.GetProperty("path").GetString() ?? "";
        var name = root.GetProperty("name").GetString() ?? "";
        var kind = root.TryGetProperty("kind", out var kindElement) ? kindElement.GetString() ?? "" : "";
        var size = root.TryGetProperty("size", out var sizeElement) ? sizeElement.GetInt64() : 0;
        var hash = root.TryGetProperty("sha256", out var hashElement) ? hashElement.GetString() ?? "" : "";
        Results.Insert(0, new ScanResultItem(path, name, kind, size, hash));
        OnPropertyChanged(nameof(SummaryText));
    }
}
