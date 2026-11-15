using System.Collections.ObjectModel;
using System.Text.Json;
using System.Windows.Input;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Microsoft.UI.Xaml;
using Ringeris.App.Localization;

namespace Ringeris.App.Services;

public sealed class QuarantineEntry
{
    public QuarantineEntry(string file, string originalPath, long movedAt, long size)
    {
        File = file;
        OriginalPath = originalPath;
        MovedAt = movedAt;
        Size = size;
    }

    public string File { get; }
    public string OriginalPath { get; }
    public long MovedAt { get; }
    public long Size { get; }

    public ICommand? RestoreCommand { get; set; }

    public ICommand? RemoveCommand { get; set; }

    public string DateHuman => MovedAt > 0
        ? DateTimeOffset.FromUnixTimeMilliseconds(MovedAt).LocalDateTime.ToString("g")
        : "";

    public string SizeHuman => HumanSize.Convert(Size);

    public string RestoreLabel => LocalizationService.S.RestoreAction;

    public string RemoveLabel => LocalizationService.S.RemoveAction;
}

public sealed partial class QuarantineService : ObservableObject
{
    public static QuarantineService Instance { get; } = new();

    [ObservableProperty]
    private bool _isLoading;

    [ObservableProperty]
    private string _lastError = "";

    public ObservableCollection<QuarantineEntry> Entries { get; } = new();

    public Visibility EmptyVisible => Entries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

    public bool HasError => LastError.Length > 0;

    partial void OnLastErrorChanged(string value)
    {
        OnPropertyChanged(nameof(HasError));
    }

    [RelayCommand]
    public async Task RefreshAsync()
    {
        var core = CoreLocator.Locate();
        if (core is null)
        {
            LastError = LocalizationService.S.CoreMissing;
            return;
        }
        LastError = "";
        IsLoading = true;
        try
        {
            var lines = await ProcessRunner.CollectAsync(core, "quarantine list", CancellationToken.None);
            var parsed = ParseEntries(lines);
            Entries.Clear();
            foreach (var entry in parsed)
            {
                var captured = entry;
                captured.RestoreCommand = new AsyncRelayCommand(() => ActAsync($"quarantine restore \"{captured.File}\""));
                captured.RemoveCommand = new AsyncRelayCommand(() => ActAsync($"quarantine remove \"{captured.File}\""));
                Entries.Add(entry);
            }
            OnPropertyChanged(nameof(EmptyVisible));
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
        }
        finally
        {
            IsLoading = false;
        }
    }

    private async Task ActAsync(string args)
    {
        var core = CoreLocator.Locate();
        if (core is null)
        {
            LastError = LocalizationService.S.CoreMissing;
            return;
        }
        try
        {
            await ProcessRunner.RunAsync(core, args, _ => { }, CancellationToken.None);
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
        }
        await RefreshAsync();
    }

    private static List<QuarantineEntry> ParseEntries(List<string> lines)
    {
        var result = new List<QuarantineEntry>();
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
                if (root.GetProperty("type").GetString() != "quarantine_list")
                {
                    continue;
                }
                foreach (var item in root.GetProperty("entries").EnumerateArray())
                {
                    result.Add(new QuarantineEntry(
                        item.GetProperty("file").GetString() ?? "",
                        item.GetProperty("original_path").GetString() ?? "",
                        item.TryGetProperty("moved_at", out var movedAt) ? movedAt.GetInt64() : 0,
                        item.TryGetProperty("size", out var size) ? size.GetInt64() : 0));
                }
            }
            catch
            {
            }
        }
        return result;
    }
}
