using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Ringeris.App.Localization;

namespace Ringeris.App.Services;

public sealed partial class UpdateService : ObservableObject
{
    public static UpdateService Instance { get; } = new();

    [ObservableProperty]
    private bool _isUpdating;

    [ObservableProperty]
    private string _statusText = "";

    public bool CanUpdate => !IsUpdating;

    public Visibility BusyVisible => IsUpdating ? Visibility.Visible : Visibility.Collapsed;

    partial void OnIsUpdatingChanged(bool value)
    {
        OnPropertyChanged(nameof(CanUpdate));
        OnPropertyChanged(nameof(BusyVisible));
    }

    [RelayCommand]
    public async Task UpdateAsync()
    {
        if (IsUpdating)
        {
            return;
        }
        var core = CoreLocator.Locate();
        if (core is null)
        {
            StatusText = LocalizationService.S.CoreMissing;
            return;
        }
        IsUpdating = true;
        StatusText = LocalizationService.S.Updating;
        try
        {
            await ProcessRunner.RunAsync(
                core,
                $"update --db \"{CoreLocator.DbPath}\"",
                line => App.Queue.TryEnqueue(() => HandleLine(line)),
                CancellationToken.None);
            StatusText = LocalizationService.S.UpdateDoneText;
        }
        catch (Exception ex)
        {
            StatusText = $"{LocalizationService.S.UpdateErrorText}: {ex.Message}";
        }
        finally
        {
            IsUpdating = false;
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
            if (root.GetProperty("type").GetString() == "update_done")
            {
                var database = root.GetProperty("database").GetString() ?? "";
                var version = root.GetProperty("version").GetInt64();
                StatusText = $"{LocalizationService.S.UpdateDoneText} ({database} {version})";
            }
        }
        catch
        {
        }
    }
}
