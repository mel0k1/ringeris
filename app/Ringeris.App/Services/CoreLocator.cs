using System.IO;

namespace Ringeris.App.Services;

public static class CoreLocator
{
    private static string? _cached;

    public static string DbPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Ringeris",
        "db");

    public static string QuarantinePath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Ringeris",
        "quarantine");

    public static string? Locate()
    {
        var custom = SettingsStore.Current.CorePath;
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(custom))
        {
            candidates.Add(custom);
        }
        candidates.Add(Path.Combine(AppContext.BaseDirectory, "core", "ringeris-core.exe"));
        candidates.Add(Path.Combine(AppContext.BaseDirectory, "ringeris-core.exe"));
        candidates.Add(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            "Ringeris", "core", "ringeris-core.exe"));
        _cached = candidates.FirstOrDefault(File.Exists);
        return _cached;
    }
}
