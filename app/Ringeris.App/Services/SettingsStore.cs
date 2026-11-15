using System.Text.Json;
using System.Text.Json.Serialization;

namespace Ringeris.App.Services;

public sealed class AppSettings
{
    [JsonPropertyName("language")]
    public string Language { get; set; } = "ru-RU";

    [JsonPropertyName("watch_on_start")]
    public bool WatchOnStart { get; set; }

    [JsonPropertyName("watch_temp")]
    public bool WatchTemp { get; set; }

    [JsonPropertyName("watch_desktop")]
    public bool WatchDesktop { get; set; }

    [JsonPropertyName("schedule_enabled")]
    public bool ScheduleEnabled { get; set; }

    [JsonPropertyName("schedule_time")]
    public string ScheduleTime { get; set; } = "12:00";

    [JsonPropertyName("exclusions")]
    public List<string> Exclusions { get; set; } = new();

    [JsonPropertyName("core_path")]
    public string CorePath { get; set; } = "";
}

public static class SettingsStore
{
    private static readonly string BaseDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "Ringeris");

    private static readonly string FilePath = Path.Combine(BaseDir, "settings.json");

    public static AppSettings Current { get; private set; } = new();

    public static void Load()
    {
        try
        {
            if (File.Exists(FilePath))
            {
                Current = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(FilePath)) ?? new AppSettings();
            }
        }
        catch
        {
            Current = new AppSettings();
        }
    }

    public static void Save()
    {
        try
        {
            Directory.CreateDirectory(BaseDir);
            File.WriteAllText(FilePath, JsonSerializer.Serialize(Current, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
        }
    }
}
