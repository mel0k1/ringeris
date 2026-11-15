namespace Ringeris.App.Localization;

public static class LocalizationService
{
    public static UiStrings S { get; private set; } = new EnglishStrings();

    public static void Apply(string language)
    {
        S = language.StartsWith("ru", StringComparison.OrdinalIgnoreCase)
            ? new RussianStrings()
            : new EnglishStrings();
    }
}
