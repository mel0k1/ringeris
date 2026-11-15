using Microsoft.UI.Xaml.Controls;
using Ringeris.App.Localization;
using System.IO;

namespace Ringeris.App.Views;

public sealed partial class AboutPage : Page
{
    public UiStrings L => LocalizationService.S;

    public Uri LogoUri { get; } = new(Path.Combine(AppContext.BaseDirectory, "Assets", "logo.png"));

    public AboutPage()
    {
        InitializeComponent();
    }
}
