using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Ringeris.App.Localization;
using System.IO;

namespace Ringeris.App.Views;

public sealed partial class AboutPage : Page
{
    public UiStrings L => LocalizationService.S;

    public ImageSource LogoImage { get; } = new BitmapImage(new Uri("ms-appx:///Assets/logo.png"));

    public AboutPage()
    {
        InitializeComponent();
    }
}
