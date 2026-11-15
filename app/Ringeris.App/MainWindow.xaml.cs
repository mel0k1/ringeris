using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Ringeris.App.Localization;
using Ringeris.App.Views;
using System.IO;

namespace Ringeris.App;

public sealed partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        var strings = LocalizationService.S;
        Title = strings.AppTitle;
        ItemDashboard.Content = strings.NavDashboard;
        ItemScan.Content = strings.NavScan;
        ItemWatch.Content = strings.NavWatch;
        ItemQuarantine.Content = strings.NavQuarantine;
        ItemSettings.Content = strings.NavSettings;
        ItemAbout.Content = strings.NavAbout;
        ExtendsContentIntoTitleBar = true;
        try
        {
            AppWindow.SetIcon(Path.Combine(AppContext.BaseDirectory, "Assets", "icon.ico"));
        }
        catch
        {
        }
        Nav.SelectedItem = ItemDashboard;
        ContentFrame.Navigate(typeof(DashboardPage));
    }

    private void OnNavSelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
    {
        if (args.SelectedItem is not NavigationViewItem item)
        {
            return;
        }
        var page = item.Tag?.ToString() switch
        {
            "dashboard" => typeof(DashboardPage),
            "scan" => typeof(ScanPage),
            "watch" => typeof(WatchPage),
            "quarantine" => typeof(QuarantinePage),
            "settings" => typeof(SettingsPage),
            "about" => typeof(AboutPage),
            _ => null,
        };
        if (page is null || (ContentFrame.Content?.GetType() == page))
        {
            return;
        }
        ContentFrame.Navigate(page);
    }
}
