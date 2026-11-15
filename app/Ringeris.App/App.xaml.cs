using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Ringeris.App.Localization;
using Ringeris.App.Services;

namespace Ringeris.App;

public partial class App : Application
{
    public static Window? Main { get; private set; }

    public static DispatcherQueue Queue { get; private set; } = null!;

    public App()
    {
        InitializeComponent();
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        SettingsStore.Load();
        LocalizationService.Apply(SettingsStore.Current.Language);
        Queue = DispatcherQueue.GetForCurrentThread();
        Main = new MainWindow();
        Main.Activate();
        if (SettingsStore.Current.WatchOnStart)
        {
            _ = WatchService.Instance.StartAsync();
        }
        ScheduleService.Instance.Start();
    }
}
