using Microsoft.UI.Xaml.Controls;
using Ringeris.App.Localization;
using Ringeris.App.Services;

namespace Ringeris.App.Views;

public sealed partial class QuarantinePage : Page
{
    public UiStrings L => LocalizationService.S;

    public QuarantineService Vm { get; } = QuarantineService.Instance;

    public QuarantinePage()
    {
        InitializeComponent();
        DataContext = Vm;
        _ = Vm.RefreshAsync();
    }
}
