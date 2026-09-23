using System.Configuration;
using System.Data;
using System.Windows;

namespace Scan_Network
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        public App()
        {
            //Show unexpected UI errors instead of the app silently closing
            DispatcherUnhandledException += (sender, e) =>
            {
                MessageBox.Show(e.Exception.ToString(), "DB Network Scanner - Unexpected Error", MessageBoxButton.OK, MessageBoxImage.Error);
                //Keep running once the window is up - a failure during startup still exits
                e.Handled = MainWindow?.IsLoaded == true;
            };
        }
    }

}
