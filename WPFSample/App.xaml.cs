using KeeperSecurity.Authentication.Sync;
using KeeperSecurity.Configuration;
using System;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Navigation;

namespace WPFSample
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : Application
    {
        private LoginViewModel mainWindowVm;
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);
            MainWindow = new MainWindow();
            mainWindowVm = new LoginViewModel(new AuthSync(new JsonConfigurationStorage()));
            MainWindow.DataContext = mainWindowVm;
            MainWindow.WindowStartupLocation = WindowStartupLocation.CenterScreen;
            MainWindow.Show();
        }

    }
}
