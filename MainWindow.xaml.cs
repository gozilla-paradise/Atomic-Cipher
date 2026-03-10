using System.Windows;
using System.Windows.Controls;
using AtomicCipher.ViewModels;

namespace AtomicCipher
{
    public partial class MainWindow : Window
    {
        public MainWindow(string? command = null, string[]? targetPaths = null)
        {
            InitializeComponent();

            var viewModel = new MainViewModel();
            DataContext = viewModel;

            if (!string.IsNullOrEmpty(command) && targetPaths is { Length: > 0 })
            {
                if (command == "--encrypt")
                    viewModel.SetEncryptPaths(targetPaths);
                else if (command == "--encrypt-passphrase")
                {
                    viewModel.SelectedEncryptMode = EncryptionMode.Passphrase;
                    viewModel.SetEncryptPaths(targetPaths);
                }
                else if (command == "--decrypt")
                    viewModel.SetDecryptPaths(targetPaths);
            }
        }

        private void EncryptPassphraseBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
                vm.EncryptPassphrase = ((PasswordBox)sender).Password;
        }

        private void EncryptPassphraseConfirmBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
                vm.EncryptPassphraseConfirm = ((PasswordBox)sender).Password;
        }

        private void DecryptPassphraseBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (DataContext is MainViewModel vm)
                vm.DecryptPassphrase = ((PasswordBox)sender).Password;
        }
    }
}
