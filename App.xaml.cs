using System.IO;
using System.IO.Pipes;
using System.Windows;

namespace AtomicCipher
{
    public partial class App : Application
    {
        private const string MutexName = "AtomicCipher_SingleInstance_Mutex";
        private const string PipeName = "AtomicCipher_PathPipe";
        private const int PathCollectionDelayMs = 600;

        private Mutex? _instanceMutex;

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            string? command = null;
            var paths = new List<string>();

            if (e.Args.Length >= 2)
            {
                command = e.Args[0];
                // Normalize --encrypt-passphrase for instance coordination
                string coordinationCommand = command == "--encrypt-passphrase" ? "--encrypt-passphrase" : command;
                for (int i = 1; i < e.Args.Length; i++)
                {
                    string path = e.Args[i];
                    if (File.Exists(path) || Directory.Exists(path))
                        paths.Add(path);
                }

                if (paths.Count == 0)
                {
                    MessageBox.Show($"No valid paths found in arguments.", "AtomicCipher",
                        MessageBoxButton.OK, MessageBoxImage.Error);
                    Shutdown(1);
                    return;
                }
            }

            // If launched from context menu with a single path, try single-instance coordination
            if (command != null && paths.Count == 1)
            {
                _instanceMutex = new Mutex(true, $"{MutexName}_{command}", out bool createdNew);

                if (!createdNew)
                {
                    // Another instance is already running — send our path and exit
                    SendPathToExistingInstance(command, paths[0]);
                    _instanceMutex.Dispose();
                    _instanceMutex = null;
                    Shutdown(0);
                    return;
                }

                // We are the first instance — collect paths from other instances
                var collectedPaths = CollectPathsFromOtherInstances(command, paths[0]);
                paths = collectedPaths;
            }

            var mainWindow = new MainWindow(command, paths.ToArray());
            mainWindow.Show();
        }

        private static void SendPathToExistingInstance(string command, string path)
        {
            try
            {
                using var client = new NamedPipeClientStream(".", $"{PipeName}_{command}", PipeDirection.Out);
                client.Connect(2000);
                using var writer = new StreamWriter(client) { AutoFlush = true };
                writer.WriteLine(path);
            }
            catch
            {
                // If pipe fails, fall through — the path won't be collected
            }
        }

        private static List<string> CollectPathsFromOtherInstances(string command, string firstPath)
        {
            var paths = new List<string> { firstPath };
            var cts = new CancellationTokenSource();

            // Start listening for other instances in background
            var listenTask = Task.Run(async () =>
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        using var server = new NamedPipeServerStream(
                            $"{PipeName}_{command}", PipeDirection.In,
                            NamedPipeServerStream.MaxAllowedServerInstances);

                        var connectTask = server.WaitForConnectionAsync(cts.Token);
                        await connectTask;

                        using var reader = new StreamReader(server);
                        string? line = await reader.ReadLineAsync(cts.Token);
                        if (!string.IsNullOrEmpty(line))
                        {
                            lock (paths)
                            {
                                paths.Add(line);
                            }
                            // Reset the timer — more paths may be coming
                            cts.CancelAfter(PathCollectionDelayMs);
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch
                    {
                        break;
                    }
                }
            });

            // Wait for the collection window
            cts.CancelAfter(PathCollectionDelayMs);
            try { listenTask.Wait(); } catch { }

            return paths;
        }

        protected override void OnExit(ExitEventArgs e)
        {
            if (_instanceMutex != null)
            {
                _instanceMutex.ReleaseMutex();
                _instanceMutex.Dispose();
            }
            base.OnExit(e);
        }
    }
}
