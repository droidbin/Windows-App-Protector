using Microsoft.UI.Xaml;
using System.Runtime.InteropServices;

namespace WindowsAppProtector;

public partial class App : Application
{
    private static readonly object ProtectionLogLock = new();
    private Window? _window;

    public App()
    {
        InitializeComponent();
        UnhandledException += App_UnhandledException;
    }

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // Exercise WinUI and its native dependencies without opening the app or changing user data.
        if (Environment.GetCommandLineArgs().Any(arg => string.Equals(arg, "--verify-install", StringComparison.OrdinalIgnoreCase)))
        {
            _ = new Microsoft.UI.Xaml.Controls.Grid
            {
                Children = { new Microsoft.UI.Xaml.Controls.TextBlock { Text = ProductBrand.Name } }
            };
            Exit();
            return;
        }

        if (Environment.GetCommandLineArgs().Any(arg => string.Equals(arg, "--blocked", StringComparison.OrdinalIgnoreCase)))
        {
            MessageBoxW(IntPtr.Zero, "보호 정책에 따라 이 앱의 실행이 차단되었습니다.", ProductBrand.Name, 0x00000030);
            Exit();
            return;
        }

        // One protector per user session. A second launch asks the running instance to show itself.
        singleInstanceMutex = new Mutex(initiallyOwned: true, SingleInstanceMutexName, out var createdNew);
        if (!createdNew)
        {
            singleInstanceMutex.Dispose();
            singleInstanceMutex = null;
            MainWindow.SignalRunningInstance();
            Exit();
            return;
        }

        var startInBackground = Environment.GetCommandLineArgs()
            .Any(arg => string.Equals(arg, BackgroundArgument, StringComparison.OrdinalIgnoreCase));
        _window = new MainWindow(startInBackground);
        if (!startInBackground)
        {
            _window.Activate();
        }
    }

    internal const string BackgroundArgument = "--background";
    private const string SingleInstanceMutexName = @"Local\WindowsAppProtector.UI.SingleInstance";
    private static Mutex? singleInstanceMutex;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

    private static void App_UnhandledException(object sender, Microsoft.UI.Xaml.UnhandledExceptionEventArgs e)
    {
        WriteCrashLog(e.Exception);
        e.Handled = true;
    }

    internal static void WriteCrashLog(Exception exception)
    {
        try
        {
            var logDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Windows App Protector",
                "Logs");
            Directory.CreateDirectory(logDirectory);
            var logPath = Path.Combine(logDirectory, "winui-crash.log");
            File.AppendAllText(
                logPath,
                $"[{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}] {exception}\r\n\r\n");
        }
        catch
        {
        }
    }

    internal static void WriteProtectionLog(string eventName)
    {
        lock (ProtectionLogLock)
        {
            try
            {
                var directory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                    "Windows App Protector", "Logs");
                Directory.CreateDirectory(directory);
                var path = Path.Combine(directory, "protection.log");
                var log = new FileInfo(path);
                if (log.Exists && log.Length >= 256 * 1024)
                {
                    File.Move(path, path + ".previous", overwrite: true);
                }
                File.AppendAllText(path, $"[{DateTimeOffset.Now:O}] {eventName}{Environment.NewLine}");
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }
}
