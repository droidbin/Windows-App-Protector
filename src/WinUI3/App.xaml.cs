using Microsoft.UI.Xaml;
using System.Runtime.InteropServices;

namespace WindowsAppProtector;

public partial class App : Application
{
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
                Children = { new Microsoft.UI.Xaml.Controls.TextBlock { Text = "Windows App Protector" } }
            };
            Exit();
            return;
        }

        if (Environment.GetCommandLineArgs().Any(arg => string.Equals(arg, "--blocked", StringComparison.OrdinalIgnoreCase)))
        {
            MessageBoxW(IntPtr.Zero, "이 앱은 Windows App Protector에 의해 차단되었습니다.", "Windows App Protector", 0x00000030);
            Exit();
            return;
        }

        _window = new MainWindow();
        _window.Activate();
    }

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
}
