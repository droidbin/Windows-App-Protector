using System.Diagnostics;
using System.Text.Json;
using System.Windows.Forms;
using WindowsAppProtector.Models;
using WindowsAppProtector.Services;

internal static class Program
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.FirstOrDefault() == "--fixture")
        {
            var form = new Form { Text = "WAP disposable close test", Width = 420, Height = 180 };
            form.Controls.Add(new Label { Text = "Synthetic test window; no user documents.", Dock = DockStyle.Fill });
            form.FormClosing += (_, e) => { if (args[1] == "refuse") e.Cancel = true; };
            form.Shown += (_, _) => File.WriteAllText(args[2], "ready");
            Application.Run(form);
            return 0;
        }
        try
        {
            if (args.FirstOrDefault() == "--discovery") DiscoveryAsync(args[1]).GetAwaiter().GetResult();
            else RunAsync(args.Single()).GetAwaiter().GetResult();
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
    }

    private static async Task DiscoveryAsync(string output)
    {
        var results = new List<object>();
        for (var i = 0; i < 3; i++)
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(90));
            var apps = await new PackagedAppDiscoveryService().GetInstalledAppsAsync(timeout.Token);
            if (apps.Count == 0 || apps.Any(app => string.IsNullOrWhiteSpace(app.Name) || string.IsNullOrWhiteSpace(app.Path)))
                throw new Exception("Installed-app discovery returned empty or invalid items");
            results.Add(new { iteration = i + 1, count = apps.Count, passed = true });
        }
        File.WriteAllText(output, JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));
        Console.WriteLine("Installed-app discovery: three iterations passed.");
    }

    private static async Task RunAsync(string output)
    {
        var service = new ProtectedAppProcessService();
        var exe = Environment.ProcessPath!;
        var results = new List<object>();
        var owned = new List<Process>();
        var temp = Path.Combine(Path.GetTempPath(), "WapCloseTest." + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(temp);
        Process Start(string mode)
        {
            var marker = Path.Combine(temp, Guid.NewGuid().ToString("N"));
            var start = new ProcessStartInfo(exe) { UseShellExecute = false };
            start.ArgumentList.Add("--fixture"); start.ArgumentList.Add(mode); start.ArgumentList.Add(marker);
            var process = Process.Start(start)!; owned.Add(process);
            var deadline = Stopwatch.StartNew();
            while (!File.Exists(marker) && !process.HasExited && deadline.Elapsed < TimeSpan.FromSeconds(15)) Thread.Sleep(100);
            if (!File.Exists(marker)) throw new Exception("Fixture did not become ready");
            return process;
        }
        void Assert(bool condition, string message) { if (!condition) throw new Exception(message); }
        try
        {
            var graceful = Start("graceful");
            var empty = await service.CloseRunningAppsAsync(Array.Empty<ProtectedApp>());
            Assert(empty == new ProtectedAppProcessCloseResult(0, 0) && !graceful.HasExited, "Empty target list closed an app");
            var packaged = await service.CloseRunningAppsAsync(new[] { new ProtectedApp { Path = exe, IsPackaged = true } });
            Assert(packaged == new ProtectedAppProcessCloseResult(0, 0) && !graceful.HasExited, "Packaged app was closed");
            var otherPath = await service.CloseRunningAppsAsync(new[] { new ProtectedApp { Path = Path.Combine(temp, Path.GetFileName(exe)) } });
            Assert(otherPath == new ProtectedAppProcessCloseResult(0, 0) && !graceful.HasExited, "Filename-only match closed an unrelated path");
            results.Add(new { scenario = "empty-packaged-and-other-path", passed = true });

            var closed = await service.CloseRunningAppsAsync(new[] { new ProtectedApp { Path = exe, Enabled = false } });
            Assert(closed == new ProtectedAppProcessCloseResult(1, 0) && graceful.HasExited, "Previously disabled Win32 app did not close");
            results.Add(new { scenario = "previously-disabled-individual", passed = true });

            var first = Start("graceful"); var second = Start("graceful"); var refusing = Start("refuse");
            var watch = Stopwatch.StartNew();
            var mixed = await service.CloseRunningAppsAsync(new[] { new ProtectedApp { Path = exe, Enabled = false } });
            Assert(mixed == new ProtectedAppProcessCloseResult(2, 1), "Unexpected multi-process result: " + mixed);
            Assert(first.HasExited && second.HasExited && !refusing.HasExited, "Refusing app was forced or graceful app survived");
            Assert(watch.Elapsed >= TimeSpan.FromSeconds(5), "Grace period was not respected");
            results.Add(new { scenario = "multiple-processes-and-refused-close", passed = true, elapsedSeconds = watch.Elapsed.TotalSeconds });
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(output))!);
            File.WriteAllText(output, JsonSerializer.Serialize(new { identity = System.Security.Principal.WindowsIdentity.GetCurrent().Name, os = Environment.OSVersion.VersionString, results }, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine("Process close integration: all scenarios passed.");
        }
        finally
        {
            // Only terminate disposable children created by this test, never protected user apps.
            foreach (var child in owned) { try { if (!child.HasExited) { child.Kill(); child.WaitForExit(5000); } } finally { child.Dispose(); } }
            Directory.Delete(temp, true);
        }
    }
}
