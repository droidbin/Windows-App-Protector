using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Windows.Forms;

internal static class WindowAgentSmoke
{
    [STAThread]
    private static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--fixture")
        {
            Application.Run(new Form { Text = "Disposable App PIN Guard window fixture" });
            return 0;
        }

        string source = Assembly.GetExecutingAssembly().Location;
        string root = Path.Combine(Path.GetDirectoryName(source), "fixture-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string copy = Path.Combine(root, Path.GetFileName(source));
        string journal = Path.Combine(root, "windows.state");
        File.Copy(source, copy);
        Process protectedChild = null, otherChild = null;
        try
        {
            protectedChild = Process.Start(source, "--fixture");
            otherChild = Process.Start(copy, "--fixture");
            IntPtr protectedWindow = WaitForWindow(protectedChild);
            IntPtr otherWindow = WaitForWindow(otherChild);
            var generation = Guid.NewGuid();
            string policy = generation.ToString("N") + "\nP:" + Convert.ToBase64String(Encoding.UTF8.GetBytes(source));
            var guard = new WindowAgent(journal);
            if (!guard.ApplyPolicy(policy, generation)) throw new InvalidOperationException("Valid policy not accepted.");
            WaitUntil(() => { guard.Scan(); return !IsWindowVisible(protectedWindow); }, "Protected window did not hide.");
            if (!File.Exists(journal) || !IsWindowVisible(otherWindow))
                throw new InvalidOperationException("Missing journal or matched a different path with the same name.");

            var restarted = new WindowAgent(journal);
            restarted.ApplyPolicy(policy, generation);
            restarted.Scan();
            if (IsWindowVisible(protectedWindow)) throw new InvalidOperationException("Restart released locked window.");
            if (restarted.ApplyPolicy(policy, Guid.NewGuid())) throw new InvalidOperationException("Wrong service generation accepted.");
            restarted.ApplyPolicy(generation.ToString("N"), generation);
            WaitUntil(() => { restarted.Scan(); return IsWindowVisible(protectedWindow) && !File.Exists(journal); },
                "Unlock did not restore the window and retire the journal entry.");
            Console.WriteLine("PASS: protected window hide, exact-path isolation, journal adoption, policy generation, and unlock restore.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine(ex); return 1; }
        finally
        {
            Stop(protectedChild);
            Stop(otherChild);
            File.Delete(journal);
            File.Delete(copy);
            Directory.Delete(root);
        }
    }

    private static IntPtr WaitForWindow(Process process)
    {
        IntPtr found = IntPtr.Zero;
        WaitUntil(() =>
        {
            EnumWindows((window, state) =>
            {
                uint pid;
                GetWindowThreadProcessId(window, out pid);
                if (pid == process.Id && IsWindowVisible(window)) found = window;
                return found == IntPtr.Zero;
            }, IntPtr.Zero);
            return found != IntPtr.Zero;
        }, "Desktop fixture did not show a window.");
        return found;
    }

    private static void WaitUntil(Func<bool> ready, string error)
    {
        var watch = Stopwatch.StartNew();
        while (watch.Elapsed < TimeSpan.FromSeconds(8))
        {
            if (ready()) return;
            Thread.Sleep(80);
        }
        throw new InvalidOperationException(error);
    }

    private static void Stop(Process process)
    {
        if (process == null) return;
        using (process)
        {
            if (!process.HasExited)
            {
                process.Kill();
                process.WaitForExit(5000);
            }
        }
    }

    private delegate bool EnumProc(IntPtr window, IntPtr state);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc callback, IntPtr state);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
}
