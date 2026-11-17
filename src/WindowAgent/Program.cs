using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using System.Threading;

internal sealed class WindowAgent
{
    private static readonly StringComparer Names = StringComparer.OrdinalIgnoreCase;
    private readonly HashSet<string> paths = new HashSet<string>(Names);
    private readonly HashSet<string> packages = new HashSet<string>(Names);
    private readonly Dictionary<IntPtr, WindowIdentity> hidden = new Dictionary<IntPtr, WindowIdentity>();
    private readonly Dictionary<uint, bool> matches = new Dictionary<uint, bool>();
    private readonly string journal;
    private bool policyReady;

    internal WindowAgent(string journal)
    {
        this.journal = journal;
        if (!File.Exists(journal)) return;
        foreach (string line in File.ReadLines(journal).Take(8192))
        {
            string[] fields = line.Split(',');
            long handle, started;
            uint pid, thread;
            if (fields.Length == 4 && long.TryParse(fields[0], out handle) && uint.TryParse(fields[1], out pid) &&
                uint.TryParse(fields[2], out thread) && long.TryParse(fields[3], out started))
                hidden[new IntPtr(handle)] = new WindowIdentity(pid, thread, started);
        }
    }

    private static int Main(string[] args)
    {
        Guid generation;
        if (args.Length != 1 || !Guid.TryParseExact(args[0], "N", out generation)) return 1;
        try
        {
            using (var stop = EventWaitHandle.OpenExisting(@"Global\WapWindowAgent-" + generation.ToString("N"),
                EventWaitHandleRights.Synchronize))
            using (var mutex = new Mutex(false, @"Local\WindowsAppProtector.WindowAgent"))
            using (var self = Process.GetCurrentProcess())
            {
                try { if (!mutex.WaitOne(0)) return 2; }
                catch (AbandonedMutexException) { }
                try
                {
                    string journal = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "WindowsAppProtector.WinUI", "window-agent-" + self.SessionId + ".state");
                    return new WindowAgent(journal).Run(stop, generation);
                }
                finally { mutex.ReleaseMutex(); }
            }
        }
        catch (Exception) { return 1; }
    }

    private int Run(EventWaitHandle stop, Guid generation)
    {
        var nextPolicy = DateTime.MinValue;
        try
        {
            while (!stop.WaitOne(0))
            {
                var now = DateTime.UtcNow;
                if (now >= nextPolicy)
                {
                    nextPolicy = now.AddSeconds(2);
                    try { if (!RefreshPolicy(generation)) break; }
                    catch (IOException) { }
                    catch (TimeoutException) { }
                    catch (UnauthorizedAccessException) { }
                    catch (FormatException) { }
                }
                if (stop.WaitOne(0)) break;
                if (policyReady) Scan();
                if (stop.WaitOne(350)) break;
            }
            return 0;
        }
        finally
        {
            var deadline = DateTime.UtcNow.AddSeconds(1);
            while (hidden.Count > 0 && DateTime.UtcNow < deadline)
            {
                RestoreWindows(true);
                if (hidden.Count > 0) Thread.Sleep(60);
            }
        }
    }

    private bool RefreshPolicy(Guid generation)
    {
        using (var pipe = GateProtocol.ConnectToService())
        {
            pipe.WriteByte(GateProtocol.Version);
            pipe.WriteByte(GateProtocol.ReadWindowPolicy);
            var deadline = DateTime.UtcNow.AddSeconds(1);
            if (GateProtocol.Read(pipe, 1, deadline)[0] != GateProtocol.Approved) return true;
            string policy = GateProtocol.ReadText(pipe, GateProtocol.MaxWindowPolicyBytes, deadline);
            pipe.WriteByte(GateProtocol.Approved);
            return ApplyPolicy(policy, generation);
        }
    }

    internal bool ApplyPolicy(string policy, Guid generation)
    {
        string[] lines = policy.Split('\n');
        Guid current;
        if (!Guid.TryParseExact(lines[0], "N", out current)) throw new FormatException("Invalid policy generation.");
        if (current != generation) return false;
        var newPaths = new HashSet<string>(Names);
        var newPackages = new HashSet<string>(Names);
        foreach (string line in lines.Skip(1))
        {
            if (line.Length < 3 || line[1] != ':' || (line[0] != 'P' && line[0] != 'F'))
                throw new FormatException("Invalid policy rule.");
            string value = Encoding.UTF8.GetString(Convert.FromBase64String(line.Substring(2)));
            (line[0] == 'P' ? newPaths : newPackages).Add(value);
        }
        paths.Clear();
        paths.UnionWith(newPaths);
        packages.Clear();
        packages.UnionWith(newPackages);
        policyReady = true;
        return true;
    }

    internal void Scan()
    {
        matches.Clear();
        RestoreWindows(false);
        if (paths.Count == 0 && packages.Count == 0) return;
        EnumWindows((window, ignored) =>
        {
            try
            {
                if (!IsWindowVisible(window) || !MatchesWindow(window)) return true;
                WindowIdentity identity;
                if (!TryIdentify(window, out identity)) return true;
                if (!hidden.ContainsKey(window) || !hidden[window].Equals(identity))
                {
                    if (hidden.Count >= 8192) return true;
                    hidden[window] = identity;
                    // Journal before hiding so a crash cannot strand a new window.
                    try { SaveJournal(); }
                    catch (IOException) { hidden.Remove(window); return true; }
                    catch (UnauthorizedAccessException) { hidden.Remove(window); return true; }
                }
                ShowWindowAsync(window, 0);
            }
            catch (Exception) { /* The window or process may disappear while enumerating. */ }
            return true;
        }, IntPtr.Zero);
    }

    private void RestoreWindows(bool all)
    {
        bool changed = false;
        foreach (var entry in hidden.ToArray())
        {
            WindowIdentity identity;
            if (TryIdentify(entry.Key, out identity) && identity.Equals(entry.Value))
            {
                if (!all && MatchesWindow(entry.Key)) continue;
                if (!IsWindowVisible(entry.Key))
                {
                    ShowWindowAsync(entry.Key, 8);
                    continue;
                }
            }
            hidden.Remove(entry.Key);
            changed = true;
        }
        if (changed)
        {
            try { SaveJournal(); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private void SaveJournal()
    {
        if (hidden.Count == 0) { File.Delete(journal); return; }
        Directory.CreateDirectory(Path.GetDirectoryName(journal));
        string temp = journal + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllLines(temp, hidden.Select(entry => string.Format(CultureInfo.InvariantCulture, "{0},{1},{2},{3}",
                entry.Key.ToInt64(), entry.Value.Pid, entry.Value.Thread, entry.Value.Started)));
            if (File.Exists(journal)) File.Replace(temp, journal, null);
            else File.Move(temp, journal);
        }
        finally { File.Delete(temp); }
    }

    private bool MatchesWindow(IntPtr window)
    {
        uint owner;
        GetWindowThreadProcessId(window, out owner);
        if (MatchesProcess(owner)) return true;
        if (packages.Count == 0) return false;
        bool match = false;
        EnumChildWindows(window, (child, ignored) =>
        {
            uint pid;
            GetWindowThreadProcessId(child, out pid);
            match = pid != owner && MatchesProcess(pid);
            return !match;
        }, IntPtr.Zero);
        return match;
    }

    private bool MatchesProcess(uint pid)
    {
        bool matched;
        if (pid == 0) return false;
        if (matches.TryGetValue(pid, out matched)) return matched;
        var handle = OpenProcess(0x1000, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                var image = new StringBuilder(32768);
                int length = image.Capacity;
                matched = paths.Count > 0 && QueryFullProcessImageName(handle, 0, image, ref length) && paths.Contains(image.ToString());
                if (!matched && packages.Count > 0)
                {
                    int count = 0;
                    if (GetPackageFamilyName(handle, ref count, null) == 122 && count > 0 && count < 512)
                    {
                        var family = new StringBuilder(count);
                        matched = GetPackageFamilyName(handle, ref count, family) == 0 && packages.Contains(family.ToString());
                    }
                }
            }
            finally { CloseHandle(handle); }
        }
        matches[pid] = matched;
        return matched;
    }

    private static bool TryIdentify(IntPtr window, out WindowIdentity identity)
    {
        identity = default(WindowIdentity);
        uint pid;
        uint thread = GetWindowThreadProcessId(window, out pid);
        if (thread == 0 || pid == 0 || pid > int.MaxValue) return false;
        try
        {
            using (var process = Process.GetProcessById((int)pid))
                identity = new WindowIdentity(pid, thread, process.StartTime.ToUniversalTime().Ticks);
            return true;
        }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
        catch (System.ComponentModel.Win32Exception) { return false; }
    }

    private struct WindowIdentity
    {
        internal readonly uint Pid, Thread;
        internal readonly long Started;
        internal WindowIdentity(uint pid, uint thread, long started) { Pid = pid; Thread = thread; Started = started; }
    }

    private delegate bool EnumProc(IntPtr window, IntPtr state);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumProc callback, IntPtr state);
    [DllImport("user32.dll")] private static extern bool EnumChildWindows(IntPtr window, EnumProc callback, IntPtr state);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
    [DllImport("user32.dll")] private static extern bool ShowWindowAsync(IntPtr window, int command);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window, out uint process);
    [DllImport("kernel32.dll")] private static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder image, ref int size);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackageFamilyName(IntPtr process, ref int length, StringBuilder name);
}
