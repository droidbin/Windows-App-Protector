using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

internal sealed class SessionAgentSupervisor : IDisposable
{
    internal const string ExeName = "WindowsAppProtector.WindowAgent.exe";
    private readonly string path;
    private readonly Dictionary<int, IntPtr> agents = new Dictionary<int, IntPtr>();
    private EventWaitHandle stop;
    internal string Generation { get; private set; }

    internal SessionAgentSupervisor(string path) { this.path = path; }

    internal void Start()
    {
        Generation = Guid.NewGuid().ToString("N");
        var acl = new EventWaitHandleSecurity();
        acl.AddAccessRule(new EventWaitHandleAccessRule(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            EventWaitHandleRights.FullControl, AccessControlType.Allow));
        acl.AddAccessRule(new EventWaitHandleAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            EventWaitHandleRights.Synchronize, AccessControlType.Allow));
        bool created;
        stop = new EventWaitHandle(false, EventResetMode.ManualReset, @"Global\WapWindowAgent-" + Generation, out created, acl);
        if (!created) throw new IOException("Could not create an exclusive window agent stop event.");
    }

    internal void Reconcile()
    {
        if (stop == null || !File.Exists(path)) return;
        IntPtr buffer;
        int count;
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out buffer, out count)) throw new Win32Exception();
        try
        {
            int size = Marshal.SizeOf(typeof(SessionInfo));
            for (int index = 0; index < count; index++)
            {
                var item = (SessionInfo)Marshal.PtrToStructure(IntPtr.Add(buffer, size * index), typeof(SessionInfo));
                // A disconnected session already has an agent. A new agent is started when it becomes active.
                if (item.Id <= 0 || item.State != 0 || agents.ContainsKey(item.Id)) continue;
                IntPtr token;
                if (!WTSQueryUserToken(item.Id, out token)) continue;
                try { agents[item.Id] = StartInSession(token); }
                catch (Win32Exception) { /* Retry on the next reconciliation. */ }
                finally { CloseHandle(token); }
            }
        }
        finally { WTSFreeMemory(buffer); }

        foreach (var pair in agents.Where(pair => WaitForSingleObject(pair.Value, 0) == 0).ToArray())
        {
            CloseHandle(pair.Value);
            agents.Remove(pair.Key);
        }
    }

    private IntPtr StartInSession(IntPtr token)
    {
        IntPtr environment;
        if (!CreateEnvironmentBlock(out environment, token, false)) throw new Win32Exception();
        try
        {
            var startup = new Startup { Size = Marshal.SizeOf(typeof(Startup)), Desktop = @"winsta0\default" };
            ProcessHandles process;
            var command = new StringBuilder("\"" + path + "\" " + Generation);
            if (!CreateProcessAsUser(token, path, command, IntPtr.Zero, IntPtr.Zero, false,
                0x400, environment, Path.GetDirectoryName(path), ref startup, out process))
                throw new Win32Exception();
            CloseHandle(process.Thread);
            return process.Process;
        }
        finally { DestroyEnvironmentBlock(environment); }
    }

    public void Dispose()
    {
        if (stop != null)
        {
            stop.Set();
            var deadline = DateTime.UtcNow.AddSeconds(4);
            foreach (var process in agents.Values)
            {
                int time = (int)Math.Max(0, (deadline - DateTime.UtcNow).TotalMilliseconds);
                WaitForSingleObject(process, time);
                CloseHandle(process);
            }
            agents.Clear();
            stop.Dispose();
            stop = null;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SessionInfo { internal int Id; internal IntPtr Name; internal int State; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Startup
    {
        internal int Size;
        internal string Reserved, Desktop, Title;
        internal int X, Y, Width, Height, XCount, YCount, Fill, Flags;
        internal short Show, ReservedSize;
        internal IntPtr ReservedData, Input, Output, Error;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessHandles { internal IntPtr Process, Thread; internal uint ProcessId, ThreadId; }

    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr memory);
    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern bool WTSQueryUserToken(int session, out IntPtr token);
    [DllImport("userenv.dll", SetLastError = true)]
    private static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);
    [DllImport("userenv.dll")]
    private static extern bool DestroyEnvironmentBlock(IntPtr environment);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CreateProcessAsUser(IntPtr token, string app, StringBuilder command, IntPtr processSecurity,
        IntPtr threadSecurity, bool inherit, uint flags, IntPtr environment, string directory, ref Startup startup, out ProcessHandles process);
    [DllImport("kernel32.dll")]
    private static extern uint WaitForSingleObject(IntPtr handle, int milliseconds);
    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
