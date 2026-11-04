using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using WindowsAppProtector.Models;

namespace WindowsAppProtector.Services;

public readonly record struct ProtectedAppProcessCloseResult(int Closed, int Failed);

public sealed class ProtectedAppProcessService
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(IntPtr hProcess, int dwFlags, StringBuilder lpExeName, ref int lpdwSize);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr hObject);

    private static string GetProcessImageFileName(int processId)
    {
        var handle = OpenProcess(ProcessQueryLimitedInformation, false, (uint)processId);
        if (handle == IntPtr.Zero)
        {
            return string.Empty;
        }

        try
        {
            var capacity = 1024;
            var sb = new StringBuilder(capacity);
            return QueryFullProcessImageNameW(handle, 0, sb, ref capacity)
                ? sb.ToString()
                : string.Empty;
        }
        catch
        {
            return string.Empty;
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    public async Task<ProtectedAppProcessCloseResult> CloseRunningAppsAsync(IEnumerable<ProtectedApp> apps)
    {
        // Callers supply the apps being locked; their current Enabled state may still be false.
        var targetPaths = apps
            .Where(app => !app.IsPackaged && !string.IsNullOrWhiteSpace(app.Path))
            .Select(app => Path.GetFullPath(app.Path))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var targetExeNames = apps
            .Where(app => !string.IsNullOrWhiteSpace(app.ExecutableName))
            .Select(app => app.ExecutableName)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (targetPaths.Count == 0 && targetExeNames.Count == 0)
        {
            return new ProtectedAppProcessCloseResult(0, 0);
        }

        var processes = new List<Process>();

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id == Environment.ProcessId || process.HasExited)
                {
                    process.Dispose();
                    continue;
                }

                var imagePath = GetProcessImageFileName(process.Id);
                var isTarget = false;

                if (!string.IsNullOrWhiteSpace(imagePath))
                {
                    var fullImagePath = Path.GetFullPath(imagePath);
                    var exeName = Path.GetFileName(imagePath);
                    isTarget = targetPaths.Contains(fullImagePath) || targetExeNames.Contains(exeName);
                }
                else
                {
                    // Fallback using process name if image path cannot be queried
                    var fallbackExe = process.ProcessName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                        ? process.ProcessName
                        : process.ProcessName + ".exe";
                    isTarget = targetExeNames.Contains(fallbackExe);
                }

                if (!isTarget)
                {
                    process.Dispose();
                    continue;
                }

                processes.Add(process);
            }
            catch
            {
                process.Dispose();
            }
        }

        var pending = new List<Process>();
        var closed = 0;
        var failed = 0;
        foreach (var process in processes)
        {
            try
            {
                if (process.CloseMainWindow())
                    pending.Add(process);
                else if (process.HasExited)
                {
                    closed++;
                    process.Dispose();
                }
                else
                {
                    failed++;
                    process.Dispose();
                }
            }
            catch
            {
                failed++;
                process.Dispose();
            }
        }

        if (pending.Count > 0)
        {
            await Task.Delay(TimeSpan.FromSeconds(5));
        }
        foreach (var process in pending)
        {
            try
            {
                if (process.HasExited)
                    closed++;
                else
                    failed++;
            }
            catch
            {
                failed++;
            }
            finally
            {
                process.Dispose();
            }
        }

        return new ProtectedAppProcessCloseResult(closed, failed);
    }
}
