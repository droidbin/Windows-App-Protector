using System.Diagnostics;
using WindowsAppProtector.Models;

namespace WindowsAppProtector.Services;

public readonly record struct ProtectedAppProcessCloseResult(int Closed, int Failed);

public sealed class ProtectedAppProcessService
{
    public async Task<ProtectedAppProcessCloseResult> CloseRunningAppsAsync(IEnumerable<ProtectedApp> apps)
    {
        // Callers supply the apps being locked; their current Enabled state may still be false.
        var targets = apps
            .Where(app => !app.IsPackaged && !string.IsNullOrWhiteSpace(app.Path))
            .Select(app => Path.GetFullPath(app.Path))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (targets.Count == 0)
        {
            return new ProtectedAppProcessCloseResult(0, 0);
        }

        var processes = new List<Process>();

        foreach (var process in Process.GetProcesses())
        {
            try
            {
                if (process.Id == Environment.ProcessId || process.HasExited ||
                    !targets.Contains(Path.GetFullPath(process.MainModule?.FileName ?? string.Empty)))
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
