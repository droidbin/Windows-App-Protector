using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.ServiceProcess;
using System.Threading;
using System.Text;
using Microsoft.Win32;

internal static class Program
{
    private const string ServiceName = "WindowsAppProtectorService";

    private static void Main(string[] args)
    {
        if (args.Any(arg => string.Equals(arg, "--console", StringComparison.OrdinalIgnoreCase)))
        {
            using (var worker = new ProtectionWorker())
            {
                worker.Start();
                Console.WriteLine(ProductBrand.Name + " service worker is running. Press Enter to stop.");
                Console.ReadLine();
                worker.Stop();
            }
            return;
        }

        ServiceBase.Run(new ProtectorService());
    }

    private sealed class ProtectorService : ServiceBase
    {
        private readonly ProtectionWorker worker = new ProtectionWorker();

        public ProtectorService()
        {
            ServiceName = Program.ServiceName;
            CanStop = true;
            CanShutdown = true;
            CanHandleSessionChangeEvent = true;
            CanHandlePowerEvent = true;
        }

        protected override void OnStart(string[] args)
        {
            worker.Start();
        }

        protected override void OnStop()
        {
            worker.Stop();
        }

        protected override void OnShutdown()
        {
            worker.Stop();
        }

        protected override void OnSessionChange(SessionChangeDescription change)
        {
            if (change.Reason == SessionChangeReason.SessionLock ||
                change.Reason == SessionChangeReason.ConsoleDisconnect ||
                change.Reason == SessionChangeReason.RemoteDisconnect ||
                change.Reason == SessionChangeReason.SessionLogoff)
                worker.RevokeLaunchGrants();
        }

        protected override bool OnPowerEvent(PowerBroadcastStatus status)
        {
            if (status == PowerBroadcastStatus.Suspend || status == PowerBroadcastStatus.ResumeAutomatic)
                worker.RevokeLaunchGrants();
            return true;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                worker.Dispose();
            }

            base.Dispose(disposing);
        }
    }
}

internal sealed class ProtectionWorker : IDisposable
{
    private const string AppName = "Windows App Protector";
    private const string UiExeName = "WindowsAppProtector.WinUI.exe";
    private const string IfeoRegistryPath = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
    private const string SaferCodeIdentifiersPath = @"SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers";
    private const string MarkerName = "WindowsAppProtectorManaged";
    private const int SePrivilegeEnabled = 0x00000002;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private static readonly HashSet<string> WindowOnlyExecutableNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    {
        "arc.exe",
        "brave.exe",
        "chrome.exe",
        "firefox.exe",
        "iexplore.exe",
        "msedge.exe",
        "opera.exe",
        "opera_gx.exe",
        "samsunginternet.exe",
        "vivaldi.exe",
        "whale.exe",
    };
    private readonly string configPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        AppName,
        "config.json");
    private readonly string uiPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, UiExeName);
    private readonly string gatePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, GateProtocol.ExeName);
    private readonly LaunchAuthorizationServer launchServer;
    private readonly SessionAgentSupervisor sessionAgents;
    private readonly object grantsLock = new object();
    private readonly Dictionary<string, LaunchGrant> launchGrants =
        new Dictionary<string, LaunchGrant>(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<int, PendingLaunch> pendingLaunches = new Dictionary<int, PendingLaunch>();
    private readonly Timer timer;
    private readonly object syncRoot = new object();
    private bool running;

    public ProtectionWorker()
    {
        timer = new Timer(_ => Tick(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        string agentPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, SessionAgentSupervisor.ExeName);
        sessionAgents = new SessionAgentSupervisor(agentPath);
        launchServer = new LaunchAuthorizationServer(
            gatePath, agentPath, uiPath, ReadWindowPolicy, ResyncPolicy, AuthorizeLaunch);
    }

    public void Start()
    {
        using (var identity = WindowsIdentity.GetCurrent())
        {
            if (identity.IsSystem) sessionAgents.Start();
        }
        running = true;
        launchServer.Start();
        timer.Change(TimeSpan.Zero, TimeSpan.FromSeconds(5));
    }

    public void Stop()
    {
        running = false;
        timer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        lock (syncRoot) sessionAgents.Dispose();
        launchServer.Dispose();
        RevokeLaunchGrants();
    }

    public void Dispose()
    {
        Stop();
        timer.Dispose();
    }

    private void Tick()
    {
        if (!running || !Monitor.TryEnter(syncRoot))
        {
            return;
        }

        try
        {
            sessionAgents.Reconcile();
            var config = LoadConfig();
            if (config == null)
            {
                return;
            }

            var protectedApps = config.ProtectedApps ?? new List<ProtectedApp>();
            SyncRules(protectedApps, config.EnableLaunchGate && File.Exists(gatePath));
        }
        catch (Exception ex)
        {
            try
            {
                EventLog.WriteEntry("Windows App Protector", ex.ToString(), EventLogEntryType.Warning);
            }
            catch
            {
            }
        }
        finally
        {
            Monitor.Exit(syncRoot);
        }
    }

    private string ReadWindowPolicy()
    {
        string generation = sessionAgents.Generation;
        if (string.IsNullOrEmpty(generation)) return null;
        var config = LoadConfig();
        if (config == null) return null;
        var policy = new StringBuilder(generation);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var app in config.ProtectedApps ?? new List<ProtectedApp>())
        {
            if (!app.Enabled || !UsesWindowOnlyBlocking(app)) continue;
            string identity = app.IsPackaged ? app.PackageFamilyName : app.Path;
            if (string.IsNullOrWhiteSpace(identity)) continue;
            if (!app.IsPackaged)
            {
                if (!Path.IsPathRooted(identity)) continue;
                identity = Path.GetFullPath(identity);
            }
            string line = (app.IsPackaged ? "F:" : "P:") + Convert.ToBase64String(Encoding.UTF8.GetBytes(identity));
            if (seen.Add(line)) policy.Append('\n').Append(line);
        }
        return policy.ToString();
    }

    private byte ResyncPolicy()
    {
        if (!running) return GateProtocol.Denied;

        lock (syncRoot)
        {
            if (!running) return GateProtocol.Denied;
            var config = LoadConfig();
            if (config == null) return GateProtocol.Denied;

            var protectedApps = config.ProtectedApps ?? new List<ProtectedApp>();
            SyncRules(protectedApps, config.EnableLaunchGate && File.Exists(gatePath));
            return GateProtocol.Approved;
        }
    }

    private AppConfig LoadConfig()
    {
        string selectedPath = GetSharedConfigPath();
        if (string.IsNullOrEmpty(selectedPath) || !File.Exists(selectedPath))
        {
            return null;
        }

        using (var stream = new FileStream(selectedPath, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete))
        {
            var serializer = new DataContractJsonSerializer(typeof(AppConfig));
            var config = serializer.ReadObject(stream) as AppConfig;
            if (config == null || (config.StorageVersion != 0 && config.StorageVersion != 2))
                throw new InvalidDataException("Unsupported protection settings format.");
            return config;
        }
    }

    private string GetSharedConfigPath()
    {
        return File.Exists(configPath) ? configPath : string.Empty;
    }

    internal void RevokeLaunchGrants()
    {
        lock (grantsLock)
        {
            launchGrants.Clear();
            pendingLaunches.Clear();
        }
    }

    private byte AuthorizeLaunch(byte command, string path, string value, string sid, int gatePid, int sessionId)
    {
        lock (grantsLock)
            return HandleLaunchRequest(command, path, value, sid, gatePid, sessionId);
    }

    private byte HandleLaunchRequest(byte command, string path, string value, string sid, int gatePid, int sessionId)
    {
        var config = LoadConfig();
        if (config == null || !config.EnableLaunchGate || !Path.IsPathRooted(path))
            return GateProtocol.Denied;
        path = Path.GetFullPath(path);
        var target = (config.ProtectedApps ?? new List<ProtectedApp>()).FirstOrDefault(app =>
            app.Enabled && CanUseGate(app) && string.Equals(Path.GetFullPath(app.Path), path, StringComparison.OrdinalIgnoreCase));
        if (target == null) return GateProtocol.Denied;

        var now = DateTime.UtcNow;
        string salt = string.IsNullOrEmpty(target.LaunchPinHash) ? config.AppPinSalt : target.LaunchPinSalt;
        string hash = string.IsNullOrEmpty(target.LaunchPinHash) ? config.AppPinHash : target.LaunchPinHash;
        int minutes = Math.Max(0, Math.Min(target.LaunchAllowedMinutes, 1440));
        string grantKey = sid + "|" + sessionId + "|" + path + "|" + (hash ?? string.Empty) + "|" +
            minutes.ToString(CultureInfo.InvariantCulture) + "|" + target.LaunchLockStartMinute + "|" +
            target.LaunchLockEndMinute + "|" + target.LaunchRelockOnExit;
        foreach (var expired in launchGrants.Where(grant => grant.Value.Expires <= now).Select(grant => grant.Key).ToArray())
            launchGrants.Remove(expired);
        foreach (var expired in pendingLaunches.Where(launch => launch.Value.TrackBefore <= now).Select(launch => launch.Key).ToArray())
            pendingLaunches.Remove(expired);

        if (command == GateProtocol.Track)
        {
            PendingLaunch pending;
            int childPid;
            if (!pendingLaunches.TryGetValue(gatePid, out pending) || pending.Key != grantKey ||
                !int.TryParse(value, out childPid) || childPid <= 0) return GateProtocol.Denied;
            pendingLaunches.Remove(gatePid);
            using (var process = Process.GetProcessById(childPid))
            {
                if (process.SessionId != sessionId || process.StartTime.ToUniversalTime() < pending.Started ||
                    !string.Equals(path, process.MainModule.FileName, StringComparison.OrdinalIgnoreCase))
                    return GateProtocol.Denied;
                pending.Grant.Processes[childPid] = process.StartTime.ToUniversalTime();
            }
            if (launchGrants.Count < 1024 || launchGrants.ContainsKey(grantKey))
                launchGrants[grantKey] = pending.Grant;
            return GateProtocol.Approved;
        }

        if (command != GateProtocol.Authorize) return GateProtocol.Denied;
        if (!IsWithinLockHours(target, DateTime.Now)) return GateProtocol.Approved;

        LaunchGrant active;
        if (minutes > 0 && launchGrants.TryGetValue(grantKey, out active))
        {
            if (!target.LaunchRelockOnExit || HasRunningLaunch(active))
            {
                if (target.LaunchRelockOnExit) AllowTracking(gatePid, grantKey, active, now);
                return GateProtocol.Approved;
            }
            launchGrants.Remove(grantKey);
        }
        string statePath = Path.Combine(Path.GetDirectoryName(configPath), "launch-attempts-" + sid + ".json");
        var state = LaunchAttemptState.Load(statePath);
        if (state.DeadlineUtcTicks > now.Ticks) return GateProtocol.RateLimited;
        if (string.IsNullOrEmpty(value)) return GateProtocol.PromptRequired;
        if (LaunchAttemptState.Verify(value, salt, hash))
        {
            new LaunchAttemptState().Save(statePath);
            if (minutes > 0 && launchGrants.Count < 1024)
            {
                var grant = new LaunchGrant { Expires = now.AddMinutes(minutes) };
                if (target.LaunchRelockOnExit) AllowTracking(gatePid, grantKey, grant, now);
                else launchGrants[grantKey] = grant;
            }
            return GateProtocol.Approved;
        }

        state.Failed = Math.Min(state.Failed + 1, 15);
        if (state.Failed >= 5)
            state.DeadlineUtcTicks = now.AddSeconds(Math.Min(900, 30 * (1 << (state.Failed - 5)))).Ticks;
        state.Save(statePath);
        return GateProtocol.Denied;
    }

    private void AllowTracking(int gatePid, string key, LaunchGrant grant, DateTime now)
    {
        if (pendingLaunches.Count < 1024)
            pendingLaunches[gatePid] = new PendingLaunch { Key = key, Grant = grant, Started = now, TrackBefore = now.AddSeconds(5) };
    }

    private static bool HasRunningLaunch(LaunchGrant grant)
    {
        foreach (var started in grant.Processes.ToArray())
        {
            try
            {
                using (var process = Process.GetProcessById(started.Key))
                    if (!process.HasExited && process.StartTime.ToUniversalTime() == started.Value) continue;
            }
            catch (ArgumentException) { }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
            grant.Processes.Remove(started.Key);
        }
        return grant.Processes.Count != 0;
    }

    private sealed class LaunchGrant
    {
        internal DateTime Expires;
        internal readonly Dictionary<int, DateTime> Processes = new Dictionary<int, DateTime>();
    }

    private sealed class PendingLaunch
    {
        internal string Key;
        internal LaunchGrant Grant;
        internal DateTime Started, TrackBefore;
    }

    private static bool IsWithinLockHours(ProtectedApp target, DateTime localTime)
    {
        int? start = target.LaunchLockStartMinute;
        int? end = target.LaunchLockEndMinute;
        if (!start.HasValue || !end.HasValue || start < 0 || end < 0 || start >= 1440 || end >= 1440 || start == end)
            return true;
        int minute = localTime.Hour * 60 + localTime.Minute;
        return start < end ? minute >= start && minute < end : minute >= start || minute < end;
    }

    private static bool CanUseGate(ProtectedApp app)
    {
        return !app.IsPackaged && !UsesWindowOnlyBlocking(app) && !string.IsNullOrWhiteSpace(app.Path) &&
            Path.IsPathRooted(app.Path) && string.Equals(Path.GetExtension(app.Path), ".exe", StringComparison.OrdinalIgnoreCase);
    }

    private void SyncRules(IEnumerable<ProtectedApp> apps, bool enableLaunchGate)
    {
        if (!File.Exists(uiPath))
        {
            return;
        }

        var desired = apps
            .Where(app => app.Enabled)
            .Where(app => !string.IsNullOrWhiteSpace(GetBlockRuleName(app)))
            .Where(app => !UsesWindowOnlyBlocking(app))
            .GroupBy(app => GetBlockRuleName(app), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);

        using (var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        {
            CleanupLegacySoftwareRestrictionRules(localMachine, apps);

            using (var root = localMachine.OpenSubKey(IfeoRegistryPath, writable: true))
            {
                if (root == null)
                {
                    return;
                }

                foreach (var existingName in ReadManagedRuleNames(root).Except(desired.Keys, StringComparer.OrdinalIgnoreCase).ToArray())
                {
                    DeleteManagedRule(root, existingName);
                }

                foreach (var entry in desired)
                {
                    using (var key = root.CreateSubKey(entry.Key, writable: true))
                    {
                        if (key == null)
                        {
                            continue;
                        }

                        bool owned = Convert.ToString(key.GetValue(MarkerName)) == "1";
                        if (key.GetSubKeyNames().Any(name => !IsManagedFilter(key, name)) ||
                            (!owned && (key.GetValue("Debugger") != null || key.GetValue("UseFilter") != null)))
                            continue;

                        bool useGate = enableLaunchGate && entry.Value.All(CanUseGate);
                        key.SetValue(MarkerName, "1", RegistryValueKind.String);
                        if (useGate)
                        {
                            var targets = entry.Value.Select(app => Path.GetFullPath(app.Path))
                                .Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
                                .Select((path, index) => new { Path = path, Key = "WAP.Launch." + index }).ToArray();
                            foreach (var target in targets)
                            {
                                using (var filter = key.CreateSubKey(target.Key))
                                {
                                    filter.SetValue(MarkerName, "1");
                                    filter.SetValue("FilterFullPath", target.Path);
                                    filter.SetValue("Debugger", "\"" + gatePath + "\" --launch");
                                }
                            }
                            key.SetValue("UseFilter", 1, RegistryValueKind.DWord);
                            key.DeleteValue("Debugger", false);
                            DeleteManagedFilters(key, targets.Select(target => target.Key));
                        }
                        else
                        {
                            key.SetValue("Debugger", "\"" + uiPath + "\" --blocked", RegistryValueKind.String);
                            key.DeleteValue("UseFilter", false);
                            DeleteManagedFilters(key, Enumerable.Empty<string>());
                        }
                    }
                }
            }
        }
    }

    private static bool IsManagedFilter(RegistryKey key, string name)
    {
        if (!name.StartsWith("WAP.Launch.", StringComparison.Ordinal)) return false;
        using (var filter = key.OpenSubKey(name))
            return filter != null && Convert.ToString(filter.GetValue(MarkerName)) == "1";
    }

    private static void DeleteManagedFilters(RegistryKey key, IEnumerable<string> keep)
    {
        foreach (var name in key.GetSubKeyNames().Except(keep, StringComparer.OrdinalIgnoreCase))
            if (IsManagedFilter(key, name)) key.DeleteSubKey(name, false);
    }

    private static void RemoveManagedRules()
    {
        using (var localMachine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
        using (var root = localMachine.OpenSubKey(IfeoRegistryPath, writable: true))
        {
            if (root == null)
            {
                return;
            }

            foreach (var existingName in ReadManagedRuleNames(root).ToArray())
            {
                DeleteManagedRule(root, existingName);
            }
        }
    }

    private static string GetBlockRuleName(ProtectedApp app)
    {
        if (app != null && !string.IsNullOrWhiteSpace(app.ExecutableName))
        {
            return app.ExecutableName;
        }

        if (app == null || string.IsNullOrWhiteSpace(app.Path))
        {
            return string.Empty;
        }

        return Path.GetFileName(app.Path);
    }

    private static bool UsesWindowOnlyBlocking(ProtectedApp app)
    {
        if (app.IsPackaged) return true;
        string executableName = GetBlockRuleName(app);
        return !string.IsNullOrWhiteSpace(executableName) &&
            WindowOnlyExecutableNames.Contains(executableName);
    }

    private static void CleanupLegacySoftwareRestrictionRules(RegistryKey localMachine, IEnumerable<ProtectedApp> apps)
    {
        var signatures = BuildLegacyRuleSignatures(apps);
        if (signatures.Count == 0)
        {
            return;
        }

        using (var codeIdentifiers = localMachine.OpenSubKey(SaferCodeIdentifiersPath, writable: true))
        {
            if (codeIdentifiers == null)
            {
                return;
            }

            DeleteMatchingLegacyRules(codeIdentifiers, @"0\Paths", signatures);
            DeleteMatchingLegacyRules(codeIdentifiers, @"0\Hashes", signatures);
        }
    }

    private static HashSet<string> BuildLegacyRuleSignatures(IEnumerable<ProtectedApp> apps)
    {
        var signatures = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var app in apps)
        {
            if (app == null)
            {
                continue;
            }

            AddSignature(signatures, app.Name);
            AddSignature(signatures, app.Path);
            AddSignature(signatures, app.ExecutableName);
            AddSignature(signatures, app.PackageFamilyName);
            AddSignature(signatures, app.AppUserModelId);

            if (!string.IsNullOrWhiteSpace(app.PackageFamilyName))
            {
                int separator = app.PackageFamilyName.IndexOf('_');
                if (separator > 0)
                {
                    AddSignature(signatures, app.PackageFamilyName.Substring(0, separator));
                }
            }
        }

        return signatures;
    }

    private static void AddSignature(HashSet<string> signatures, string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return;
        }

        string trimmed = value.Trim();
        if (trimmed.Length >= 4)
        {
            signatures.Add(trimmed);
        }
    }

    private static void DeleteMatchingLegacyRules(RegistryKey codeIdentifiers, string relativePath, HashSet<string> signatures)
    {
        using (var container = codeIdentifiers.OpenSubKey(relativePath, writable: true))
        {
            if (container == null)
            {
                return;
            }

            foreach (var ruleName in container.GetSubKeyNames())
            {
                try
                {
                    using (var rule = container.OpenSubKey(ruleName))
                    {
                        if (rule == null || !LegacyRuleMatches(rule, signatures))
                        {
                            continue;
                        }
                    }

                    DeleteLegacyRule(container, ruleName);
                }
                catch
                {
                }
            }
        }
    }

    private static bool LegacyRuleMatches(RegistryKey rule, HashSet<string> signatures)
    {
        foreach (var valueName in new[] { "Description", "ItemPath", "ItemData" })
        {
            var value = Convert.ToString(rule.GetValue(valueName));
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            foreach (var signature in signatures)
            {
                if (value.IndexOf(signature, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return true;
                }
            }
        }

        return false;
    }

    private static void DeleteLegacyRule(RegistryKey container, string ruleName)
    {
        try
        {
            container.DeleteSubKeyTree(ruleName, throwOnMissingSubKey: false);
            return;
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (SecurityException)
        {
        }

        if (!RepairLegacyRuleAccess(container, ruleName))
        {
            return;
        }

        container.DeleteSubKeyTree(ruleName, throwOnMissingSubKey: false);
    }

    private static bool RepairLegacyRuleAccess(RegistryKey container, string ruleName)
    {
        EnablePrivilege("SeTakeOwnershipPrivilege");
        EnablePrivilege("SeRestorePrivilege");
        EnablePrivilege("SeBackupPrivilege");

        try
        {
            using (var rule = container.OpenSubKey(
                ruleName,
                RegistryKeyPermissionCheck.ReadWriteSubTree,
                RegistryRights.ReadKey |
                RegistryRights.ReadPermissions |
                RegistryRights.ChangePermissions |
                RegistryRights.TakeOwnership))
            {
                if (rule == null)
                {
                    return false;
                }

                var security = rule.GetAccessControl(AccessControlSections.All);
                security.SetOwner(new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
                security.SetAccessRuleProtection(false, false);
                security.SetAccessRule(new RegistryAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    RegistryRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
                security.SetAccessRule(new RegistryAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    RegistryRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
                rule.SetAccessControl(security);
                return true;
            }
        }
        catch
        {
            return false;
        }
    }

    private static bool EnablePrivilege(string privilegeName)
    {
        IntPtr token;
        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out token))
        {
            return false;
        }

        try
        {
            Luid luid;
            if (!LookupPrivilegeValue(null, privilegeName, out luid))
            {
                return false;
            }

            var privileges = new TokenPrivileges
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SePrivilegeEnabled,
            };
            return AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private static IEnumerable<string> ReadManagedRuleNames(RegistryKey root)
    {
        foreach (var name in root.GetSubKeyNames())
        {
            RegistryKey key = null;
            try
            {
                key = root.OpenSubKey(name);
                if (key != null && Convert.ToString(key.GetValue(MarkerName)) == "1")
                {
                    yield return name;
                }
            }
            finally
            {
                if (key != null)
                {
                    key.Dispose();
                }
            }
        }
    }

    private static void DeleteManagedRule(RegistryKey root, string exeName)
    {
        try
        {
            using (var key = root.OpenSubKey(exeName, writable: true))
            {
                if (key == null || Convert.ToString(key.GetValue(MarkerName)) != "1")
                {
                    return;
                }

                key.DeleteValue("Debugger", throwOnMissingValue: false);
                key.DeleteValue(MarkerName, throwOnMissingValue: false);
                DeleteManagedFilters(key, Enumerable.Empty<string>());
                if (key.SubKeyCount == 0) key.DeleteValue("UseFilter", throwOnMissingValue: false);
            }

            try
            {
                using (var key = root.OpenSubKey(exeName))
                    if (key == null || key.ValueCount != 0 || key.SubKeyCount != 0) return;
                root.DeleteSubKey(exeName, throwOnMissingSubKey: false);
            }
            catch
            {
            }
        }
        catch
        {
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public Luid Luid;
        public uint Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        bool disableAllPrivileges,
        ref TokenPrivileges newState,
        uint bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}

[DataContract]
internal sealed class AppConfig
{
    public AppConfig()
    {
        UnlockUntil = string.Empty;
        ProtectedApps = new List<ProtectedApp>();
    }

    [DataMember]
    public bool ProtectionEnabled { get; set; }

    [DataMember]
    public int StorageVersion { get; set; }

    [DataMember]
    public string UnlockUntil { get; set; }

    [DataMember]
    public List<ProtectedApp> ProtectedApps { get; set; }

    [DataMember] public bool EnableLaunchGate { get; set; }
    [DataMember] public string AppPinSalt { get; set; }
    [DataMember] public string AppPinHash { get; set; }
}

[DataContract]
internal sealed class ProtectedApp
{
    public ProtectedApp()
    {
        Name = string.Empty;
        Path = string.Empty;
        PackageFamilyName = string.Empty;
        AppUserModelId = string.Empty;
        ExecutableName = string.Empty;
        Enabled = true;
    }

    [DataMember]
    public string Name { get; set; }

    [DataMember]
    public string Path { get; set; }

    [DataMember]
    public bool IsPackaged { get; set; }

    [DataMember]
    public string PackageFamilyName { get; set; }

    [DataMember]
    public string AppUserModelId { get; set; }

    [DataMember]
    public string ExecutableName { get; set; }

    [DataMember]
    public bool Enabled { get; set; }

    [DataMember] public string LaunchPinSalt { get; set; }
    [DataMember] public string LaunchPinHash { get; set; }
    [DataMember] public int LaunchAllowedMinutes { get; set; }
    [DataMember] public int? LaunchLockStartMinute { get; set; }
    [DataMember] public int? LaunchLockEndMinute { get; set; }
    [DataMember] public bool LaunchRelockOnExit { get; set; }
}
