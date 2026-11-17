using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading;

internal sealed class LaunchAuthorizationServer : IDisposable
{
    private readonly Func<byte, string, string, string, int, int, byte> authorize;
    private readonly string gatePath;
    private readonly string agentPath;
    private readonly string uiPath;
    private readonly Func<string> readWindowPolicy;
    private readonly Func<byte> syncPolicy;
    private readonly object lifecycle = new object();
    private NamedPipeServerStream listener;
    private Thread thread;
    private volatile bool stopping;

    internal LaunchAuthorizationServer(string gatePath, string agentPath, string uiPath,
        Func<string> readWindowPolicy, Func<byte> syncPolicy,
        Func<byte, string, string, string, int, int, byte> authorize)
    {
        this.gatePath = gatePath;
        this.agentPath = agentPath;
        this.uiPath = uiPath;
        this.readWindowPolicy = readWindowPolicy;
        this.syncPolicy = syncPolicy;
        this.authorize = authorize;
    }

    internal void Start()
    {
        lock (lifecycle)
        {
            if (thread != null) return;
            stopping = false;
            thread = new Thread(Listen) { IsBackground = true, Name = "WAP launch authorization" };
            thread.Start();
        }
    }

    public void Dispose()
    {
        Thread worker;
        lock (lifecycle)
        {
            stopping = true;
            if (listener != null) listener.Dispose();
            worker = thread;
        }
        if (worker != null && worker.Join(6000))
        {
            lock (lifecycle) thread = null;
        }
    }

    private void Listen()
    {
        var acl = new PipeSecurity();
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(system);
        acl.AddAccessRule(new PipeAccessRule(system, PipeAccessRights.FullControl, AccessControlType.Allow));
        // Avoid granting CreateNewInstance through the generic Write right.
        acl.AddAccessRule(new PipeAccessRule(new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadPermissions |
                PipeAccessRights.Synchronize, AccessControlType.Allow));

        while (!stopping)
        {
            try
            {
                using (var pipe = new NamedPipeServerStream(GateProtocol.PipeName, PipeDirection.InOut, 1,
                    PipeTransmissionMode.Byte, PipeOptions.Asynchronous, 8192, 8192, acl))
                {
                    lock (lifecycle)
                    {
                        if (stopping) return;
                        listener = pipe;
                    }
                    pipe.EndWaitForConnection(pipe.BeginWaitForConnection(null, null));
                    Handle(pipe);
                    lock (lifecycle) listener = null;
                }
            }
            catch (Exception)
            {
                if (!stopping) Thread.Sleep(150);
            }
        }
    }

    private void Handle(NamedPipeServerStream pipe)
    {
        byte reply = GateProtocol.Denied;
        try
        {
            var deadline = DateTime.UtcNow.AddSeconds(2);
            int processId;
            int sessionId;
            var header = GateProtocol.Read(pipe, 2, deadline);
            var command = header[1];
            var expectedPath = command == GateProtocol.ReadWindowPolicy
                ? agentPath
                : command == GateProtocol.SyncPolicy ? uiPath : gatePath;
            if (header[0] == GateProtocol.Version &&
                IsExpectedProcess(pipe, expectedPath, out processId, out sessionId))
            {
                if (command == GateProtocol.ReadWindowPolicy)
                {
                    var policy = readWindowPolicy();
                    if (!string.IsNullOrEmpty(policy))
                    {
                        using (var response = new MemoryStream())
                        {
                            response.WriteByte(GateProtocol.Approved);
                            GateProtocol.WriteText(response, policy, GateProtocol.MaxWindowPolicyBytes);
                            var bytes = response.ToArray();
                            var pending = pipe.BeginWrite(bytes, 0, bytes.Length, null, null);
                            using (var ready = pending.AsyncWaitHandle)
                            {
                                if (ready.WaitOne(1000))
                                {
                                    pipe.EndWrite(pending);
                                    GateProtocol.Read(pipe, 1, DateTime.UtcNow.AddMilliseconds(500));
                                }
                            }
                        }
                        return;
                    }
                }
                else if (command == GateProtocol.SyncPolicy)
                {
                    if (IsAdministratorAndInteractive(pipe)) reply = syncPolicy();
                }
                else if (command == GateProtocol.Authorize || command == GateProtocol.Track)
                {
                string path = GateProtocol.ReadText(pipe, 4096, deadline);
                string value = GateProtocol.ReadText(pipe, 128, deadline);
                string sid = null;
                pipe.RunAsClient(() =>
                {
                    using (var identity = WindowsIdentity.GetCurrent(true))
                    {
                        if (identity != null && identity.User != null)
                            sid = identity.User.Value;
                    }
                });
                if (sid != null) reply = authorize(command, path, value, sid, processId, sessionId);
                }
            }
        }
        catch (Exception)
        {
            // Treat invalid requests and unavailable policy as denied.
        }

        pipe.WriteByte(reply);
        pipe.Flush();
    }

    private static bool IsAdministratorAndInteractive(NamedPipeServerStream pipe)
    {
        bool approved = false;
        pipe.RunAsClient(() =>
        {
            using (var identity = WindowsIdentity.GetCurrent(true))
            {
                if (identity == null || identity.User == null) return;
                var principal = new WindowsPrincipal(identity);
                var interactive = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
                approved = principal.IsInRole(WindowsBuiltInRole.Administrator) &&
                    identity.Groups != null && identity.Groups.Contains(interactive);
            }
        });
        return approved;
    }

    private static bool IsExpectedProcess(NamedPipeServerStream pipe, string expectedPath,
        out int processId, out int sessionId)
    {
        processId = 0;
        sessionId = 0;
        uint pid;
        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle, out pid) || pid == 0 || pid > int.MaxValue) return false;
        using (var process = Process.GetProcessById((int)pid))
        {
            processId = process.Id;
            sessionId = process.SessionId;
            return sessionId > 0 &&
                string.Equals(process.MainModule.FileName, expectedPath, StringComparison.OrdinalIgnoreCase);
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(Microsoft.Win32.SafeHandles.SafePipeHandle pipe, out uint pid);
}

[DataContract]
internal sealed class LaunchAttemptState
{
    [DataMember] public int Failed { get; set; }
    [DataMember] public long DeadlineUtcTicks { get; set; }

    internal static LaunchAttemptState Load(string path)
    {
        if (!File.Exists(path)) return new LaunchAttemptState();
        using (var stream = File.OpenRead(path))
            return (LaunchAttemptState)new DataContractJsonSerializer(typeof(LaunchAttemptState)).ReadObject(stream);
    }

    internal void Save(string path)
    {
        string temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var stream = File.Create(temporary))
                new DataContractJsonSerializer(typeof(LaunchAttemptState)).WriteObject(stream, this);
            if (File.Exists(path)) File.Replace(temporary, path, null);
            else File.Move(temporary, path);
        }
        finally
        {
            File.Delete(temporary);
        }
    }

    internal static bool Verify(string pin, string saltText, string hashText)
    {
        if (string.IsNullOrWhiteSpace(pin) || string.IsNullOrEmpty(saltText) || string.IsNullOrEmpty(hashText))
            return false;
        byte[] salt = Convert.FromBase64String(saltText);
        byte[] expected = Convert.FromBase64String(hashText);
        if (salt.Length != 16 || expected.Length != 32) return false;
        using (var derivation = new Rfc2898DeriveBytes(pin, salt, 120000, HashAlgorithmName.SHA256))
        {
            byte[] computed = derivation.GetBytes(expected.Length);
            int difference = 0;
            for (int i = 0; i < expected.Length; i++) difference |= computed[i] ^ expected[i];
            return difference == 0;
        }
    }
}
