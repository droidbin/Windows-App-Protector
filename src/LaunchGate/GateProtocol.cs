using System;
using System.IO;
using System.IO.Pipes;
using System.Text;

internal static class GateProtocol
{
    internal const string PipeName = "WindowsAppProtector.Launch.v2";
    internal const string ExeName = "WindowsAppProtector.Gate.exe";
    internal const byte Version = 1;
    internal const byte Authorize = 1;
    internal const byte Track = 2;
    internal const byte ReadWindowPolicy = 3;
    internal const byte SyncPolicy = 4;
    internal const int MaxWindowPolicyBytes = 60000;
    internal const byte Denied = 0;
    internal const byte Approved = 1;
    internal const byte RateLimited = 2;
    internal const byte PromptRequired = 3;
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);

    internal static NamedPipeClientStream ConnectToService()
    {
#if NET5_0_OR_GREATER
        var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Identification, HandleInheritability.None);
#else
        var pipe = new NamedPipeClientStream(".", PipeName,
            PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadPermissions |
                PipeAccessRights.Synchronize, PipeOptions.Asynchronous,
            System.Security.Principal.TokenImpersonationLevel.Identification, HandleInheritability.None);
#endif
        try
        {
            pipe.Connect(1500);
            var system = new System.Security.Principal.SecurityIdentifier(
                System.Security.Principal.WellKnownSidType.LocalSystemSid, null);
            if (!system.Equals(pipe.GetAccessControl().GetOwner(typeof(System.Security.Principal.SecurityIdentifier))))
                throw new UnauthorizedAccessException("보호 서비스의 신원을 확인할 수 없습니다.");
            return pipe;
        }
        catch { pipe.Dispose(); throw; }
    }

    internal static void WriteText(Stream stream, string value, int maximum)
    {
        var bytes = Utf8.GetBytes(value);
        if (bytes.Length > maximum) throw new InvalidDataException("Gate request exceeds the size limit.");
        stream.WriteByte((byte)bytes.Length);
        stream.WriteByte((byte)(bytes.Length >> 8));
        stream.Write(bytes, 0, bytes.Length);
    }

    internal static string ReadText(PipeStream stream, int maximum, DateTime deadline)
    {
        var header = Read(stream, 2, deadline);
        var length = header[0] | (header[1] << 8);
        if (length > maximum) throw new InvalidDataException("Gate request exceeds the size limit.");
        return Utf8.GetString(Read(stream, length, deadline));
    }

    internal static byte[] Read(PipeStream stream, int length, DateTime deadline)
    {
        var bytes = new byte[length];
        for (int offset = 0; offset < length;)
        {
            var remaining = deadline - DateTime.UtcNow;
            if (remaining <= TimeSpan.Zero) throw new TimeoutException("Gate request timed out.");
            var pending = stream.BeginRead(bytes, offset, length - offset, null, null);
            using (var ready = pending.AsyncWaitHandle)
            {
                if (!ready.WaitOne(remaining)) throw new TimeoutException("Gate request timed out.");
                var count = stream.EndRead(pending);
                if (count == 0) throw new EndOfStreamException();
                offset += count;
            }
        }
        return bytes;
    }
}
