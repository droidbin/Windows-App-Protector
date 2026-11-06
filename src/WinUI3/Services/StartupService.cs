using Microsoft.Win32;
using System.Diagnostics;
using System.Security;

namespace WindowsAppProtector.Services;

public static class StartupService
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "Windows App Protector";
    private const string TaskName = "Windows App Protector";

    public static void SetEnabled(bool enabled)
    {
        if (enabled)
        {
            CreateStartupTask(GetExecutablePath());
            DeleteRunValue();
            return;
        }

        DeleteStartupTask();
        DeleteRunValue();
    }

    public static bool IsEnabled()
    {
        if (StartupTaskExists())
        {
            return true;
        }

        using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
        return key?.GetValue(ValueName) is string value && !string.IsNullOrWhiteSpace(value);
    }

    private static string GetExecutablePath()
    {
        return Environment.ProcessPath
            ?? Process.GetCurrentProcess().MainModule?.FileName
            ?? throw new InvalidOperationException("현재 실행 파일 경로를 확인할 수 없습니다.");
    }

    private static void CreateStartupTask(string executablePath)
    {
        // schtasks /SC ONLOGON defaults stop the task on battery power, kill it after 72 hours,
        // and run it at below-normal priority. Register from XML so the protector stays resident.
        var xmlPath = Path.Combine(Path.GetTempPath(), $"wap-startup-{Guid.NewGuid():N}.xml");
        try
        {
            File.WriteAllText(xmlPath, BuildStartupTaskXml(executablePath), System.Text.Encoding.Unicode);
            var result = RunSchtasks("/Create", "/TN", TaskName, "/XML", xmlPath, "/F");
            if (result.ExitCode != 0)
            {
                throw new InvalidOperationException(
                    string.IsNullOrWhiteSpace(result.Error)
                        ? "시작프로그램 예약 작업을 만들 수 없습니다."
                        : result.Error.Trim());
            }
        }
        finally
        {
            try { File.Delete(xmlPath); } catch { }
        }
    }

    internal static string BuildStartupTaskXml(string executablePath)
    {
        using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
        var userSid = identity.User?.Value
            ?? throw new InvalidOperationException("현재 사용자 SID를 확인할 수 없습니다.");
        var command = SecurityElement.Escape(executablePath);
        var user = SecurityElement.Escape(userSid);

        return $"""
            <?xml version="1.0" encoding="UTF-16"?>
            <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo>
                <Description>Windows App Protector background protection</Description>
              </RegistrationInfo>
              <Triggers>
                <LogonTrigger>
                  <Enabled>true</Enabled>
                  <UserId>{user}</UserId>
                </LogonTrigger>
              </Triggers>
              <Principals>
                <Principal id="Author">
                  <UserId>{user}</UserId>
                  <LogonType>InteractiveToken</LogonType>
                  <RunLevel>HighestAvailable</RunLevel>
                </Principal>
              </Principals>
              <Settings>
                <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
                <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
                <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
                <AllowHardTerminate>true</AllowHardTerminate>
                <StartWhenAvailable>false</StartWhenAvailable>
                <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
                <IdleSettings>
                  <StopOnIdleEnd>false</StopOnIdleEnd>
                  <RestartOnIdle>false</RestartOnIdle>
                </IdleSettings>
                <AllowStartOnDemand>true</AllowStartOnDemand>
                <Enabled>true</Enabled>
                <Hidden>false</Hidden>
                <RunOnlyIfIdle>false</RunOnlyIfIdle>
                <WakeToRun>false</WakeToRun>
                <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
                <Priority>4</Priority>
              </Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>{command}</Command>
                  <Arguments>{App.BackgroundArgument}</Arguments>
                </Exec>
              </Actions>
            </Task>
            """;
    }

    private static void DeleteStartupTask()
    {
        var result = RunSchtasks("/Delete", "/TN", TaskName, "/F");
        if (result.ExitCode != 0 && !TaskNotFound(result))
        {
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(result.Error)
                    ? "시작프로그램 예약 작업을 삭제할 수 없습니다."
                    : result.Error.Trim());
        }
    }

    private static bool StartupTaskExists()
    {
        return RunSchtasks("/Query", "/TN", TaskName).ExitCode == 0;
    }

    private static void DeleteRunValue()
    {
        using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true);
        key?.DeleteValue(ValueName, throwOnMissingValue: false);
    }

    private static bool TaskNotFound((int ExitCode, string Output, string Error) result)
    {
        var text = result.Output + "\n" + result.Error;
        return text.Contains("cannot find", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("does not exist", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("찾을 수 없습니다", StringComparison.OrdinalIgnoreCase) ||
            text.Contains("없습니다", StringComparison.OrdinalIgnoreCase);
    }

    private static (int ExitCode, string Output, string Error) RunSchtasks(params string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "schtasks.exe",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("작업 스케줄러를 실행할 수 없습니다.");
        var output = process.StandardOutput.ReadToEnd();
        var error = process.StandardError.ReadToEnd();
        process.WaitForExit();
        return (process.ExitCode, output, error);
    }
}
