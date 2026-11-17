[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SetupExePath,

    [string[]]$ProtectedExecutableNames = @(),

    [string]$OutputDirectory = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function ConvertTo-MarkdownText {
    param([AllowNull()][object]$Value)

    if ($null -eq $Value) {
        return "없음"
    }

    return ([string]$Value).Replace("|", "\|").Replace("`r", " ").Replace("`n", " ")
}

function Get-ScheduledTaskEvidence {
    try {
        $scheduledTask = Get-ScheduledTask -TaskName "Windows App Protector" -ErrorAction Stop
        $scheduledTaskInfo = Get-ScheduledTaskInfo -InputObject $scheduledTask -ErrorAction Stop
        return [pscustomobject]@{
            Exists = $true
            State = [string]$scheduledTask.State
            LastRunTime = $scheduledTaskInfo.LastRunTime
            LastTaskResult = $scheduledTaskInfo.LastTaskResult
            NextRunTime = $scheduledTaskInfo.NextRunTime
            Actions = @($scheduledTask.Actions | ForEach-Object {
                [pscustomobject]@{
                    Execute = $_.Execute
                    Arguments = $_.Arguments
                    WorkingDirectory = $_.WorkingDirectory
                }
            })
        }
    }
    catch {
        return [pscustomobject]@{
            Exists = $false
            State = $null
            LastRunTime = $null
            LastTaskResult = $null
            NextRunTime = $null
            Actions = @()
            Error = $_.Exception.Message
        }
    }
}

function Get-IfeoEvidence {
    param([string[]]$RequestedExecutableNames)

    $ifeoRegistryPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    $managedExecutableNames = @()
    try {
        $managedExecutableNames = @(Get-ChildItem -LiteralPath $ifeoRegistryPath -ErrorAction Stop | Where-Object {
            $_.GetValue("WindowsAppProtectorManaged") -eq "1"
        } | ForEach-Object { $_.PSChildName })
    }
    catch {
        return @([pscustomobject]@{
            ExecutableName = "<IFEO 조회 실패>"
            Exists = $false
            Managed = $false
            Debugger = $null
            UseFilter = $null
            Filters = @()
            Error = $_.Exception.Message
        })
    }

    $executableNames = @($RequestedExecutableNames + $managedExecutableNames | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_)
    } | Sort-Object -Unique)

    $ifeoEvidence = foreach ($executableName in $executableNames) {
        $executableRegistryPath = Join-Path -Path $ifeoRegistryPath -ChildPath $executableName
        if (-not (Test-Path -LiteralPath $executableRegistryPath)) {
            [pscustomobject]@{
                ExecutableName = $executableName
                Exists = $false
                Managed = $false
                Debugger = $null
                UseFilter = $null
                Filters = @()
            }
            continue
        }

        $executableRegistryKey = Get-Item -LiteralPath $executableRegistryPath -ErrorAction Stop
        $filterEvidence = @(Get-ChildItem -LiteralPath $executableRegistryPath -ErrorAction Stop | Where-Object {
            $_.PSChildName -like "WAP.Launch.*"
        } | ForEach-Object {
            [pscustomobject]@{
                Name = $_.PSChildName
                Managed = $_.GetValue("WindowsAppProtectorManaged") -eq "1"
                FilterFullPath = $_.GetValue("FilterFullPath")
                Debugger = $_.GetValue("Debugger")
            }
        })

        [pscustomobject]@{
            ExecutableName = $executableName
            Exists = $true
            Managed = $executableRegistryKey.GetValue("WindowsAppProtectorManaged") -eq "1"
            Debugger = $executableRegistryKey.GetValue("Debugger")
            UseFilter = $executableRegistryKey.GetValue("UseFilter")
            Filters = $filterEvidence
        }
    }

    return @($ifeoEvidence)
}

$resolvedSetupExePath = (Resolve-Path -LiteralPath $SetupExePath -ErrorAction Stop).Path
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputDirectory = Join-Path -Path (Get-Location).Path -ChildPath "VmEvidence-$timestamp"
}

$resolvedOutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
$null = New-Item -ItemType Directory -Path $resolvedOutputDirectory -Force

$operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem
$currentVersionRegistry = Get-ItemProperty -LiteralPath "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$uninstallRegistryPath = "Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall\WindowsAppProtector"
$installedProduct = if (Test-Path -LiteralPath $uninstallRegistryPath) {
    $uninstallEntry = Get-ItemProperty -LiteralPath $uninstallRegistryPath
    [pscustomobject]@{
        Exists = $true
        DisplayName = $uninstallEntry.DisplayName
        DisplayVersion = $uninstallEntry.DisplayVersion
        InstallLocation = $uninstallEntry.InstallLocation
        UninstallString = $uninstallEntry.UninstallString
    }
}
else {
    [pscustomobject]@{
        Exists = $false
        DisplayName = $null
        DisplayVersion = $null
        InstallLocation = $null
        UninstallString = $null
    }
}

$serviceInstance = Get-CimInstance -ClassName Win32_Service -Filter "Name='WindowsAppProtectorService'" -ErrorAction SilentlyContinue
$serviceEvidence = if ($null -ne $serviceInstance) {
    [pscustomobject]@{
        Exists = $true
        Name = $serviceInstance.Name
        DisplayName = $serviceInstance.DisplayName
        State = $serviceInstance.State
        StartMode = $serviceInstance.StartMode
        ProcessId = $serviceInstance.ProcessId
        PathName = $serviceInstance.PathName
    }
}
else {
    [pscustomobject]@{
        Exists = $false
        Name = "WindowsAppProtectorService"
        DisplayName = $null
        State = $null
        StartMode = $null
        ProcessId = $null
        PathName = $null
    }
}

$agentProcesses = @(Get-CimInstance -ClassName Win32_Process -Filter "Name='WindowsAppProtector.WindowAgent.exe'" -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
        ProcessId = $_.ProcessId
        SessionId = $_.SessionId
        ExecutablePath = $_.ExecutablePath
        CreationDate = $_.CreationDate
    }
})

$setupFile = Get-Item -LiteralPath $resolvedSetupExePath
$setupHash = Get-FileHash -LiteralPath $resolvedSetupExePath -Algorithm SHA256
$ifeoEvidence = Get-IfeoEvidence -RequestedExecutableNames $ProtectedExecutableNames
$scheduledTaskEvidence = Get-ScheduledTaskEvidence

$evidence = [ordered]@{
    EvidenceVersion = 1
    CollectedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
    ComputerName = $env:COMPUTERNAME
    OperatingSystem = [ordered]@{
        Caption = $operatingSystem.Caption
        Version = $operatingSystem.Version
        BuildNumber = $operatingSystem.BuildNumber
        Ubr = $currentVersionRegistry.UBR
        OsArchitecture = $operatingSystem.OSArchitecture
    }
    InstalledProduct = $installedProduct
    Service = $serviceEvidence
    ScheduledTask = $scheduledTaskEvidence
    IfeoRules = $ifeoEvidence
    WindowAgents = $agentProcesses
    SetupPackage = [ordered]@{
        Path = $setupFile.FullName
        Length = $setupFile.Length
        LastWriteTimeUtc = $setupFile.LastWriteTimeUtc.ToString("o")
        Sha256 = $setupHash.Hash
    }
}

$jsonReportPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "evidence.json"
$markdownReportPath = Join-Path -Path $resolvedOutputDirectory -ChildPath "report.md"
$evidence | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $jsonReportPath -Encoding UTF8

$markdownLines = [System.Collections.Generic.List[string]]::new()
$markdownLines.Add("# App PIN Guard VM 검증 증거")
$markdownLines.Add("")
$markdownLines.Add("- 수집 시각(UTC): $(ConvertTo-MarkdownText $evidence.CollectedAtUtc)")
$markdownLines.Add("- 컴퓨터: $(ConvertTo-MarkdownText $evidence.ComputerName)")
$markdownLines.Add("- OS: $(ConvertTo-MarkdownText $operatingSystem.Caption) $($operatingSystem.Version), 빌드 $($operatingSystem.BuildNumber).$($currentVersionRegistry.UBR)")
$markdownLines.Add("- 설치 제품: $(ConvertTo-MarkdownText $installedProduct.DisplayName) $(ConvertTo-MarkdownText $installedProduct.DisplayVersion)")
$markdownLines.Add("- 서비스: 존재=$($serviceEvidence.Exists), 상태=$(ConvertTo-MarkdownText $serviceEvidence.State), 시작 유형=$(ConvertTo-MarkdownText $serviceEvidence.StartMode)")
$markdownLines.Add("- 예약 작업: 존재=$($scheduledTaskEvidence.Exists), 상태=$(ConvertTo-MarkdownText $scheduledTaskEvidence.State)")
$markdownLines.Add(('- Setup.exe SHA-256: `{0}`' -f $setupHash.Hash))
$markdownLines.Add("")
$markdownLines.Add("## IFEO 규칙")
$markdownLines.Add("")
foreach ($ifeoRule in $ifeoEvidence) {
    $markdownLines.Add("- $(ConvertTo-MarkdownText $ifeoRule.ExecutableName): 존재=$($ifeoRule.Exists), 관리됨=$($ifeoRule.Managed), Debugger=$(ConvertTo-MarkdownText $ifeoRule.Debugger), UseFilter=$(ConvertTo-MarkdownText $ifeoRule.UseFilter)")
    foreach ($filterRule in @($ifeoRule.Filters)) {
        $markdownLines.Add("  - $(ConvertTo-MarkdownText $filterRule.Name): 경로=$(ConvertTo-MarkdownText $filterRule.FilterFullPath), Debugger=$(ConvertTo-MarkdownText $filterRule.Debugger)")
    }
}
$markdownLines.Add("")
$markdownLines.Add("## 세션 에이전트")
$markdownLines.Add("")
if ($agentProcesses.Count -eq 0) {
    $markdownLines.Add("- 실행 중인 에이전트 없음")
}
else {
    foreach ($agentProcess in $agentProcesses) {
        $markdownLines.Add("- PID $($agentProcess.ProcessId), 세션 $($agentProcess.SessionId), 경로 $(ConvertTo-MarkdownText $agentProcess.ExecutablePath)")
    }
}

$markdownLines | Set-Content -LiteralPath $markdownReportPath -Encoding UTF8
Write-Host "JSON 증거: $jsonReportPath"
Write-Host "Markdown 보고서: $markdownReportPath"
