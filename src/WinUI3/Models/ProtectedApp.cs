namespace WindowsAppProtector.Models;

public sealed class ProtectedApp
{
    public string Name { get; set; } = string.Empty;
    public string Path { get; set; } = string.Empty;
    public bool IsPackaged { get; set; }
    public string PackageFamilyName { get; set; } = string.Empty;
    public string AppUserModelId { get; set; } = string.Empty;
    public string ExecutableName { get; set; } = string.Empty;
    public bool Enabled { get; set; } = true;
    public string LaunchPinSalt { get; set; } = string.Empty;
    public string LaunchPinHash { get; set; } = string.Empty;
    public int LaunchAllowedMinutes { get; set; }
    public int? LaunchLockStartMinute { get; set; }
    public int? LaunchLockEndMinute { get; set; }
    public bool LaunchRelockOnExit { get; set; }
}
