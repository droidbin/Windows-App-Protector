using System.Text.Json;
using WindowsAppProtector.Models;

namespace WindowsAppProtector.Services;

public sealed class JsonSettingsStore : ISettingsStore
{
    internal const int CurrentStorageVersion = 2;
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private static readonly SemaphoreSlim SaveGate = new(1, 1);
    private readonly string userConfigPath;
    private readonly string sharedConfigPath;
    private readonly string pinBackupPath;

    public JsonSettingsStore() : this(
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Windows App Protector", "config.json"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "WindowsAppProtector.WinUI", "config.json"),
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "WindowsAppProtector.WinUI", "pin.json"))
    {
    }

    internal JsonSettingsStore(string sharedConfigPath, string userConfigPath, string pinBackupPath)
    {
        this.sharedConfigPath = sharedConfigPath;
        this.userConfigPath = userConfigPath;
        this.pinBackupPath = pinBackupPath;
    }

    public async Task<AppConfig> LoadAsync(CancellationToken cancellationToken = default)
    {
        await using var lease = await AcquireWriteLeaseAsync(cancellationToken);
        var shared = await ReadRequiredAsync<AppConfig>(sharedConfigPath, cancellationToken);
        Validate(shared);

        if (shared.StorageVersion == CurrentStorageVersion)
        {
            RequirePinForSavedPolicy(shared);
            return shared;
        }
        if (shared.StorageVersion != 0)
        {
            throw new InvalidDataException("이 버전에서 지원하지 않는 보호 설정 형식입니다.");
        }

        // Prefer the policy the installed service already trusted. A legacy profile
        // may supply a policy only when the shared file has no prior PIN or app list.
        var config = HasPin(shared) || shared.ProtectedApps.Count != 0 || shared.ProtectionEnabled || shared.EnableLaunchGate
            ? shared
            : await ReadOptionalAsync<AppConfig>(userConfigPath, cancellationToken) ?? shared;
        if (config == shared && !HasPin(config) && (config.ProtectedApps.Count != 0 || config.ProtectionEnabled || config.EnableLaunchGate))
        {
            throw new InvalidDataException("공유 보호 정책에 PIN 정보가 없습니다.");
        }
        if (!HasPin(config))
        {
            var backup = await ReadOptionalAsync<PinBackup>(pinBackupPath, cancellationToken);
            if (backup is not null)
            {
                config.AppPinSalt = backup.Salt;
                config.AppPinHash = backup.Hash;
            }
        }

        Validate(config);
        RequirePinForSavedPolicy(config);
        config.StorageVersion = CurrentStorageVersion;
        await ReplaceSharedAsync(JsonSerializer.SerializeToUtf8Bytes(config, JsonOptions), cancellationToken);
        return config;
    }

    public async Task SaveAsync(AppConfig config, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        Validate(config);
        RequirePinForSavedPolicy(config);
        config.StorageVersion = CurrentStorageVersion;
        var contents = JsonSerializer.SerializeToUtf8Bytes(config, JsonOptions);

        await SaveGate.WaitAsync(cancellationToken);
        try
        {
            await using var lease = await AcquireWriteLeaseAsync(cancellationToken);
            var stored = await ReadRequiredAsync<AppConfig>(sharedConfigPath, cancellationToken);
            Validate(stored);
            RequirePinForSavedPolicy(stored);
            if (stored.StorageVersion != CurrentStorageVersion)
            {
                throw new InvalidDataException("보호 설정을 저장하기 전에 다시 불러오세요.");
            }
            await ReplaceSharedAsync(contents, cancellationToken);
        }
        finally
        {
            SaveGate.Release();
        }
    }

    private async Task<FileStream> AcquireWriteLeaseAsync(CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(sharedConfigPath)!;
        if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("보호 설정 폴더가 재분석 지점입니다.");
        }
        var leasePath = Path.Combine(directory, "settings-write.lock");
        for (var attempt = 0; ; attempt++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(leasePath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException ex) when ((ex.HResult & 0xFFFF) is 32 or 33 && attempt < 100)
            {
                await Task.Delay(50, cancellationToken);
            }
        }
    }

    private static async Task<T> ReadRequiredAsync<T>(string path, CancellationToken cancellationToken)
        where T : class
    {
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new IOException("보호 설정 파일이 재분석 지점입니다.");
        }
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        return await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, cancellationToken)
            ?? throw new InvalidDataException("보호 설정 파일이 비어 있습니다.");
    }

    private static async Task<T?> ReadOptionalAsync<T>(string path, CancellationToken cancellationToken)
        where T : class
    {
        try
        {
            return await ReadRequiredAsync<T>(path, cancellationToken);
        }
        catch (FileNotFoundException) { return null; }
        catch (DirectoryNotFoundException) { return null; }
    }

    private static bool HasPin(AppConfig config) => !string.IsNullOrEmpty(config.AppPinHash);

    private static void Validate(AppConfig config)
    {
        if (config.ProtectedApps is null || config.GlobalHotkeys is null ||
            !IsValidPinPair(config.AppPinSalt, config.AppPinHash) ||
            config.ProtectedApps.Any(app => app is null || !IsValidPinPair(app.LaunchPinSalt, app.LaunchPinHash)))
        {
            throw new InvalidDataException("보호 설정 또는 PIN 해시 형식이 올바르지 않습니다.");
        }
    }

    private static void RequirePinForSavedPolicy(AppConfig config)
    {
        if (!HasPin(config) && (config.ProtectedApps.Count != 0 || config.ProtectionEnabled || config.EnableLaunchGate))
        {
            throw new InvalidDataException("저장된 보호 정책에 관리 PIN이 없습니다.");
        }
    }

    private static bool IsValidPinPair(string? salt, string? hash)
    {
        if (salt == string.Empty && hash == string.Empty) return true;
        if (salt is null || hash is null) return false;
        Span<byte> decodedSalt = stackalloc byte[16];
        Span<byte> decodedHash = stackalloc byte[32];
        return Convert.TryFromBase64String(salt, decodedSalt, out var saltLength) && saltLength == decodedSalt.Length &&
            Convert.TryFromBase64String(hash, decodedHash, out var hashLength) && hashLength == decodedHash.Length;
    }

    private async Task ReplaceSharedAsync(byte[] contents, CancellationToken cancellationToken)
    {
        var temporary = $"{sharedConfigPath}.{Guid.NewGuid():N}.tmp";
        try
        {
            await File.WriteAllBytesAsync(temporary, contents, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            File.Replace(temporary, sharedConfigPath, null);
        }
        finally
        {
            try { File.Delete(temporary); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private sealed record PinBackup(string Salt, string Hash);
}
