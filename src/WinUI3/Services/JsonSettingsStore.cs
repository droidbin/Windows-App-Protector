using System.Text.Json;
using WindowsAppProtector.Models;

namespace WindowsAppProtector.Services;

public sealed class JsonSettingsStore : ISettingsStore
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    private readonly string userConfigPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "WindowsAppProtector.WinUI",
        "config.json");
    private readonly string sharedConfigPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "Windows App Protector",
        "config.json");
    private readonly string pinBackupPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "WindowsAppProtector.WinUI",
        "pin.json");

    public async Task<AppConfig> LoadAsync(CancellationToken cancellationToken = default)
    {
        AppConfig config;
        if (File.Exists(userConfigPath))
        {
            await using var stream = File.OpenRead(userConfigPath);
            config = await JsonSerializer.DeserializeAsync<AppConfig>(stream, JsonOptions, cancellationToken)
                ?? new AppConfig();
        }
        else
        {
            config = await LoadSharedConfigAsync(cancellationToken) ?? new AppConfig();
        }

        var pin = await LoadPinBackupAsync(cancellationToken);
        if (pin is not null)
        {
            config.AppPinSalt = pin.Salt;
            config.AppPinHash = pin.Hash;
        }

        return config;
    }

    public async Task SaveAsync(AppConfig config, CancellationToken cancellationToken = default)
    {
        await SaveToPathAsync(userConfigPath, config, cancellationToken);

        if (!string.IsNullOrWhiteSpace(config.AppPinSalt) && !string.IsNullOrWhiteSpace(config.AppPinHash))
        {
            await SavePinBackupAsync(config.AppPinSalt, config.AppPinHash, cancellationToken);
        }

        try
        {
            await SaveToPathAsync(sharedConfigPath, config, cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
        }
        catch (IOException)
        {
        }
    }

    private async Task<AppConfig?> LoadSharedConfigAsync(CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(sharedConfigPath))
            {
                return null;
            }

            await using var stream = File.OpenRead(sharedConfigPath);
            return await JsonSerializer.DeserializeAsync<AppConfig>(stream, JsonOptions, cancellationToken);
        }
        catch (UnauthorizedAccessException)
        {
            return null;
        }
    }

    private async Task<PinBackup?> LoadPinBackupAsync(CancellationToken cancellationToken)
    {
        if (!File.Exists(pinBackupPath))
        {
            return null;
        }

        await using var stream = File.OpenRead(pinBackupPath);
        return await JsonSerializer.DeserializeAsync<PinBackup>(stream, JsonOptions, cancellationToken);
    }

    private Task SavePinBackupAsync(string salt, string hash, CancellationToken cancellationToken)
    {
        return SaveToPathAsync(pinBackupPath, new PinBackup(salt, hash), cancellationToken);
    }

    private static async Task SaveToPathAsync(string path, AppConfig config, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tempPath = path + ".tmp";
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                await using (var stream = File.Create(tempPath))
                {
                    await JsonSerializer.SerializeAsync(stream, config, JsonOptions, cancellationToken);
                }

                if (File.Exists(path))
                {
                    File.Replace(tempPath, path, null);
                }
                else
                {
                    File.Move(tempPath, path);
                }
                return;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (File.Exists(tempPath))
                {
                    try { File.Delete(tempPath); } catch { }
                }

                try
                {
                    await using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.ReadWrite);
                    await JsonSerializer.SerializeAsync(stream, config, JsonOptions, cancellationToken);
                    return;
                }
                catch when (attempt < 2)
                {
                    await Task.Delay(50, cancellationToken);
                }
            }
        }
    }

    private static async Task SaveToPathAsync(string path, PinBackup pin, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var tempPath = path + ".tmp";
        await using (var stream = File.Create(tempPath))
        {
            await JsonSerializer.SerializeAsync(stream, pin, JsonOptions, cancellationToken);
        }

        if (File.Exists(path))
        {
            File.Replace(tempPath, path, null);
        }
        else
        {
            File.Move(tempPath, path);
        }
    }

    private sealed record PinBackup(string Salt, string Hash);
}
