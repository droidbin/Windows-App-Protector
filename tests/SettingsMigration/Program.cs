using System.Text.Json;
using WindowsAppProtector.Models;
using WindowsAppProtector.Services;

var root = Directory.CreateDirectory(Path.Combine(AppContext.BaseDirectory, $"wap-settings-migration-{Guid.NewGuid():N}"));
try
{
    var shared = Path.Combine(root.FullName, "config.json");
    var legacy = Path.Combine(root.FullName, "legacy.json");
    var backup = Path.Combine(root.FullName, "pin.json");
    var store = new JsonSettingsStore(shared, legacy, backup);
    var pin = PinHasher.CreateHash("legacy-pin");
    var replacement = PinHasher.CreateHash("different-pin");
    await WriteAsync(shared, new AppConfig());
    await WriteAsync(legacy, new AppConfig
    {
        EnableLaunchGate = true,
        IdleLockMinutes = 21,
        ProtectedApps = [new ProtectedApp { Name = "Fixture", Path = @"C:\Fixture\App.exe" }],
    });
    await WriteAsync(backup, new { pin.Salt, pin.Hash });
    var migrated = await store.LoadAsync();
    Check(migrated.StorageVersion == 2 && migrated.EnableLaunchGate && migrated.IdleLockMinutes == 21 &&
        migrated.AppPinHash == pin.Hash && migrated.ProtectedApps.Count == 1, "Legacy policy and PIN backup migration");

    // A profile can still contain 1.x files, but edits to them cannot supply a PIN or policy after migration.
    await WriteAsync(legacy, new AppConfig { AppPinSalt = replacement.Salt, AppPinHash = replacement.Hash });
    await WriteAsync(backup, new { replacement.Salt, replacement.Hash });
    Check((await store.LoadAsync()).AppPinHash == pin.Hash, "Legacy files are ignored after migration");
    var userBefore = await File.ReadAllTextAsync(legacy);
    var backupBefore = await File.ReadAllTextAsync(backup);

    var saves = Enumerable.Range(1, 20).Select(value =>
    {
        migrated.IdleLockMinutes = value;
        return store.SaveAsync(migrated);
    }).ToArray();
    await Task.WhenAll(saves);
    Check((await store.LoadAsync()).IdleLockMinutes == 20, "Concurrent settings snapshots are saved in order");
    Check(await File.ReadAllTextAsync(legacy) == userBefore && await File.ReadAllTextAsync(backup) == backupBefore,
        "Policy saves write only to the shared store");
    Check(!Directory.EnumerateFiles(root.FullName, "*.tmp").Any(), "No temporary settings files remain");

    await WriteAsync(shared, new AppConfig { AppPinSalt = pin.Salt, AppPinHash = pin.Hash, IdleLockMinutes = 34 });
    var protectedLegacy = await store.LoadAsync();
    Check(protectedLegacy.AppPinHash == pin.Hash && protectedLegacy.IdleLockMinutes == 34,
        "Existing shared policy takes precedence during upgrade");

    await WriteAsync(shared, new AppConfig { StorageVersion = 2, AppPinHash = "invalid" });
    await ExpectAsync<InvalidDataException>(() => store.LoadAsync());
    await ExpectAsync<InvalidDataException>(() => store.SaveAsync(migrated));
    File.Delete(shared);
    await ExpectAsync<FileNotFoundException>(() => store.LoadAsync());
    Console.WriteLine("PASS: first migration, shared priority, tamper isolation, concurrent saves, and fail-closed loading.");
}
finally
{
    root.Delete(recursive: true);
}

static Task WriteAsync<T>(string path, T value) => File.WriteAllTextAsync(path, JsonSerializer.Serialize(value));

static void Check(bool check, string scenario)
{
    if (!check) throw new InvalidOperationException(scenario);
}

static async Task ExpectAsync<T>(Func<Task> action) where T : Exception
{
    try { await action(); }
    catch (T) { return; }
    throw new InvalidOperationException($"Expected {typeof(T).Name}.");
}
