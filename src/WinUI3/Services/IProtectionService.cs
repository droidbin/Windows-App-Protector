using WindowsAppProtector.Models;

namespace WindowsAppProtector.Services;

public interface IProtectionService
{
    Task RequestPolicyResyncAsync(CancellationToken cancellationToken = default);
    Task StopProtectedProcessesAsync(IEnumerable<ProtectedApp> apps, CancellationToken cancellationToken = default);
}
