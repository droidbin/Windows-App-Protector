# Process close integration test

Run on a Windows desktop session. The test opens disposable WinForms windows and does not read or change WAP settings, PINs, service state, or IFEO rules.

```powershell
dotnet publish tests/ProcessCloseIntegration/ProcessCloseIntegration.csproj -c Release -r win-x64 --self-contained true -o build/process-close-integration
./build/process-close-integration/ProcessCloseIntegration.exe build/process-close-result.json
```

The test compiles the production process-close service and model directly. It checks an empty list, packaged-app exclusion, full-path matching, a currently disabled Win32 target, multiple processes, graceful exit, the five-second grace period, and a refusing process remaining alive. Cleanup terminates only fixture children created by the test.

This does not verify the WAP UI, administrator malware resistance, real unsaved documents, different privilege levels, or clean-machine installation.
