@echo off
setlocal

net session >nul 2>&1
if errorlevel 1 (
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

sc stop WindowsAppProtectorService >nul 2>&1
sc delete WindowsAppProtectorService >nul 2>&1
taskkill /IM WindowsAppProtector.WinUI.exe /F >nul 2>&1
taskkill /IM WindowsAppProtector.Service.exe /F >nul 2>&1
schtasks /Delete /TN "Windows App Protector" /F >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Windows App Protector" /f >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command "$root='HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'; Get-ChildItem -LiteralPath $root | ForEach-Object { $key=$_; if ($key.GetValue('WindowsAppProtectorManaged') -eq '1') { Get-ChildItem -LiteralPath $key.PSPath | Where-Object { $_.PSChildName -like 'WAP.Launch.*' -and $_.GetValue('WindowsAppProtectorManaged') -eq '1' -and $_.SubKeyCount -eq 0 } | Remove-Item -Force; foreach ($name in 'Debugger','WindowsAppProtectorManaged') { Remove-ItemProperty -LiteralPath $key.PSPath -Name $name -ErrorAction SilentlyContinue }; if ($key.SubKeyCount -eq 0) { Remove-ItemProperty -LiteralPath $key.PSPath -Name UseFilter -ErrorAction SilentlyContinue; if ($key.ValueCount -eq 0) { Remove-Item -LiteralPath $key.PSPath -Force } } } }"

rmdir /s /q "%ProgramData%\Windows App Protector" >nul 2>&1
rmdir /s /q "%AppData%\WindowsAppProtector.WinUI" >nul 2>&1
rmdir /s /q "%AppData%\WindowsAppProtector" >nul 2>&1
del "%PUBLIC%\Desktop\Windows App Protector.lnk" >nul 2>&1
del "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Windows App Protector.lnk" >nul 2>&1
del "%ProgramData%\Microsoft\Windows\Start Menu\Programs\Windows App Protector Uninstall.lnk" >nul 2>&1
del "%PUBLIC%\Desktop\App PIN Guard.lnk" >nul 2>&1
del "%ProgramData%\Microsoft\Windows\Start Menu\Programs\App PIN Guard.lnk" >nul 2>&1
del "%ProgramData%\Microsoft\Windows\Start Menu\Programs\App PIN Guard Uninstall.lnk" >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\WindowsAppProtector" /f >nul 2>&1

cd /d "%ProgramFiles%"
rmdir /s /q "Windows App Protector" >nul 2>&1

echo App PIN Guard has been removed.
pause
