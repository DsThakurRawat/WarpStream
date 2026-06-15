# install.ps1
param (
    [string]$ConfigPath = "C:\ProgramData\warpstream\client.yaml",
    [string]$BinaryPath = "C:\Program Files\warpstream\warpstream.exe"
)

$Action = New-ScheduledTaskAction -Execute $BinaryPath -Argument "client --config `"$ConfigPath`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

Register-ScheduledTask -TaskName "warpstream-client" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force
Write-Host "warpstream-client task registered successfully."
