WMIC /NAMESPACE:\\root\ccm\dcm path SMS_DesiredConfiguration CALL EvaluatePassportCertProfiles /NOINTERACTIVE
Start-Process -FilePath c:\windows\ccm\ccmeval.exe
Set-NetFirewallProfile -Profile Domain, Public, Private -Enabled False
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000121}"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000003}"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000010}"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000001}"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000021}"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000022}"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000002}"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000031}"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000114}"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000113}"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000111}"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000032}"
Enable-PSRemoting -Force
New-Item "C:\TEMP" -itemType Directory
powercfg /batteryreport /output "C:\TEMP\battery-report.html"
Invoke-expression C:\TEMP\battery-report.html
New-Item "C:\TEMP\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -itemType Directory
powercfg.exe /hibernate off
powercfg.exe /change monitor-timeout-ac 0
powercfg.exe /change standby-timeout-ac 0
powercfg.exe /change disk-timeout-ac 0
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
Optimize-Volume -DriveLetter C -ReTrim -Verbose
cleanmgr.exe /AUTOCLEAN
cleanmgr.exe /verylowdisk
gpupdate /force
wuauclt /detectnow /updatenow
Stop-Service CmRcService
Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\CmRcService" -Name "DelayedAutostart" -Value 0 -Type DWORD
Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\CmRcService" -Name "Start" -Value 2 -Type DWORD
set-service CmRcService -startuptype 'Automatic'
sc.exe config CmRcService start= auto
Start-Service CmRcService
Get-Service CmRcService | Select-Object -Property Name, StartType, Status
Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "Permission Required" -Value 0 -Type DWORD
Get-NetFirewallProfile | Format-Table Name, Enabled