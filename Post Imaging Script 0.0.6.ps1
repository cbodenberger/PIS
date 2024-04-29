Start-Process Powershell -ArgumentList $PSCommandPath -Verb RunAs
Requires -RunAsAdministrator
ECHO "This is a script to install .NET 3.5, DocManager, run configuration manager actions, scheduled tasks, apply group policy updates, and run windows updates"
#-----CHANGES-----
#"V1 - Removed Office 2013 manual install"
#"V2 - Removed the 1809 feature lock"
#"V3 - Remove the forced reboot"
#"V4 - Removed the go fast and Sonic ASCII"
#"0.0.5 - Renamed from "Chris' Go Fast Script V4" To a more proper name""
#"0.0.6 - Added CmRcService set starttype to auto"
Start-Sleep 5
#Author:
#Chris Bodenberger 
#Service Delivery Technician Level 2
#Town Pump Inc
ECHO --------------------
ECHO "Execute Scheduled Tasks"
Start-Sleep 1
WMIC /NAMESPACE:\\root\ccm\dcm path SMS_DesiredConfiguration CALL EvaluatePassportCertProfiles /NOINTERACTIVE
Start-Process -FilePath c:\windows\ccm\ccmeval.exe
ECHO --------------------
ECHO "Execute Configuration Manager Actions"
Start-Sleep 5
ECHO --------------------
ECHO "Application Deployment Evaluation Cycle"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000121}"
ECHO --------------------
ECHO "Discovery Data Collection Cycle"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000003}"
ECHO --------------------
ECHO "File Collection Cycle"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000010}"
ECHO --------------------
ECHO "Hardware Inventory Cycle"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000001}"
ECHO --------------------
ECHO "Machine Policy Retrieval Cycle"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000021}" 
ECHO --------------------
ECHO "Machine Policy Evaluation Cycle"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000022}"
ECHO --------------------
ECHO "Software Inventory Cycle"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000002}"
ECHO --------------------
ECHO "Software Metering Usage Report Cycle"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000031}"
ECHO --------------------
ECHO "Software Update Deployment Evaluation Cycle"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000114}"
ECHO --------------------
ECHO "Software Update Scan Cycle"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000113}"
ECHO --------------------
ECHO "State Message Refresh"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000111}"
ECHO --------------------
ECHO "Windows Installers Source List Update Cycle"
Start-Sleep 1
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000032}"
ECHO --------------------
ECHO "Setting CmRcService to start automatically"
Stop-Service CmRcService
Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\CmRcService" -Name "DelayedAutostart" -Value 0 -Type DWORD
Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\CmRcService" -Name "Start" -Value 2 -Type DWORD
set-service CmRcService -startuptype 'Automatic'
sc.exe config CmRcService start= auto
Start-Sleep 5
Start-Service CmRcService
Get-Service CmRcService | Select-Object -Property Name, StartType, Status
ECHO --------------------
ECHO "Cleaning up Image prior to updating"
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
ECHO --------------------
ECHO "ReTrimming Volume prior to updating"
Optimize-Volume -DriveLetter C: -ReTrim -Verbose
ECHO --------------------
ECHO "Cleaning disk prior to update"
cleanmgr.exe /AUTOCLEAN
cleanmgr /verylowdisk
ECHO --------------------
ECHO "Updating the Group Policy"
gpupdate /force
ECHO --------------------
ECHO "Executing Windows Updates"
wuauclt /detectnow /updatenow
ECHO --------------------
ECHO ".NET 3.5 Mapping"
Start-Sleep 1
net use E: \\tpsccm03\packages$\OSUpgrades\Windows10X64\Windows10Upgrade21H1
ECHO --------------------
ECHO ".NET 3.5 Installation"
DISM /Online /Enable-Feature /FeatureName:NetFX3 /All /Source:E:\Sources\sxs /LimitAccess
Start-Sleep 1
ECHO --------------------
ECHO "Execute DocManager Installer"
Start-Sleep 1
#Start-Process -FilePath "\\tpsccm03\sources$\TPApps\DocManager 3.4.1\DocManager_3_4_1_Setup.exe"
ECHO --------------------
Pause
#-----REMOVED ITEMS-----
#DISM /Online /Enable-Feature /FeatureName:NetFX3 /All /Source:E:\Sources\sxs /LimitAccess
#ECHO --------------------
#ECHO "Office 2013 Installation"
#Start-Sleep 1
#Start-Process -FilePath "\\tpsccm03\sources$\Microsoft\Office\2013 Standard\setup.exe" /adminfile townpump.msp
#ECHO  --------------------
#ECHO "Locking Windows 10 Feature updates to 1809"
#reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersion /t REG_DWORD /d 1
#reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate /f /v TargetReleaseVersionInfo /t REG_SZ /d 1903
#ECHO  --------------------
#ECHO "Computer will now reboot"
#Restart-Computer -force