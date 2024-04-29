<# Main Function
$Pathtoreadme = "D:\readme.txt
Start-Process Powershell -ArgumentList $PSCommandPath -Verb RunAs
Requires -RunAsAdministrator
WMIC /NAMESPACE:\\root\ccm\dcm path SMS_DesiredConfiguration CALL EvaluatePassportCertProfiles /NOINTERACTIVE
Start-Process -FilePath c:\windows\ccm\ccmeval.exe
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000121}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000003}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000010}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000001}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000021}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000022}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000002}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000031}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000114}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000113}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000111}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000032}"
Clear-Host
New-Item "C:\TEMP" -itemType Directory
powercfg /batteryreport /output "C:\TEMP\battery-report.html"
Invoke-expression C:\TEMP\battery-report.html
New-Item "C:\TEMP\GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}" -itemType Directory
Dism.exe /online /Cleanup-Image /StartComponentCleanup /ResetBase
Optimize-Volume -DriveLetter C: -ReTrim -Verbose
cleanmgr.exe /AUTOCLEAN
cleanmgr /verylowdisk
gpupdate /force
wuauclt /detectnow /updatenow
net use E: \\tpsccm03\packages$\OSUpgrades\Windows10X64\Windows10Upgrade21H1
DISM /Online /Enable-Feature /FeatureName:NetFX3 /All /Source:E:\Sources\sxs /LimitAccess
Start-Process -FilePath "\\tpsccm03\sources$\TPApps\DocManager 3.4.1\DocManager_3_4_1_Setup.exe"
Clear-Host
$S = New-PSSession -Computername corplt247
Enter-PSSession $s
CD BTM:
$ResourceID = (Get-CMDevice -Name $MemberName).ResourceID
    If ($ResourceID) {
        	Write-Host "Adobe Reader DC"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM001BA" -ResourceId $ResourceID
		Write-Host "Enable PSRemoting"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM00288" -ResourceId $ResourceID
		Write-Host "Google Chrome"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM00254" -ResourceId $ResourceID
    }
Exit-Session
Clear-Host
$Office = New-Object System.Management.Automation.Host.ChoiceDescription "&Office","Description."
$Field = New-Object System.Management.Automation.Host.ChoiceDescription "&Field","Description."
$Special = New-Object System.Management.Automation.Host.ChoiceDescription "&Special","Description."
$Cancel = New-Object System.Management.Automation.Host.ChoiceDescription "&Cancel","Description."
$options = [System.Management.Automation.Host.ChoiceDescription[]]($Office, $Field, $Special, $Cancel)
$heading = "Computer Type"
$mess = "Please define the type of computer you're setting up"
$rslt = $host.ui.PromptForChoice($heading, $mess, $options, 1)
if ($rslt -eq 'Cancel'){Return}
if ($rslt -eq 'Office'){
Enter-PSSession $s
CD BTM:
$ResourceID = (Get-CMDevice -Name $MemberName).ResourceID
    If ($ResourceID) {
        Write-Host "Office 365"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM002EF" -ResourceId $ResourceID
    }
Exit-Session
Clear-Host
if ($rslt -eq 'Field'){
Enter-PSSession $s
CD BTM:
$ResourceID = (Get-CMDevice -Name $MemberName).ResourceID
    If ($ResourceID) {
		Write-Host "PDI Enterprise"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM002CF" -ResourceId $ResourceID
		Write-Host "PDI Timeclock"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM002A7" -ResourceId $ResourceID
		Write-Host "SaleGuard"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM002E1" -ResourceId $ResourceID
		Write-Host "Radius"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM0001F" -ResourceId $ResourceID
		Write-Host "OWS"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM002F8" -ResourceId $ResourceID
    }
if ($rslt -eq 'Special'){Return}
Exit-Session
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000121}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000002}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000031}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000114}"
Clear-Host
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000113}"
Clear-Host
Stop-Service CmRcService
Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\CmRcService" -Name "DelayedAutostart" -Value 0 -Type DWORD
Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\CmRcService" -Name "Start" -Value 2 -Type DWORD
set-service CmRcService -startuptype 'Automatic'
sc.exe config CmRcService start= auto
Start-Service CmRcService
Get-Service CmRcService | Select-Object -Property Name, StartType, Status
Pause
Set-ItemProperty -Path "Registry::HKLM\SOFTWARE\Microsoft\SMS\Client\Client Components\Remote Control" -Name "Permission Required" -Value 0 -Type DWORD
#Restart-Computer -force
#>