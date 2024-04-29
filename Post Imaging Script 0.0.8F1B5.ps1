﻿<# Main Function
Start-Process Powershell -ArgumentList $PSCommandPath -Verb RunAs
Requires -RunAsAdministrator
WMIC /NAMESPACE:\\root\ccm\dcm path SMS_DesiredConfiguration CALL EvaluatePassportCertProfiles /NOINTERACTIVE
Start-Process -FilePath c:\windows\ccm\ccmeval.exe
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
$SccmServer = "tpsccm03.tpi.townpump.com"
$PathToSCCMModule = "D:\ConfigurationManager.psd1"
 
&nbsp;$MemberName = $env:COMPUTERNAME
$SCCMSession = New-PSSession -ComputerName $SccmServer
Invoke-Command -Session $SccmSession -ArgumentList @($PathToSCCMModule, $MemberName) -ScriptBlock {
    Param (
        [string]$PathToSCCMModule,
        [string]$MemberName
    )
    Import-Module $PathToSCCMModule -ErrorAction SilentlyContinue
    $SccmSite = (Get-PSDrive -PSProvider CMSite | Sort-Object -Property Name | Select-Object -First 1).Name
    Set-Location "$($SccmSite):"
 
&nbsp;    $ResourceID = (Get-CMDevice -Name $MemberName).ResourceID
    If ($ResourceID) {
        Write-Host "Adobe Reader DC"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM001BA" -ResourceId $ResourceID
		Write-Host "Enable PSRemoting"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM00288" -ResourceId $ResourceID
		Write-Host "Google Chrome"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM00254" -ResourceId $ResourceID
    }
}
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
$SccmServer = "tpsccm03.tpi.townpump.com"
$PathToSCCMModule = "D:\ConfigurationManager.psd1"
&nbsp;$MemberName = $env:COMPUTERNAME
$SCCMSession = New-PSSession -ComputerName $SccmServer
Invoke-Command -Session $SccmSession -ArgumentList @($PathToSCCMModule, $MemberName) -ScriptBlock {
    Param (
        [string]$PathToSCCMModule,
        [string]$MemberName
    )
    Import-Module $PathToSCCMModule -ErrorAction SilentlyContinue
    $SccmSite = (Get-PSDrive -PSProvider CMSite | Sort-Object -Property Name | Select-Object -First 1).Name
    Set-Location "$($SccmSite):"
 
&nbsp;    $ResourceID = (Get-CMDevice -Name $MemberName).ResourceID
    If ($ResourceID) {
        Write-Host "Office 365"
		Add-CMDeviceCollectionDirectMembershipRule -CollectionID "BTM002EF" -ResourceId $ResourceID
    }
}
}
if ($rslt -eq 'Field'){
$SccmServer = "tpsccm03.tpi.townpump.com"
$PathToSCCMModule = "D:\ConfigurationManager.psd1"
&nbsp;$MemberName = $env:COMPUTERNAME
$SCCMSession = New-PSSession -ComputerName $SccmServer
Invoke-Command -Session $SccmSession -ArgumentList @($PathToSCCMModule, $MemberName) -ScriptBlock {
    Param (
        [string]$PathToSCCMModule,
        [string]$MemberName
    )
    Import-Module $PathToSCCMModule -ErrorAction SilentlyContinue
    $SccmSite = (Get-PSDrive -PSProvider CMSite | Sort-Object -Property Name | Select-Object -First 1).Name
    Set-Location "$($SccmSite):"
 
&nbsp;    $ResourceID = (Get-CMDevice -Name $MemberName).ResourceID
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
}
}
if ($rslt -eq 'Special'){
$P = New-Object System.Management.Automation.Host.ChoiceDescription "&Adobe Pro","Description."
$S = New-Object System.Management.Automation.Host.ChoiceDescription "&Adobe Standard","Description."
$A = New-Object System.Management.Automation.Host.ChoiceDescription "&O365+Access","Description."
$V = New-Object System.Management.Automation.Host.ChoiceDescription "&O365+Visio","Description."
$M = New-Object System.Management.Automation.Host.ChoiceDescription "&Mitel UCA","Description."
$options2  = [System.Management.Automation.Host.ChoiceDescription[]]($P, $S, $A, $V, $M, $Cancel)
$heading2 = "Program Choices"
$mess2 = "Please select the programs you wish to install"
$progs = $host.ui.PromptForChoice($heading2, $mess2, $options2, 1)
switch ($progs) {
0{
Write-Host "Office" -ForegroundColor Green
}1{
Write-Host "Field" -ForegroundColor Green
}2{
Write-Host "Special" -ForegroundColor Green
}3{
Write-Host "Cancelling" -ForegroundColor Green
Start-Sleep 1
Return
}
}
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000121}" #"Application Deployment Evaluation Cycle"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000002}" #"Software Inventory Cycle"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000031}" #"Software Metering Usage Report Cycle"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000114}" #"Software Update Deployment Evaluation Cycle"
Invoke-WMIMethod -Namespace root\ccm -Class SMS_CLIENT -Name TriggerSchedule "{00000000-0000-0000-0000-000000000113}" #"Software Update Scan Cycle"
Stop-Service CmRcService
Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\CmRcService" -Name "DelayedAutostart" -Value 0 -Type DWORD
Set-ItemProperty -Path "Registry::HKLM\System\CurrentControlSet\Services\CmRcService" -Name "Start" -Value 2 -Type DWORD
set-service CmRcService -startuptype 'Automatic'
sc.exe config CmRcService start= auto
Start-Service CmRcService
Get-Service CmRcService | Select-Object -Property Name, StartType, Status
Pause
Restart-Computer -force
#>
Clear-Host
$i = 0
do 
{
    "(>'-')>", "^('-')^", "<('-'<)", "^('-')^" | 
    ForEach { 
        Clear-Host
        Write-Host "`r$PSItem" -NoNewline
        Start-Sleep -Milliseconds 250
    }
    $i++
} until ($i -eq 50) #>