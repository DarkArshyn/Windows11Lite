#################################################################
#                                                               #
#             Windows 11 Lite Image - DarkArshyn                #
#                    04/12/2023 - Version 01                    #
#                                                               #
#                 Last Revision : 28/04/2024                    #
#                                                               #
#################################################################

#Launch script into admin mode
param([switch]$Elevated)

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((Test-Admin) -eq $false)  {
    if ($elevated) {
        # tried to elevate, did not work, aborting
    } else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))

        If ((Get-ExecutionPolicy) -eq 'Restricted'){
        Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Confirm:$false
        }
    }
    exit
}

#Log function
Function Write-Log([String]$Value,[Switch]$Information,[Switch]$Success,[Switch]$Warning,[Switch]$Err,[Switch]$Debug){
    $Type = 'Information';$Color = 'White'
    $Time=(Get-Date).tostring('dd-MM HH-mm-ss')
    If($Information){$Type = 'Information';$Color='White'}
    If($Success){$Type = 'Success';$Color='Green'}
    ElseIf($Warning){$Type = 'Warning';$Color='Yellow'}
    ElseIf($Err){$Type = 'Error';$Color='Red'}
    ElseIf($Debug){$Type = 'Debug';$Color='Cyan'}
    $ValueLog="[$Time] [$Type] $Value"
    Add-Content -Path $Log_Path -Value $ValueLog
    Write-Host $Value -ForegroundColor $Color
}

#Log file write function
$Log_Folder = "C:\Log\" #Log access file -> Can be modified
$Log_Path = $Log_Folder+ $((Get-Date).tostring('dd-MM-yyyy_HH-mm-ss')) + '.log'

If (Test-Path $Log_Folder) {
    Write-Log "Log folder already exists" -Warning
}
Else{
    New-Item $Log_Folder -ItemType Directory
    Write-Log "Log folder successfully created" -Success
}

$ISOOriginal = Read-Host "Enter the drive letter where the original ISO is stored "

If (!(Test-Path -Path $ISOOriginal":\sources\boot.wim" -PathType Leaf)) {
    Write-Log "The boot.wim file cannot be found, please enter a valid drive number. Exiting $($_.Exception.Message)" -Err
    Pause
    Exit
}

If (!(Test-Path -Path $ISOOriginal":\sources\install.wim" -PathType Leaf)) {
    Write-Log "The install.wim file cannot be found, please enter a valid drive number. Exiting $($_.Exception.Message)" -Err
    Pause
    Exit
}

#Create a temporary copy directory
$Temp_Folder = "C:\win_temp\"

If (Test-Path $Temp_Folder) {
    Write-Log "The temporary folder already exists" -Warning
}
Else{
    New-Item $Temp_Folder -ItemType Directory
    Write-Log "The temporary folder has been correctly created" -Success  
}

#Creating a temporary mount directory
$Mount_Folder = "C:\win_mount\"

If (Test-Path $Mount_Folder) {
    Write-Log "The temporary folder already exists" -Warning
}
Else{
    New-Item $Mount_Folder -ItemType Directory
    Write-Log "The temporary folder has been correctly created" -Success
}

Copy-Item -Path "$($ISOOriginal):\*" -Destination $Temp_Folder -Recurse
Write-Log "File copy complete" -Success
Start-Sleep 2

#Disable read-only if enabled
$ROAttribute = $false
Get-ChildItem -Path $Temp_Folder -Recurse | ForEach-Object {
    Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $ROAttribute -ErrorAction SilentlyContinue
}

dism /Get-WimInfo /wimfile:"$($Temp_Folder)sources\install.wim"
$DISMIndex = Read-Host "Enter the desired index number "

Write-Log "Mounting image, please wait"
dism /mount-image /imagefile:"$($Temp_Folder)sources\install.wim" /index:$DISMIndex /mountdir:$Mount_Folder
Start-Sleep 2

#################################
#   Windows bloatware removal   #
#################################

Write-Log "Removing bloatware, please wait..."

$ExcludeApp = "Microsoft.AVCEncoderVideoExtension","Microsoft.DesktopAppInstaller","Microsoft.DolbyAudioExtensions","Microsoft.HEIFImageExtension","Microsoft.HEVCVideoExtension","Microsoft.MPEG2VideoExtension","Microsoft.Paint","Microsoft.RawImageExtension","Microsoft.ScreenSketch","Microsoft.SecHealthUI","Microsoft.StorePurchaseApp","Microsoft.VCLibs","Microsoft.VP9VideoExtensions","Microsoft.WebMediaExtensions","Microsoft.WebpImageExtension","Microsoft.WindowsCalculator","Microsoft.WindowsNotepad","Microsoft.WindowsStore","Microsoft.WindowsTerminal"

$GetAppExclude = Get-AppxProvisionedPackage -Path $Mount_Folder | Select DisplayName,PackageName | Where DisplayName -notin $ExcludeApp     #Pour exclure une appli

ForEach ($App in $GetAppExclude.PackageName){
    dism /Image:$Mount_Folder /Remove-ProvisionedAppxPackage /PackageName:$App
}

Write-Log "Bloatware removal complete" -Success

########################
#   OneDrive removal   #
########################

Write-Log "Removing OneDrive, please wait..."
Try {
    #Find local administrator
    $GetAdminSID = Get-LocalGroup -SID "S-1-5-32-544"
    $Admin = $GetAdminSID.Name

    #Assigning rights to the file and deleting it
    $ACL = Get-ACL $Mount_Folder\Windows\System32\OneDriveSetup.exe
    $Group = New-Object System.Security.Principal.NTAccount("BUILTIN", "$Admin")
    $ACL.SetOwner($Group)
    Set-Acl -Path $Mount_Folder\Windows\System32\OneDriveSetup.exe -AclObject $ACL
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\$Admin", "FullControl", "Allow")
    $ACL.SetAccessRule($AccessRule)
    $ACL | Set-Acl $Mount_Folder\Windows\System32\OneDriveSetup.exe
    Remove-Item $Mount_Folder\Windows\System32\OneDriveSetup.exe
    Start-Sleep 2

    Write-Log "OneDrive removal complete" -Success
}
Catch {

    Write-Log "OneDrive removal failed. An error has been detected $($_.Exception.Message)." -Err
}

###################
#   Edge Removal  #
###################

Write-Log "Removing Edge, please wait..."

Try { 
    #Edge folders removal
    Remove-Item -Path "$Mount_Folder\Program Files (x86)\Microsoft\Edge" -Recurse -Force
    Remove-Item -Path "$Mount_Folder\Program Files (x86)\Microsoft\EdgeUpdate" -Recurse -Force
    Remove-Item -Path "$Mount_Folder\Program Files (x86)\Microsoft\EdgeCore" -Recurse -Force

    #Find local administrator
    $GetAdminSID = Get-LocalGroup -SID "S-1-5-32-544"
    $Admin = $GetAdminSID.Name

    #Assigning rights to the folder and deleting it
    $WebviewLocation = Get-ChildItem -Path "$Mount_Folder\Windows\WinSxS" -Filter "amd64_microsoft-edge-webview_31bf3856ad364e35*" -Directory | Select-Object -ExpandProperty FullName
    $WebviewLocationRecurse = Get-ChildItem $WebviewLocation -Recurse | Select-Object -ExpandProperty FullName
    $ACL = Get-ACL $WebviewLocation
    $Group = New-Object System.Security.Principal.NTAccount("BUILTIN", "$Admin")
    $ACL.SetOwner($Group)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\$Admin", "FullControl", "Allow")
    $ACL.SetAccessRule($AccessRule)
    Set-Acl $WebviewLocation -AclObject $ACL
    ForEach ($Folder in $WebviewLocation)
        {Set-Acl -Path $WebviewLocationRecurse -AclObject $ACL}

    Remove-Item -Path $WebviewLocation -Recurse -Force
    Start-Sleep 2

    #Assigning rights to the folder and deleting it
    $WebviewSystem32 = $Mount_Folder+"Windows\System32\Microsoft-Edge-WebView"
    $WebviewSystem32Recurse = Get-ChildItem $WebviewSystem32 -Recurse | Select-Object -ExpandProperty FullName
    $ACL = Get-ACL $WebviewSystem32
    $Group = New-Object System.Security.Principal.NTAccount("BUILTIN", "$Admin")
    $ACL.SetOwner($Group)
    $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\$Admin", "FullControl", "Allow")
    $ACL.SetAccessRule($AccessRule)
    Set-Acl $WebviewSystem32 -AclObject $ACL
    ForEach ($Folder in $WebviewSystem32)
        {Set-Acl -Path $WebviewSystem32Recurse -AclObject $ACL}

    Remove-Item -Path $WebviewSystem32 -Recurse -Force
    Start-Sleep 2

    Write-Log "Edge removal complete" -Success
}
Catch {

    Write-Log "Edge removal failed. An error has been detected $($_.Exception.Message)." -Err
}

#############################################################################
#   Edit IntegratedServicesRegionPolicySet.json file (Digital Market Act)   #
#############################################################################

Write-Log "Editing IntegratedServicesRegionPolicySet.json file, please wait..."

#Find local administrator
$GetAdminSID = Get-LocalGroup -SID "S-1-5-32-544"
$Admin = $GetAdminSID.Name

#Assigning rights to file to edit it
$ACL = Get-ACL $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json
$Group = New-Object System.Security.Principal.NTAccount("BUILTIN", "$Admin")
$ACL.SetOwner($Group)
Set-Acl -Path $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json -AclObject $ACL
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("BUILTIN\$Admin", "FullControl", "Allow")
$ACL.SetAccessRule($AccessRule)
$ACL | Set-Acl $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json

#Can uninstall Edge
$DMAEdgeUninstall = Get-Content $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json
$DMAEdgeUninstall[7] = $DMAEdgeUninstall[7] -replace 'disabled','enabled'
Set-Content -Path $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json -Value $DMAEdgeUninstall

#Users can disable Web Search from the Start Menu
$DMAWebSearchDisable = Get-Content $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json
$DMAWebSearchDisable[17] = $DMAWebSearchDisable[17] -replace 'disabled','enabled'
Set-Content -Path $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json -Value $DMAWebSearchDisable

#Hide files from MS Office MRU recommendation provider
$DMAOfficeMRU = Get-Content $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json
$DMAOfficeMRU[157] = $DMAOfficeMRU[157] -replace 'enabled','disabled'
Set-Content -Path $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json -Value $DMAOfficeMRU

#Restrict widget data sharing
$DMAWidgetDataSharing = Get-Content $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json
$DMAWidgetDataSharing[207] = $DMAWidgetDataSharing[207] -replace 'disabled','enabled'
Set-Content -Path $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json -Value $DMAWidgetDataSharing

#Restrict data sharing with third-party widgets
$DMAThirdWidgetDataSharing = Get-Content $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json
$DMAThirdWidgetDataSharing[217] = $DMAThirdWidgetDataSharing[217] -replace 'disabled','enabled'
Set-Content -Path $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json -Value $DMAThirdWidgetDataSharing

#Disable XBox performance adaptation according to data sharing
$DMAXboxData = Get-Content $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json
$DMAXboxData[237] = $DMAXboxData[237] -replace 'enabled','disabled'
Set-Content -Path $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json -Value $DMAXboxData

#Disable Windows Copilot
$DMAWindowsCopilot = Get-Content $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json
$DMAWindowsCopilot[257] = $DMAWindowsCopilot[257] -replace 'enabled','disabled'
Set-Content -Path $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json -Value $DMAWindowsCopilot

#Hide website items in Start Menu recommendations
$DMAStartRecommendations = Get-Content $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json
$DMAStartRecommendations[297] = $DMAStartRecommendations[297] -replace 'enabled','disabled'
Set-Content -Path $Mount_Folder\Windows\System32\IntegratedServicesRegionPolicySet.json -Value $DMAStartRecommendations

Write-Log "IntegratedServicesRegionPolicySet.json file has been edited successfully" -Success

########################
#   Registry tweaking  #
########################

Write-Log "Tweaking registry, please wait..."

#Loading registry keys (System components)
reg load "HKLM\zDEFAULT" $Mount_Folder\Windows\System32\config\default
reg load "HKLM\zNTUSER" $Mount_Folder\Users\Default\ntuser.dat
reg load "HKLM\zSOFTWARE" $Mount_Folder\Windows\System32\config\SOFTWARE
reg load "HKLM\zSYSTEM" $Mount_Folder\Windows\System32\config\SYSTEM

Do{

    $Win11Requierements = Read-Host "Would you like to bypass the hardware requirements of Windows 11 ? (1 for Yes or 0 for No) "

} Until (($Win11Requierements -eq "1") -or ($Win11Requierements -eq "0"))

If($Win11Requierements -eq "1"){

    #Bypassing Windows 11 hardware restrictions
    reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d "0" /f
    reg add "HKLM\zDEFAULT\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d "0" /f
    reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV1" /t REG_DWORD /d "0" /f
    reg add "HKLM\zNTUSER\Control Panel\UnsupportedHardwareNotificationCache" /v "SV2" /t REG_DWORD /d "0" /f
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassCPUCheck" /t REG_DWORD /d "1" /f
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassRAMCheck" /t REG_DWORD /d "1" /f
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassSecureBootCheck" /t REG_DWORD /d "1" /f
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassStorageCheck" /t REG_DWORD /d "1" /f
    reg add "HKLM\zSYSTEM\Setup\LabConfig" /v "BypassTPMCheck" /t REG_DWORD /d "1" /f
    reg add "HKLM\zSYSTEM\Setup\MoSetup" /v "AllowUpgradesWithUnsupportedTPMOrCPU" /t REG_DWORD /d "1" /f
}

#########################
#   Registry : Privacy  #
#########################

#Disable Windows Copilot
reg add "HKLM\zNTUSER\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" /v "TurnOffWindowsCopilot" /t REG_DWORD /d "1" /f

#Disable Windows Welcome Experience
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v "ScoobeSystemSettingEnabled" /t REG_DWORD /d "0" /f

#Disable Recommended Tips, Shortcuts, New Apps, and more on Start Menu
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d "0" /f

#Disable Notification Badging for Microsoft Accounts on Start Menu
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_AccountNotifications" /t REG_DWORD /d "0" /f

#Disable ads
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f         #Turn off automatically installing Suggested Apps
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f       #Disable Start Menu Ads or Suggestions
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f                 #Disable Promotional Apps
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d "0" /f    #Turn off Get fun facts, tips, tricks, and more on your lock screen
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d "0" /f    #Turn off Showing My People App Suggestions
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d "0" /f    #Turn off Timeline Suggestions
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f           #Disable Sync Provider Notifications in File Explorer
reg add "HKLM\zNTUSER\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d "1" /f                           #Disable Advertising ID
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\SearchSettings" /v "IsDynamicSearchBoxEnabled" /t REG_DWORD /d "0" /f                  #Disable Search Highlights in Start Menu

#Disable suggested content in Settings
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d "0" /f

#Disable files recently used in Quick Access
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f

#DisableCortana + Web Explorer (HKCU)
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d "0" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d "0" /f
reg add "HKLM\zNTUSER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "DisableSearchBoxSuggestions" /t REG_DWORD /d "1" /f

#Disable Cortana + Web Explorer (HKLM)
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaInAAD" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWebOverMeteredConnections" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoSearchInternetInStartMenu" /t REG_DWORD /d "1" /f

#Disable OneDrive
#reg delete "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f                                             #Error : Key not found
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\OneDrive" /v "KFMBlockOptIn" /t REG_DWORD /d "1" /f

#Disable Windows Tips
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /t REG_DWORD /d "1" /f

#Disable Edge features + telemetry
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Edge" /v "DefaultSearchProviderContextMenuAccessAllowed" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Edge" /v "EdgeEnhanceImagesEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Edge" /v "EdgeFollowEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\EdgeUpdate" /v "CreateDesktopShortcutDefault" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\EdgeUpdate" /v "RemoveDesktopShortcutDefault" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Edge" /v "PersonalizationReportingEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Edge" /v "ShowRecommendationsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Edge" /v "HideFirstRunExperience" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "MicrosoftEdgeDataOptIn" /t REG_DWORD /d "0" /f

#Disable automatically installing Suggested Apps
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "ConfigureStartPins" /t REG_SZ /d '"{\"pinnedList\": [{}]}"' /f

#Disable Cloud search
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d "0" /f

#Disable telemetry
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d "0" /f                       #Disable telemetry
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f                                 #Disable application telemetry
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "EnableOneSettingsAuditing" /t REG_DWORD /d "0" /f            #Disable OneSettings audit
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDeviceNameInTelemetry" /t REG_DWORD /d "0" /f           #Disable sending of device name in Windows diagnostic data
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowCommercialDataPipeline" /t REG_DWORD /d "0" /f          #Disable the commercial data pipeline
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowDesktopAnalyticsProcessing" /t REG_DWORD /d "0" /f      #Disable desktop analysis processing
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowWUfBCloudProcessing" /t REG_DWORD /d "0" /f             #Disable Cloud WUfB processing
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowUpdateComplianceProcessing" /t REG_DWORD /d "0" /f      #Disable update compliance processing
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "DisableEnterpriseAuthProxy" /t REG_DWORD /d "1" /f           #Disable logged-in user experience and telemetry

#Disable Steps Recorder
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d "1" /f

#Disable Timeline
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\System" /v "EnableActivityFeed" /t REG_DWORD /d "0" /f

#Disable videos and tips in Settings
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d "0" /f

#Disable "Look for an app in the Store" + "New Apps Notification"
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoNewAppAlert" /t REG_DWORD /d "1" /f

#Disable Windows Ink Workspace
reg add "HKLM\zSOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowSuggestedAppsInWindowsInkWorkspace" /t REG_DWORD /d "0" /f

#Disable Windows Chat + Teams
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d "3" /f
#reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v "ConfigureChatAutoInstall" /t REG_DWORD /d "0" /f      #Access denied

#Disable widgets
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Dsh" /v "AllowNewsAndInterests" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v "EnableFeeds" /t REG_DWORD /d "0" /f

#Start Menu customization
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HideRecentlyAddedApps" /t REG_DWORD /d "1" /f                  #Hide recently addes apps
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer" /v "ShowOrHideMostUsedApps" /t REG_DWORD /d "2" /f                 #Hide most used apps
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "EnableDynamicContentInWSB" /t REG_DWORD /d "0" /f        #Disable ads in Start Menu
#reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoInstrumentation" /t REG_DWORD /d "1" /f                     #Disable Windows tracking to improve search results. Warning : Breaks search history on third-party tools like StartAllBack

#Taskbar customization
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoPinningStoreToTaskbar" /t REG_DWORD /d "1" /f                #Unpin Windows Store from Taskbar
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d "1" /f       #Disable Cloud optimized content from Taskbar

#OOBE Settings
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\OOBE" /v "DisablePrivacyExperience" /t REG_DWORD /d "1" /f                                               #Disable Privacy Experience in OOBE
reg add "HKLM\zSOFTWARE\Software\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d "0" /f                             #Disable online voice recognition
reg add "HKLM\zSOFTWARE\Software\Microsoft\MdmCommon\SettingValues" /v "LocationSyncEnabled" /t REG_DWORD /d "0" /f                                         #Disable computer location
reg add "HKLM\zSOFTWARE\Software\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowLinguisticDataCollection" /t REG_DWORD /d "0" /f             #Disable collection of handwriting and keystroke data
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled " /t REG_DWORD /d "0" /f                 #Disable tailored experiences

#Privacy preferences
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f                       #Disable motion data
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f                 #Disable diagnostic data
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f                   #Disable calendar access
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f                  #Disable access to other devices
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f          #Disable file system access
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f                       #Disable contacts access
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f                           #Disable chat access
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f               #Disable documents access
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v "Value" /t REG_SZ /d "Deny" /f                #Disable downloads access
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f                          #Disable mail access
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f                       #Disable location services
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f                      #Disable phone calls
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f               #Disable phone call history
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f                #Disable pictures access
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f                         #Disable radios access
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f         #Disable user account access
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f                  #Disable tasks access
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f                  #Disable videos access
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d "2" /f                                             #Disable access to voice-activated Windows applications
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d "2" /f                                    #Disable access to voice-activated Windows applications when the screen is locked

#Disable computer location
reg add "HKLM\zSOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d "0" /f 

#Disable activity history
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\System" /v "UploadUserActivities" /t REG_DWORD /d "0" /f

#Disable Microsoft Diagnostic Tool (MSDT)
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d "100" /f

#Disable shared experiences
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\System" /v "EnableCdp" /t REG_DWORD /d "0" /f

#Disable inventory collection
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d "1" /f

#Allow creation of a local account rather than a Microsoft account
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "BypassNRO" /t REG_DWORD /d "1" /f

##############################
#   Registry : Performances  #
##############################

#Disable background applications
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BackgroundAppGlobalToggle" /t REG_DWORD /d "0" /f

#Disable SmartScreen (HCKU)
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f

#Disable SmartScreen (HKLM)
reg add "HKLM\zSOFTWARE\Microsoft\Edge\SmartScreenEnabled" /ve /d "0" /f
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d "0" /f

#Disable Hiberboot (Hybrid Start)
reg add "HKLM\zSOFTWARE\Policies\Microsoft\Windows\System" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f

#Disable power limiting
reg add "HKLM\zSOFTWARE\PCurrentControlSet\Control\Power\PowerThrottling" /v "PowerThrottlingOff" /t REG_DWORD /d "1" /f

#Disable Reserved Storage
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d "0" /f

###############################
#   Registry : Customization  #
###############################

#RealTimeIsUniversal
reg add "HKLM\zSYSTEM\ControlSet001\Control\TimeZoneInformation" /v "RealTimeIsUniversal" /t REG_DWORD /d "1" /f

#Disable de Xbox DVR
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /v "AppCaptureEnabled" /t REG_DWORD /d "0" /f
reg add "HKLM\zNTUSER\System\GameConfigStore" /v "GameDVR_Enabled" /t REG_DWORD /d "0" /f

#Taskbar tweaking
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d "0" /f           #Remove Widget
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d "0" /f           #Remove Teams
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d "0" /f           #Align taskbar to the left
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v "ShellFeedsTaskbarViewMode" /t REG_DWORD /d "2" /f       #Disable News & Interest

#Enable NumLock on power on
reg add "HKLM\zDEFAULT\.DEFAULT\Control Panel\Keyboard" /v "InitialKeyboardIndicators" /t REG_DWORD /d "2" /f

#Open File Explorer in "This PC" instead of Quick Access
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f

#Enable transparency effects
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d "1" /f

#Enable accent color on title bars and window borders
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d "1" /f

#Enable "This PC" shortcut on desktop
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu" /v "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" /t REG_DWORD /d "0" /f

#Set desktop icon size to medium
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "IconSize" /t REG_DWORD /d "48" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "Mode" /t REG_DWORD /d "1" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\Shell\Bags\1\Desktop" /v "LogicalViewMode" /t REG_DWORD /d "3" /f

#The Print Screen button launches Snipping Tool application
reg add "HKLM\zNTUSER\Control Panel\Keyboard" /v "PrintScreenKeyForSnippingEnabled " /t REG_DWORD /d "1" /f

#Set default dark mode for system and applications
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d "0" /f
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d "0" /f

#Hide "Tasks" item on the taskbar by default
reg add "HKLM\zNTUSER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d "0" /f

#100% wallpaper quality
reg add "HKLM\zNTUSER\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d "64" /f

#Intensify taskbar transparency
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseOLEDTaskbarTransparency" /t REG_DWORD /d "1" /f

#Show Start Menu folders. Warning : User can't disable them except from the registry afterwards
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderDocuments" /t REG_DWORD /d "1" /f                                #Show documents
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderDocuments_ProviderSet" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderDownloads" /t REG_DWORD /d "1" /f                                #Show downloads
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderDownloads_ProviderSet" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderMusic" /t REG_DWORD /d "1" /f                                    #Show music
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderMusic_ProviderSet" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderPersonalFolder" /t REG_DWORD /d "1" /f                           #Show personnal folder
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderPersonalFolder_ProviderSet" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderPictures" /t REG_DWORD /d "1" /f                                 #Show pictures
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderPictures_ProviderSet" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderSettings" /t REG_DWORD /d "1" /f                                 #Show settings
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderSettings_ProviderSet" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderVideos" /t REG_DWORD /d "1" /f                                   #Show videos
reg add "HKLM\zSOFTWARE\Microsoft\PolicyManager\current\device\Start" /v "AllowPinnedFolderVideos_ProviderSet" /t REG_DWORD /d "1" /f

#Enable startup sound
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\BootAnimation" /v "DisableStartupSound" /t REG_DWORD /d "0" /f

#Remove Cast to device from the context menu
reg add "HKLM\zSOFTWARE\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{7AD84985-87B4-4a16-BE58-8B72A5B390F7}" /t REG_SZ /f

#Restore Windows Photo Viewer
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer"
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities" /v "ApplicationDescription" /t REG_SZ /d "@%ProgramFiles%\\Windows Photo Viewer\\photoviewer.dll,-3069" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities" /v "ApplicationName" /t REG_SZ /d "@%ProgramFiles%\\Windows Photo Viewer\\photoviewer.dll,-3009" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".bmp" /t REG_SZ /d "PhotoViewer.FileAssoc.Bitmap" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".dib" /t REG_SZ /d "PhotoViewer.FileAssoc.Bitmap" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".gif" /t REG_SZ /d "PhotoViewer.FileAssoc.Gif" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jfif" /t REG_SZ /d "PhotoViewer.FileAssoc.JFIF" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpe" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpeg" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jpg" /t REG_SZ /d "PhotoViewer.FileAssoc.Jpeg" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".jxr" /t REG_SZ /d "PhotoViewer.FileAssoc.Wdp" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".png" /t REG_SZ /d "PhotoViewer.FileAssoc.Png" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tif" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".tiff" /t REG_SZ /d "PhotoViewer.FileAssoc.Tiff" /f
reg add "HKLM\zSOFTWARE\Microsoft\Windows Photo Viewer\Capabilities\FileAssociations" /v ".wdp" /t REG_SZ /d "PhotoViewer.FileAssoc.Wdp" /f

reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3057" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\imageres.dll,-70"' /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell"
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open"
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Bitmap\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" /v "EditFlags" /t REG_DWORD /d "10000" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3055" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\imageres.dll,-72"' /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell"
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3043" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" /v "EditFlags" /t REG_DWORD /d "10000" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3055" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\imageres.dll,-72"' /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell"
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3043" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Gif" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Gif" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3057" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\imageres.dll,-83"' /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell"
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open"
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Png" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Png" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3057" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Png\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\imageres.dll,-71"' /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell"
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open"
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp" /v "EditFlags" /t REG_DWORD /d "10000" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp" /v "ImageOptionFlags" /t REG_DWORD /d "1" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp" /v "FriendlyTypeName" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-400" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\DefaultIcon" /ve /d '@="%SystemRoot%\\System32\\wmphoto.dll,-72"' /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell"
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open" /v "MuiVerb" /t REG_EXPAND_SZ /d "@%ProgramFiles%\Windows Photo Viewer\PhotoViewer.dll,-3043" /f
reg add "HKLM\zSOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\DropTarget" /v "Clsid" /t REG_SZ /d "{FFE2A43C-56B9-4bf5-9A79-CC6D4285608A}" /f

#Unloading registry keys (System components)
reg unload "HKLM\zDEFAULT"
reg unload "HKLM\zNTUSER"
reg unload "HKLM\zSOFTWARE"
reg unload "HKLM\zSYSTEM"
Start-Sleep 2

Write-Log "Registry tweaking completed" -Success

Write-Log "Saving changes and unmounting the current image, please wait..."
dism /unmount-image /mountdir:$Mount_Folder /commit
Start-Sleep 2

#Remove unused editions
Write-Log "Deleting unused editions, please wait..."
dism /Export-Image /SourceImageFile:"$($Temp_Folder)sources\install.wim" /SourceIndex:$DISMIndex /DestinationImageFile:"$($Temp_Folder)sources\install2.wim" /compress:max
Remove-Item -Path "$($Temp_Folder)sources\install.wim" -Force
Rename-Item -Path "$($Temp_Folder)sources\install2.wim" -NewName "install.wim"

Start-Sleep 5

###############################
#   Post Installation OOBE    #
###############################

Write-Log "Application of OOBE settings, please wait..."

New-Item $Temp_Folder'sources\$OEM$\$$\Setup\Scripts' -ItemType Directory

#OOBE.cmd file creation

New-Item -Path $Temp_Folder'sources\$OEM$\$$\Setup\Scripts' -Name OOBE.cmd -ItemType File

Add-Content -Path $Temp_Folder'sources\$OEM$\$$\Setup\Scripts\OOBE.cmd' '@echo off
TITLE Setting-up RunOnceEx
CLS

IF EXIST "%WINDIR%\SysWOW64" (
    SET ARCH=x64
) ElSE (
    SET ARCH=x86
)

SET FINTEXT="Windows Post-Setup"
SET CERTEXT="Installing certificates"
SET SCRIPTTEXT="Executing scripts"
SET OFFTEXT="Installing Microsoft Office"
SET MSITEXT="Installing MSI packages"
SET ACTTEXT="Activating products"
SET UPDTEXT="Installing updates"
SET SILTEXT="Installing applications"
SET TWKTEXT="Applying personal settings"
set DRVCLNTEXT="Removing unused drivers"
SET RBTTEXT="Reboot"

FOR %%I IN (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) DO IF EXIST %%I:\sources\install.esd SET DRIVE=%%I:
IF "%DRIVE%" == "" FOR %%I IN (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) DO IF EXIST %%I:\sources\install.wim SET DRIVE=%%I:
IF "%DRIVE%" == "" FOR %%I IN (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) DO IF EXIST %%I:\sources\install.swm SET DRIVE=%%I:

SET ROE=HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnceEx

IF EXIST "%WINDIR%\System32\iernonce.dll" (

    REG ADD %ROE% /v Title /d %FINTEXT% /f
    REG ADD %ROE% /v Flags /t REG_DWORD /d "00000024" /f


    REM From Windows 8 up kill explorer.exe
    IF NOT EXIST "%WINDIR%\Servicing\Version\6.1.*" (
        REG ADD %ROE%\000 /ve /d " " /f
        REG ADD %ROE%\000 /v "KillExplorer" /d "%WINDIR%\System32\cmd.exe /c \"start /min /wait %WINDIR%\setup\scripts\Watcher.cmd\"" /f
    )


    REM Install certificates into My / Root / CA store
    IF EXIST "%DRIVE%\setup\*.cer" (
        REG ADD %ROE%\001 /ve /d %CERTEXT% /f
        FOR %%U IN ("%DRIVE%\setup\*.cer") DO (
            REG ADD %ROE%\001 /v "%%~nU_TrustedPublisher" /d "%WINDIR%\System32\certutil.exe -addstore TrustedPublisher %%U" /f
            REG ADD %ROE%\001 /v "%%~nU_My" /d "%WINDIR%\System32\certutil.exe -addstore My %%U" /f
            REG ADD %ROE%\001 /v "%%~nU_CA" /d "%WINDIR%\System32\certutil.exe -addstore CA %%U" /f
            REG ADD %ROE%\001 /v "%%~nU_Root" /d "%WINDIR%\System32\certutil.exe -addstore Root %%U" /f
        )
    )


    REM Auto-install Microsoft Office 2008 - 2016
    IF EXIST "%DRIVE%\office\%ARCH%\setup.exe" (
        REG ADD %ROE%\002 /ve /d %OFFTEXT% /f
        REG ADD %ROE%\002 /v "MSO" /d "%DRIVE%\office\%ARCH%\setup.exe" /f
    ) ELSE IF EXIST "%DRIVE%\office\All\setup.exe" (
        REG ADD %ROE%\002 /ve /d %OFFTEXT% /f
        REG ADD %ROE%\002 /v "MSO" /d "%DRIVE%\office\All\setup.exe" /f
    )


    REM Auto-install Microsoft Office 2019 / 365
    IF EXIST "%DRIVE%\office\YAOCTRI_Installer.cmd" (
        REG ADD %ROE%\002 /ve /d %OFFTEXT% /f
        REG ADD %ROE%\002 /v "MSO" /d "%DRIVE%\office\YAOCTRI_Installer.cmd" /f
    )
    IF EXIST "%DRIVE%\office\YAOCTRIR_Installer.cmd" (
        REG ADD %ROE%\002 /ve /d %OFFTEXT% /f
        REG ADD %ROE%\002 /v "MSO" /d "%DRIVE%\office\YAOCTRIR_Installer.cmd" /f
    )


    REM Auto-install %ARCH% depend MSI packages
    IF EXIST "%DRIVE%\setup\*-%ARCH%.msi" (
        REG ADD %ROE%\003 /ve /d %MSITEXT% /f

        FOR %%C IN ("%DRIVE%\setup\*-%ARCH%.msi") DO (
            REM Get Installer
            FOR /F "tokens=1 delims=-" %%G IN ("%%~nC") DO (
                REM Get Switch
                if exist "%DRIVE%\setup\%%G.txt" (
                    for /F "usebackq tokens=*" %%A in ("%DRIVE%\setup\%%G.txt") do (
                        REG ADD %ROE%\003 /v "%%~nC" /d "%%C %%A" /f
                    )
                ) else (
                    REG ADD %ROE%\003 /v "%%~nC" /d "msiexec /i %%C /quiet /norestart" /f
                )
            )
        )
    )


    REM Auto-install %ARCH% independent MSI packages
    IF EXIST "%DRIVE%\setup\*-all.msi" (
        REG ADD %ROE%\003 /ve /d %MSITEXT% /f

        FOR %%C IN ("%DRIVE%\setup\*-all.msi") DO (
            REM Get Installer
            FOR /F "tokens=1 delims=-" %%G IN ("%%~nC") DO (
                REM Get Switch
                if exist "%DRIVE%\setup\%%G.txt" (
                    for /F "usebackq tokens=*" %%A in ("%DRIVE%\setup\%%G.txt") do (
                        REG ADD %ROE%\003 /v "%%~nC" /d "%%C %%A" /f
                    )
                ) else (
                    REG ADD %ROE%\003 /v "%%~nC" /d "msiexec /i %%C /quiet /norestart" /f
                )
            )
        )
    )


    REM Windows + Office activation
    IF EXIST "%DRIVE%\support\Activate.cmd" (
        REG ADD %ROE%\004 /ve /d %ACTTEXT% /f
        REG ADD %ROE%\004 /v "Activation" /d "%WINDIR%\System32\cmd.exe /c \"start /min /wait %DRIVE%\support\Activate.cmd\"" /f
    )


    REM Install MSU / CAB / MSP Packages from %DRIVE%\updates
    REG ADD %ROE%\005 /ve /d %UPDTEXT% /f
    FOR %%U IN ("%DRIVE%\updates\*%ARCH%*.msu") DO REG ADD %ROE%\005 /v "%%~nU" /d "dism /Online /Add-Package /PackagePath:%%U /quiet /norestart" /f
    FOR %%U IN ("%DRIVE%\updates\*%ARCH%*.cab") DO REG ADD %ROE%\005 /v "%%~nU" /d "dism /Online /Add-Package /PackagePath:%%U /quiet /norestart" /f
    FOR %%U IN ("%DRIVE%\updates\*%ARCH%*.msp") DO REG ADD %ROE%\005 /v "%%~nU" /d "msiexec /i %%U /quiet /norestart" /f


    REM Auto-install %ARCH% depend software with predefined silent switch
    IF EXIST "%DRIVE%\setup\*-%ARCH%.exe" (
        REG ADD %ROE%\006 /ve /d %SILTEXT% /f

        FOR %%C IN ("%DRIVE%\setup\*-%ARCH%.exe") DO (
            REM Get Installer
            FOR /F "tokens=1 delims=-" %%G IN ("%%~nC") DO (
                REM Get Switch
                if exist "%DRIVE%\setup\%%G.txt" (
                    for /F "usebackq tokens=*" %%A in ("%DRIVE%\setup\%%G.txt") do (
                        REG ADD %ROE%\006 /v "%%~nC" /d "%%C %%A" /f
                    )
                )
            )
        )
    )

    REM Auto-install %ARCH% independent software with predefined silent switch
    IF EXIST "%DRIVE%\setup\*-all.exe" (
        REG ADD %ROE%\006 /ve /d %SILTEXT% /f

        FOR %%C IN ("%DRIVE%\setup\*-all.exe") DO (
            REM Get Installer
            FOR /F "tokens=1 delims=-" %%G IN ("%%~nC") DO (
                REM Get Switch
                if exist "%DRIVE%\setup\%%G.txt" (
                    for /F "usebackq tokens=*" %%A in ("%DRIVE%\setup\%%G.txt") do (
                        REG ADD %ROE%\006 /v "%%~nC" /d "%%C %%A" /f
                    )
                )
            )
        )
    )


    REM Apply REG Tweaks from %DRIVE%\setup
    IF EXIST "%DRIVE%\setup\*.reg" (
        REG ADD %ROE%\007 /ve /d %TWKTEXT% /f
        FOR %%U IN ("%DRIVE%\setup\*.reg") DO REG ADD %ROE%\007 /v "%%~nU" /d "regedit /s %%U" /f
    )


    REM Remove unused drivers from DriverStore
    IF EXIST "%WINDIR%\setup\scripts\CleanDriverStore.cmd" (
        REG ADD %ROE%\008 /ve /d %DRVCLNTEXT% /f
        REG ADD %ROE%\008 /v "Driver CleanUp" /d "%WINDIR%\System32\cmd.exe /c \"start /min /wait %WINDIR%\setup\scripts\CleanDriverStore.cmd\"" /f
    )


    REM Custom PS1 / CMD / BAT scripts execution
    REM PS1
    FOR %%C IN ("%DRIVE%\setup\*.ps1") DO (
        REG ADD %ROE%\009 /ve /d %SCRIPTTEXT% /f
        REG ADD %ROE%\009 /v "%%C" /d "%WINDIR%\System32\cmd.exe /min /c \"start /wait powershell -NoLogo -WindowStyle Hidden -File \"%%C\"\"" /f
    )

    REM CMD
    FOR %%C IN ("%DRIVE%\setup\*.cmd") DO (
        REG ADD %ROE%\009 /ve /d %SCRIPTTEXT% /f
        REG ADD %ROE%\009 /v "%%C" /d "%WINDIR%\System32\cmd.exe /min /c \"start /wait %%C\"" /f
    )

    REM BAT
    FOR %%C IN ("%DRIVE%\setup\*.bat") DO (
        REG ADD %ROE%\009 /ve /d %SCRIPTTEXT% /f
        REG ADD %ROE%\009 /v "%%C" /d "%WINDIR%\System32\cmd.exe /min /c \"start /wait %%C\"" /f
    )


    REM Polish Start menu items and reboot
    REG ADD %ROE%\010 /ve /d %RBTTEXT% /f
    if exist "%WINDIR%\setup\scripts\StartMenu.cmd" (
        REG ADD %ROE%\010 /v "01_StartMenu" /d "%WINDIR%\System32\cmd.exe /c \"start /min /wait %WINDIR%\setup\scripts\StartMenu.cmd\"" /f
    )
    REG ADD %ROE%\010 /v "02_Reboot" /d "%WINDIR%\System32\shutdown.exe -r -f -t 0" /f


    REM Enable ROE
    REG ADD %ROE% /d "%WINDIR%\System32\rundll32.exe %WINDIR%\System32\iernonce.dll,RunOnceExProcess" /f

)


exit'

#Watcher.cmd file creation

New-Item -Path $Temp_Folder'sources\$OEM$\$$\Setup\Scripts' -Name Watcher.cmd -ItemType File

Add-Content -Path $Temp_Folder'sources\$OEM$\$$\Setup\Scripts\Watcher.cmd' '@echo off
title Windows Explorer Watcher
cls

set ProcessToFind=explorer.exe

:PerformCheck
for /f "tokens=1 delims= " %%G in (''tasklist ^| findstr %ProcessToFind%'') do set RunningProcess=%%G

if "%RunningProcess%" == "%ProcessToFind%" (
    taskkill /im %ProcessToFind% /f
    exit
) else (
    timeout 5 >nul
    goto :PerformCheck
)'

Write-Log "Convert end-of-line encoding from UNIX (LF) to Windows (CRLF), please wait..."
Get-ChildItem $Temp_Folder'sources\$OEM$\$$\Setup\Scripts' | ForEach-Object {
    ## If contains UNIX line endings, replace with Windows line endings
    if (Get-Content $_.FullName -Delimiter "`0" | Select-String "[^`r]`n")
    {
        $content = Get-Content $_.FullName
        $content | Set-Content $_.FullName
    }
}

###############################################
#   Application download and configuration    #
###############################################

#Application folder creation

New-Item $Temp_Folder'setup' -ItemType Directory

#Download system applications

Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile $Temp_Folder'setup\VCRedist2022-x64.exe'       #VCRedist 2015-2022 x64
New-Item -Path $Temp_Folder'setup' -Name VCRedist2022.txt -ItemType File
Add-Content -Path $Temp_Folder'setup\VCRedist2022.txt' '/install /quiet /norestart'

#Download web browser

Do{

    $WebBrowser = Read-Host "Which browser would you like to install ? (0 for None or enter the desired browser from the list below : Firefox, Brave) "

} Until (($WebBrowser -eq "0") -or ($WebBrowser -eq "Firefox") -or ($WebBrowser -eq "Brave"))

If($WebBrowser -eq "Firefox"){

    Invoke-WebRequest -Uri "https://download.mozilla.org/?product=firefox-msi-latest-ssl&os=win64" -OutFile $Temp_Folder'setup\FirefoxInstaller-x64.msi'

}
ElseIf($WebBrowser -eq "Brave"){

    Invoke-WebRequest -Uri "https://github.com/brave/brave-browser/releases/latest/download/BraveBrowserStandaloneSetup.exe" -OutFile $Temp_Folder'setup\Brave-x64.exe'
    New-Item -Path $Temp_Folder'setup' -Name Brave.cmd -ItemType File
    Add-Content -Path $Temp_Folder'setup\Brave.cmd' '::::::::::::::::::::::::::::::::::::::::::::
:: Elevate.cmd - Version 4
:: Automatically check & get admin rights
:: see "https://stackoverflow.com/a/12264592/1016343" for description
::::::::::::::::::::::::::::::::::::::::::::
 @echo off
 CLS
 ECHO.
 ECHO =============================
 ECHO Running Admin shell
 ECHO =============================

:init
 setlocal DisableDelayedExpansion
 set cmdInvoke=1
 set winSysFolder=System32
 set "batchPath=%~dpnx0"
 rem this works also from cmd shell, other than %~0
 for %%k in (%0) do set batchName=%%~nk
 set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
 setlocal EnableDelayedExpansion

:checkPrivileges
  NET FILE 1>NUL 2>NUL
  if ''%errorlevel%'' == ''0'' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
  if ''%1''==''ELEV'' (echo ELEV & shift /1 & goto gotPrivileges)
  ECHO.
  ECHO **************************************
  ECHO Invoking UAC for Privilege Escalation
  ECHO **************************************

  ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
  ECHO args = "ELEV " >> "%vbsGetPrivileges%"
  ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
  ECHO args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
  ECHO Next >> "%vbsGetPrivileges%"
  
  if ''%cmdInvoke%''==''1'' goto InvokeCmd 

  ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
  goto ExecElevation

:InvokeCmd
  ECHO args = "/c """ + "!batchPath!" + """ " + args >> "%vbsGetPrivileges%"
  ECHO UAC.ShellExecute "%SystemRoot%\%winSysFolder%\cmd.exe", args, "", "runas", 1 >> "%vbsGetPrivileges%"

:ExecElevation
 "%SystemRoot%\%winSysFolder%\WScript.exe" "%vbsGetPrivileges%" %*
 exit /B

:gotPrivileges
 setlocal & cd /d %~dp0
 if ''%1''==''ELEV'' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

 ::::::::::::::::::::::::::::
 ::START
 ::::::::::::::::::::::::::::

FOR %%I IN (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) DO IF EXIST %%I:\setup\Brave-x64.exe SET DRIVE=%%I:

copy "%DRIVE%\setup\Brave-x64.exe" "%localappdata%\Temp"
"%localappdata%\Temp\Brave-x64.exe" /silent /install

exit'
}
ElseIf($WebBrowser -eq "0"){
    Write-Log "No browser selected"
}

Do{

    $StartAllBack = Read-Host "Would you like to download StartAllBack ? (1 for Yes or 0 for No) "

} Until (($StartAllBack -eq "1") -or ($StartAllBack -eq "0"))

If($StartAllBack -eq "1"){

    Invoke-WebRequest -Uri "https://www.startallback.com/download.php" -OutFile $Temp_Folder'setup\StartAllBack-x64.exe'
    New-Item -Path $Temp_Folder'setup' -Name StartAllBack.cmd -ItemType File
    Add-Content -Path $Temp_Folder'setup\StartAllBack.cmd' '::::::::::::::::::::::::::::::::::::::::::::
:: Elevate.cmd - Version 4
:: Automatically check & get admin rights
:: see "https://stackoverflow.com/a/12264592/1016343" for description
::::::::::::::::::::::::::::::::::::::::::::
 @echo off
 CLS
 ECHO.
 ECHO =============================
 ECHO Running Admin shell
 ECHO =============================

:init
 setlocal DisableDelayedExpansion
 set cmdInvoke=1
 set winSysFolder=System32
 set "batchPath=%~dpnx0"
 rem this works also from cmd shell, other than %~0
 for %%k in (%0) do set batchName=%%~nk
 set "vbsGetPrivileges=%temp%\OEgetPriv_%batchName%.vbs"
 setlocal EnableDelayedExpansion

:checkPrivileges
  NET FILE 1>NUL 2>NUL
  if ''%errorlevel%'' == ''0'' ( goto gotPrivileges ) else ( goto getPrivileges )

:getPrivileges
  if ''%1''==''ELEV'' (echo ELEV & shift /1 & goto gotPrivileges)
  ECHO.
  ECHO **************************************
  ECHO Invoking UAC for Privilege Escalation
  ECHO **************************************

  ECHO Set UAC = CreateObject^("Shell.Application"^) > "%vbsGetPrivileges%"
  ECHO args = "ELEV " >> "%vbsGetPrivileges%"
  ECHO For Each strArg in WScript.Arguments >> "%vbsGetPrivileges%"
  ECHO args = args ^& strArg ^& " "  >> "%vbsGetPrivileges%"
  ECHO Next >> "%vbsGetPrivileges%"
  
  if ''%cmdInvoke%''==''1'' goto InvokeCmd 

  ECHO UAC.ShellExecute "!batchPath!", args, "", "runas", 1 >> "%vbsGetPrivileges%"
  goto ExecElevation

:InvokeCmd
  ECHO args = "/c """ + "!batchPath!" + """ " + args >> "%vbsGetPrivileges%"
  ECHO UAC.ShellExecute "%SystemRoot%\%winSysFolder%\cmd.exe", args, "", "runas", 1 >> "%vbsGetPrivileges%"

:ExecElevation
 "%SystemRoot%\%winSysFolder%\WScript.exe" "%vbsGetPrivileges%" %*
 exit /B

:gotPrivileges
 setlocal & cd /d %~dp0
 if ''%1''==''ELEV'' (del "%vbsGetPrivileges%" 1>nul 2>nul  &  shift /1)

 ::::::::::::::::::::::::::::
 ::START
 ::::::::::::::::::::::::::::

FOR %%I IN (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) DO IF EXIST %%I:\setup\StartAllBack-x64.exe SET DRIVE=%%I:

copy "%DRIVE%\setup\StartAllBack-x64.exe" "%localappdata%\Temp"
"%localappdata%\Temp\StartAllBack-x64.exe" /elevated /install /silent

exit'
}

Write-Log "Convert end-of-line encoding from UNIX (LF) to Windows (CRLF), please wait..."
Get-ChildItem $Temp_Folder'setup\*.cmd' | ForEach-Object {
    ## If contains UNIX line endings, replace with Windows line endings
    if (Get-Content $_.FullName -Delimiter "`0" | Select-String "[^`r]`n")
    {
        $content = Get-Content $_.FullName
        $content | Set-Content $_.FullName
    }
}


Write-Log "OOBE successfully configured" -Success

#####################################
#   Add additional registry keys    #
#####################################

Write-Log "Applying registry changes with .reg file"

New-Item -Path $Temp_Folder'setup' -Name RegDeploy.reg -ItemType File
Add-Content -Path $Temp_Folder'setup\RegDeploy.reg' 'Windows Registry Editor Version 5.00

; Restore old context menu

[HKEY_CURRENT_USER\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32]
@="-"

; Open .msi files in administrator mode

[HKEY_CLASSES_ROOT\Msi.Package\shell\runas\command]
@="C:\\Windows\\System32\\msiexec.exe /i \"%1\" %*"

; Open .ps1 files in administrator mode

[HKEY_CLASSES_ROOT\Microsoft.PowerShellScript.1\Shell\runas\command]
@="powershell.exe \"-Command\" \"if((Get-ExecutionPolicy ) -ne ''AllSigned'') { Set-ExecutionPolicy -Scope Process Bypass }; & ''%1''\""

; Open .vbs files in administrator mode

[HKEY_CLASSES_ROOT\VBSFile\Shell\runas\command]
@="C:\\Windows\\System32\\WScript.exe \"%1\" %*"

; Installing .cab files

[HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs]
@="Install this update"
"HasLUAShield"=""

[HKEY_CLASSES_ROOT\CABFolder\Shell\RunAs\Command]
@="cmd /k dism /online /add-package /packagepath:\"%1\""

; Extract .msi files

[HKEY_CLASSES_ROOT\Msi.Package\shell\Extract\command]
@="msiexec.exe /a \"%1\" /qb TARGETDIR=\"%1 Contents\""

; Disable website language access to display relevant content

[HKEY_CURRENT_USER\Control Panel\International\User Profile]
"HttpAcceptLanguageOptOut"=dword:00000001

; Remove automatic installation of Outlook and PowerAutomate

[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\DevHomeUpdate]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator\UScheduler\OutlookUpdate]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate]
[-HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate]

; Integration of photo viewer controls

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Tiff\shell\open\command]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
  00,31,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.JFIF\shell\open\command]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
  00,31,00,00,00


[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Jpeg\shell\open\command]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
  00,31,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Gif\shell\open\command]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
  00,31,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\command]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
  00,31,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Png\shell\open\command]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
  00,31,00,00,00

[HKEY_LOCAL_MACHINE\SOFTWARE\Classes\PhotoViewer.FileAssoc.Wdp\shell\open\command]
@=hex(2):25,00,53,00,79,00,73,00,74,00,65,00,6d,00,52,00,6f,00,6f,00,74,00,25,\
  00,5c,00,53,00,79,00,73,00,74,00,65,00,6d,00,33,00,32,00,5c,00,72,00,75,00,\
  6e,00,64,00,6c,00,6c,00,33,00,32,00,2e,00,65,00,78,00,65,00,20,00,22,00,25,\
  00,50,00,72,00,6f,00,67,00,72,00,61,00,6d,00,46,00,69,00,6c,00,65,00,73,00,\
  25,00,5c,00,57,00,69,00,6e,00,64,00,6f,00,77,00,73,00,20,00,50,00,68,00,6f,\
  00,74,00,6f,00,20,00,56,00,69,00,65,00,77,00,65,00,72,00,5c,00,50,00,68,00,\
  6f,00,74,00,6f,00,56,00,69,00,65,00,77,00,65,00,72,00,2e,00,64,00,6c,00,6c,\
  00,22,00,2c,00,20,00,49,00,6d,00,61,00,67,00,65,00,56,00,69,00,65,00,77,00,\
  5f,00,46,00,75,00,6c,00,6c,00,73,00,63,00,72,00,65,00,65,00,6e,00,20,00,25,\
  00,31,00,00,00

'

Write-Log ".reg file successfully configured" -Success

#############################
#   autounattend.xml file   #
#############################

Write-Log "autounattend.xml file configuration"

New-Item -Path $Temp_Folder -Name autounattend.xml -ItemType File
Add-Content -Path $Temp_Folder'autounattend.xml' '<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
	<!--https://schneegans.de/windows/unattend-generator/?LanguageMode=Unattended&UILanguage=fr-FR&UserLocale=fr-FR&KeyboardLayout=040c%3A0000040c&ProcessorArchitecture=amd64&BypassNetworkCheck=true&ComputerNameMode=Random&TimeZoneMode=Explicit&TimeZone=Romance+Standard+Time&PartitionMode=Interactive&WindowsEditionMode=Unattended&WindowsEdition=pro&UserAccountMode=Interactive&PasswordExpirationMode=Unlimited&LockoutMode=Default&WifiMode=Skip&ExpressSettings=DisableAll&SystemScript0=&SystemScriptType0=Cmd&SystemScript1=&SystemScriptType1=Ps1&SystemScript2=&SystemScriptType2=Reg&SystemScript3=&SystemScriptType3=Vbs&DefaultUserScript0=&DefaultUserScriptType0=Reg&FirstLogonScript0=&FirstLogonScriptType0=Cmd&FirstLogonScript1=&FirstLogonScriptType1=Ps1&FirstLogonScript2=&FirstLogonScriptType2=Reg&FirstLogonScript3=&FirstLogonScriptType3=Vbs&UserOnceScript0=&UserOnceScriptType0=Cmd&UserOnceScript1=&UserOnceScriptType1=Ps1&UserOnceScript2=&UserOnceScriptType2=Reg&UserOnceScript3=&UserOnceScriptType3=Vbs&WdacMode=Skip-->
	<settings pass="offlineServicing"></settings>
	<settings pass="windowsPE">
		<component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
			<UserData>
				<ProductKey>
					<Key>VK7JG-NPHTM-C97JM-9MPGT-3V66T</Key>
				</ProductKey>
				<AcceptEula>true</AcceptEula>
			</UserData>
		</component>
	</settings>
	<settings pass="generalize"></settings>
	<settings pass="specialize">
		<component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
			<RunSynchronous>
				<RunSynchronousCommand wcm:action="add">
					<Order>1</Order>
					<Path>reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v BypassNRO /t REG_DWORD /d 1 /f</Path>
				</RunSynchronousCommand>
				<RunSynchronousCommand wcm:action="add">
					<Order>2</Order>
					<Path>net.exe accounts /maxpwage:UNLIMITED</Path>
				</RunSynchronousCommand>
			</RunSynchronous>
		</component>
	</settings>
	<settings pass="auditSystem"></settings>
	<settings pass="auditUser"></settings>
	<settings pass="oobeSystem">
		<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
			<OOBE>
				<ProtectYourPC>3</ProtectYourPC>
				<HideEULAPage>true</HideEULAPage>
				<HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
			</OOBE>
		</component>
	</settings>
</unattend>'

Write-Log "autounattend.xml file successfully configurated" -Success

#########################
#   ISO File Creation   #
#########################

Write-Log "ISO file creation, please wait..."

function New-IsoFile 
{  
  <# .Synopsis Creates a new .iso file .Description The New-IsoFile cmdlet creates a new .iso file containing content from chosen folders .Example New-IsoFile "c:\tools","c:Downloads\utils" This command creates a .iso file in $env:temp folder (default location) that contains c:\tools and c:\downloads\utils folders.
  The folders themselves are included at the root of the .iso image. .Example New-IsoFile -FromClipboard -Verbose Before running this command, select and copy (Ctrl-C) files/folders in Explorer first. .Example dir c:\WinPE | New-IsoFile -Path c:\temp\WinPE.iso -BootFile "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\efisys.bin" -Media DVDPLUSR -Title "WinPE"
  This command creates a bootable .iso file containing the content from c:\WinPE folder, but the folder itself isn't included. Boot file etfsboot.com can be found in Windows ADK. Refer to IMAPI_MEDIA_PHYSICAL_TYPE enumeration for possible media types: http://msdn.microsoft.com/en-us/library/windows/desktop/aa366217(v=vs.85).aspx
  Notes NAME: New-IsoFile AUTHOR: Chris Wu LASTEDIT: 23/03/2016 14:46:50 #> 
   
  [CmdletBinding(DefaultParameterSetName='Source')]Param( 
    [parameter(Position=1,Mandatory=$true,ValueFromPipeline=$true, ParameterSetName='Source')]$Source,  
    [parameter(Position=2)][string]$Path = "$env:temp\$((Get-Date).ToString('dd-MM-yyyy_HH-mm-ss.ffff')).iso",  
    [ValidateScript({Test-Path -LiteralPath $_ -PathType Leaf})][string]$BootFile = $null, 
    [ValidateSet('CDR','CDRW','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','BDR','BDRE')][string] $Media = 'DVDPLUSRW_DUALLAYER', 
    [string]$Title = (Get-Date).ToString("dd-MM-yyyy_HH-mm-ss.ffff"),  
    [switch]$Force, 
    [parameter(ParameterSetName='Clipboard')][switch]$FromClipboard 
  ) 
  
  Begin {  
    ($cp = new-object System.CodeDom.Compiler.CompilerParameters).CompilerOptions = '/unsafe' 
    if (!('ISOFile' -as [type])) {  
      Add-Type -CompilerParameters $cp -TypeDefinition @'
public class ISOFile  
{ 
  public unsafe static void Create(string Path, object Stream, int BlockSize, int TotalBlocks)  
  {  
    int bytes = 0;  
    byte[] buf = new byte[BlockSize];  
    var ptr = (System.IntPtr)(&bytes);  
    var o = System.IO.File.OpenWrite(Path);  
    var i = Stream as System.Runtime.InteropServices.ComTypes.IStream;  
   
    if (o != null) { 
      while (TotalBlocks-- > 0) {  
        i.Read(buf, BlockSize, ptr); o.Write(buf, 0, bytes);  
      }  
      o.Flush(); o.Close();  
    } 
  } 
}  
'@  
    } 
   
    if ($BootFile) { 
      if('BDR','BDRE' -contains $Media) { Write-Log "Bootable image doesn't seem to work with media type $Media" -Warning } 
      ($Stream = New-Object -ComObject ADODB.Stream -Property @{Type=1}).Open()  # adFileTypeBinary 
      $Stream.LoadFromFile((Get-Item -LiteralPath $BootFile).Fullname) 
      ($Boot = New-Object -ComObject IMAPI2FS.BootOptions).AssignBootImage($Stream) 
    } 
  
    $MediaType = @('UNKNOWN','CDROM','CDR','CDRW','DVDROM','DVDRAM','DVDPLUSR','DVDPLUSRW','DVDPLUSR_DUALLAYER','DVDDASHR','DVDDASHRW','DVDDASHR_DUALLAYER','DISK','DVDPLUSRW_DUALLAYER','HDDVDROM','HDDVDR','HDDVDRAM','BDROM','BDR','BDRE') 
  
    Write-Log "The media type is $Media with value $($MediaType.IndexOf($Media))"
    ($Image = New-Object -com IMAPI2FS.MsftFileSystemImage -Property @{VolumeName=$Title}).ChooseImageDefaultsForMediaType($MediaType.IndexOf($Media)) 
   
    if (!($Target = New-Item -Path $Path -ItemType File -Force:$Force -ErrorAction SilentlyContinue)) { Write-Log "Cannot create file $Path. Use -Force parameter to overwrite if the target file already exists" -Err; break } 
  }  
  
  Process { 
    if($FromClipboard) { 
      if($PSVersionTable.PSVersion.Major -lt 5) { Write-Log 'The -FromClipboard parameter is only supported on PowerShell v5 or higher' -Err; break } 
      $Source = Get-Clipboard -Format FileDropList 
    } 
  
    foreach($item in $Source) { 
      if($item -isnot [System.IO.FileInfo] -and $item -isnot [System.IO.DirectoryInfo]) { 
        $item = Get-Item -LiteralPath $item
      } 
  
      if($item) { 
        Write-Log "Adding item to the target image : $($item.FullName)"
        try { $Image.Root.AddTree($item.FullName, $true) } catch { Write-Log ($_.Exception.Message.Trim() + ' Try a different media type') -Err } 
      } 
    } 
  } 
  
  End {  
    if ($Boot) { $Image.BootImageOptions=$Boot }  
    $Result = $Image.CreateResultImage()  
    [ISOFile]::Create($Target.FullName,$Result.ImageStream,$Result.BlockSize,$Result.TotalBlocks) 
    Write-Log "Target image ($($Target.FullName)) has been created" -Success
    $Target
  } 
} 

Get-ChildItem "$Temp_Folder" | New-ISOFile -Path "C:\Users\$env:USERNAME\Desktop\Windows 11 Lite x64.iso" -Media DISK -Bootfile "$Temp_Folder\efi\microsoft\boot\efisys_noprompt.bin" -Title "Windows 11 Lite x64"

Pause
Exit