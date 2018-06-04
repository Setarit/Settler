##
# 
# Installer script for settler
# (c) Setarit
#
##
##
# Boot script
##
param(
    [switch]$Elevated = $false,
    [string]$CertificatePath = $null
)
$ErrorActionPreference = "Stop"

function PrintMessageAndExit($ErrorMessage, $ReturnCode)
{
    Write-Host $ErrorMessage
    if (!$Force)
    {
        Pause
    }
    exit $ReturnCode
}

##
# Gets the OS processor architecture
##
function GetOsArchitecture(){
    $architecture = ""
    if (($Env:Processor_Architecture -eq "x86"))
    {
        $architecture = "x86"
    }
    if (($Env:Processor_Architecture -eq "amd64"))
    {
        $architecture = "x64"
    }
    if (($Env:Processor_Architecture -eq "arm"))
    {
        $architecture = "arm"
    }
    return $architecture
}

#
# Validates whether a file is a valid certificate using CertUtil.
# This needs to be done before calling Get-PfxCertificate on the file, otherwise
# the user will get a cryptic "Password: " prompt for invalid certs.
#
function ValidateCertificateFormat($FilePath)
{
    # certutil -verify prints a lot of text that we don't need, so it's redirected to $null here
    certutil.exe -verify $FilePath > $null
    if ($LastExitCode -lt 0)
    {        
        PrintMessageAndExit -ErrorMessage "The prvodided license is not valid" -ReturnCode -1
    }
    
    # Check if certificate is expired
    $cert = Get-PfxCertificate $FilePath
    if (($cert.NotBefore -gt (Get-Date)) -or ($cert.NotAfter -lt (Get-Date)))
    {        
        PrintMessageAndExit -ErrorMessage "The prvodided license has expired" -ReturnCode -1
    }
}

##
# Installs the certificate in the TrustedPeople store
##
function InstallCertificate($CertificatePath){
    # Add cert to store
    certutil.exe -addstore -f TrustedPeople $CertificatePath
    if ($LastExitCode -lt 0)
    {
        PrintMessageAndExit -ErrorMessage "We were unable to install the certificate" -ReturnCode -1
    }
}

function RequestContinueAsElevated($certPath){
    $RelaunchArgs = '-ExecutionPolicy Unrestricted -file "' + $ScriptPath + '" -Elevated -CertificatePath "'+$certPath+'"'
    try{
        $AdminProcess = Start-Process "$PsHome\PowerShell.exe" -Verb RunAs -ArgumentList $RelaunchArgs -PassThru -WindowStyle Hidden
    }catch{
        $Error[0] # Dump details about the last error
        PrintMessageAndExit -ErrorMessage "Launching as admin failed" -ReturnCode -1
    }

    while (!($AdminProcess.HasExited))
    {
        Start-Sleep -Seconds 2
    }
}

##
# Checks if the device is compatible
##
function VerifyDeviceCompatibility(){
    if([System.Environment]::OSVersion.Version.Major -ne 10){
        PrintMessageAndExit -ErrorMessage "No running on Windows 10" -ReturnCode -1
    }elseif([System.Environment]::OSVersion.Version.Build -lt 16299){
        PrintMessageAndExit -ErrorMessage "Settler requires the Fall Creators Update released in October 2017" -ReturnCode -1
    }
}

##
# Downloads and installs remote msi software
##
function DownloadAndInstall($url, $FriendlyName){
    $fullLocalPath = $env:TEMP+"\"+$FriendlyName
    Invoke-WebRequest -Uri $url -OutFile  $fullLocalPath
    $msiArgs = "/I "+$fullLocalPath+" /norestart"
    $installResult = Start-Process msiexec.exe -Wait -ArgumentList $msiArgs
    Remove-Item -Path $fullLocalPath    
}

##
# Downloads and installs remote exe software
##
function DownloadAndInstallExe($url, $FriendlyName){
    $fullLocalPath = $env:TEMP+"\"+$FriendlyName
    Invoke-WebRequest -Uri $url -OutFile  $fullLocalPath
    Start-Process -FilePath $fullLocalPath -Wait
    Remove-Item -Path $fullLocalPath    
}

##
# Checks if a module is available
##
function IsModuleAvailable($name){
    $arguments = '-c "$modules = (Get-Module -ListAvailable -All | Where-Object {$_.Name -like ''*'+$name+'*''} | group).Count;$exitCode = if($modules -ge 0){0}else{-1};exit $exitCode;"'
    $result = Start-Process -FilePath PowerShell.exe -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden
    $message = "Verify "+$name+": "+$result.ExitCode
    Write-Host $message    
    return ($result.ExitCode -eq 0)
}

##
# Check if sharepoint is installed
##
function VerifyIfSharePointConnectionSoftwareIsInstalled($osArchitecture, $noInstall){
    $installed = (Get-Command Get-SPOUser -errorAction SilentlyContinue) -or (IsModuleAvailable -name 'Microsoft.Online.SharePoint.PowerShell')
    if((!$installed) -and ($noInstall -eq $false)){#only install if required
        $url = "https://download.microsoft.com/download/0/2/E/02E7E5BA-2190-44A8-B407-BC73CA0D6B87/SharePointOnlineManagementShell_7625-1200_"+$osArchitecture+"_en-us.msi"        
        DownloadAndInstall -url $url -FriendlyName "sharepoint.msi"
        VerifyIfSharePointConnectionSoftwareIsInstalled -osArchitecture $osArchitecture -noInstall $true
    }
    if($noInstall -and !$installed){
        PrintMessageAndExit -ErrorMessage "Failed to install sharepoint.msi" -ReturnCode -1
    }
}

##
# Check if Microsoft Azure Active Directory Module is installed
##
function VerifyIfMicrosoftAzureActiveDirectoryModuleIsInstalled($osArchitecture, $noInstall){
    $installed = (Get-Command Connect-MsolService -errorAction SilentlyContinue) -or (IsModuleAvailable -name 'MSOnline')
    if((!$installed) -and ($noInstall -eq $false)){#only install if required
        $osArchitecture = (($osArchitecture -replace "x86","_32") -replace "x64","_64")
        $url = "https://download.microsoft.com/download/5/0/1/5017D39B-8E29-48C8-91A8-8D0E4968E6D4/en/msoidcli"+$osArchitecture+".msi"
        DownloadAndInstall -url $url -FriendlyName "MicrosoftAzureActiveDirectoryModule.msi"
        #extra steps required
        $powershellArgs = '-c "Install-Module MSOnline -Force"'
        Start-Process "$PsHome\PowerShell.exe" -Verb RunAs -ArgumentList $powershellArgs -PassThru -Wait
        #end extra steps
        VerifyIfMicrosoftAzureActiveDirectoryModuleIsInstalled -osArchitecture $osArchitecture -noInstall $true
    }
    if($noInstall -and !$installed){
        PrintMessageAndExit -ErrorMessage "Failed to install Microsoft Azure Active Directory Module" -ReturnCode -1
    }
}

##
# Check if sharepoint is installed
##
function VerifyIfSkypeForBusinessOnlineIsInstalled($osArchitecture, $noInstall){
    $installed = (Get-Command New-CsOnlineSession -errorAction SilentlyContinue) -or (IsModuleAvailable -name 'SkypeOnlineConnector')
    if((!$installed) -and ($noInstall -eq $false)){#only install if required
        $url = "https://download.microsoft.com/download/2/0/5/2050B39B-4DA5-48E0-B768-583533B42C3B/SkypeOnlinePowerShell.Exe"
        DownloadAndInstallExe -url $url -FriendlyName "SkypeOnlinePowerShell.Exe"
        VerifyIfSkypeForBusinessOnlineIsInstalled -osArchitecture $osArchitecture -noInstall $true
    }
    if($noInstall -and !$installed){
        PrintMessageAndExit -ErrorMessage "Failed to install Skype Online PowerShell" -ReturnCode -1
    }
}

##
# Checks if the required software for the toolbox is installed
##
function VerifyRequiredSoftware($osArchitecture){
    VerifyIfSharePointConnectionSoftwareIsInstalled -osArchitecture $osArchitecture -noInstall $false
    VerifyIfMicrosoftAzureActiveDirectoryModuleIsInstalled -osArchitecture $osArchitecture -noInstall $false
    VerifyIfSkypeForBusinessOnlineIsInstalled -osArchitecture $osArchitecture -noInstall $false
}

#
# Finds all applicable dependency packages according to OS architecture, and
# installs the developer package with its dependencies.  The expected layout
# of dependencies is:
#
# <current dir>
#   \generated
#     \Dependencies
#         <Architecture neutral dependencies>.appx
#         \x86
#             <x86 dependencies>.appx
#         \x64
#             <x64 dependencies>.appx
#         \arm
#             <arm dependencies>.appx
#
function InstallPackageWithDependencies
{
    $DeveloperPackagePath = (Get-ChildItem -Directory | Where-Object {Get-ChildItem $_ | Where-Object {($_.Name -like '*.appxbundle') -and ($_.Mode -NotMatch "d")}}).FullName
    $DependencyPackagesDir = (Join-Path $DeveloperPackagePath "Dependencies")
    $DependencyPackages = @()
    if (Test-Path $DependencyPackagesDir)
    {
        # Get architecture-neutral dependencies
        $DependencyPackages += Get-ChildItem (Join-Path $DependencyPackagesDir "*.appx") | Where-Object { $_.Mode -NotMatch "d" }

        # Get architecture-specific dependencies
        if (($Env:Processor_Architecture -eq "x86" -or $Env:Processor_Architecture -eq "amd64") -and (Test-Path (Join-Path $DependencyPackagesDir "x86")))
        {
            $DependencyPackages += Get-ChildItem (Join-Path $DependencyPackagesDir "x86\*.appx") | Where-Object { $_.Mode -NotMatch "d" }
        }
        if (($Env:Processor_Architecture -eq "amd64") -and (Test-Path (Join-Path $DependencyPackagesDir "x64")))
        {
            $DependencyPackages += Get-ChildItem (Join-Path $DependencyPackagesDir "x64\*.appx") | Where-Object { $_.Mode -NotMatch "d" }
        }
        if (($Env:Processor_Architecture -eq "arm") -and (Test-Path (Join-Path $DependencyPackagesDir "arm")))
        {
            $DependencyPackages += Get-ChildItem (Join-Path $DependencyPackagesDir "arm\*.appx") | Where-Object { $_.Mode -NotMatch "d" }
        }
    }
    Write-Host $UiStrings.InstallingPackage

    $AddPackageSucceeded = $False
    try
    {
        if ($DependencyPackages.FullName.Count -gt 0)
        {
            Write-Host "DependenciesFound"
            $DependencyPackages.FullName
            Add-AppxPackage -Path $DeveloperPackagePath -DependencyPath $DependencyPackages.FullName -ForceApplicationShutdown
        }
        else
        {
            Add-AppxPackage -Path $DeveloperPackagePath -ForceApplicationShutdown
        }
        $AddPackageSucceeded = $?
    }
    catch
    {
        $Error[0] # Dump details about the last error
    }

    if (!$AddPackageSucceeded)
    {
        if ($NeedInstallCertificate)
        {
            PrintMessageAndExit "Certificate missing" -ReturnCode -1
        }
        else
        {
            PrintMessageAndExit "Package installation failed" -ReturnCode -1
        }
    }
}

##
# Request the user if a reboot is allowed
##
function PromptForReboot(){
    $yes = New-Object System.Management.Automation.Host.ChoiceDescription '&Yes'
    $no = New-Object System.Management.Automation.Host.ChoiceDescription '&No'
    $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
    return $host.ui.PromptForChoice('Reboot?', 'Your system should be rebooted to complete the installation. Do you want to reboot now?', $options, 0)
}

##
# Executed as elevated
##
function DoElevated(){
    if((Get-ExecutionPolicy) -eq "Restricted"){
        Set-ExecutionPolicy RemoteSigned #required for the O365 commandlets
    }
    #enable sideloading
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\AppModelUnlock" /t REG_DWORD /f /v "AllowAllTrustedApps" /d "1"
    #install certificate
    InstallCertificate -CertificatePath $CertificatePath
}

##
# Execution with standard privileges
#
# Contains the main logic
##
function DoStandardOperations(){
    Write-Host "Verifying OS compatibility"
    VerifyDeviceCompatibility
    $OSArchitecture = GetOsArchitecture
    Write-Host "Verifying required software"
    VerifyRequiredSoftware($OSArchitecture)
    #get cert
    $certPath = (Get-ChildItem -Depth 1 | Where-Object {$_.FullName -like '*.cer'}).FullName
    #validate cert
    Write-Host "Verifying Settler certificate"
    ValidateCertificateFormat -FilePath $certPath
    #execute admin parts    
    RequestContinueAsElevated
    #install the app
    Write-Host "Starting the app installer"
    InstallPackageWithDependencies
    #request reboot
    if(PromptForReboot -eq 0){
        Restart-Computer
    }
}

## 
# Main script entry point
##
if ($Elevated)
{
    if($null -eq $CertificatePath){
        DoElevatedOperations
    }else{
        PrintMessageAndExit -ErrorMessage "No certificate provided" -ReturnCode -2
    }
}
else
{
    DoStandardOperations
}