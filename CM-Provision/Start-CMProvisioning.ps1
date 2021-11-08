<#
    .SYNOPSIS
        Starts MECM provisioning
    .DESCRIPTION
        Mainly intended to be called by an Azure custom script extension. This script will start to provision
        MECM on a virtual machine. First downloads a set of source files and the Ensono.MECM PowerShell
        module, imports that module and invokes the installation from it.
    .PARAMETER SourceURL
        (Optional) The URL to download a zip file that contains the content and scripts required for the install.
    .PARAMETER LocalPath
        (Optional) The local folder path to sync the source files to for install, defaults to C:\CM-Install.
#>
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $SourceURL = 'https://dsstorinfgen.blob.core.windows.net/mecmcontent/MECM.zip',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ModuleURL = 'https://raw.githubusercontent.com/domcsshaw/Automation-Public/main/CM-Module',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ControlURL = 'https://raw.githubusercontent.com/domcsshaw/Automation-Public/main/CM-Control',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $EnvironmentRef,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $LocalPath = "$env:SystemDrive\CM-Install"
)

# Create a local folder if it doesn't exist already
if (!(Test-Path -Path $LocalPath)) {
    [void](New-Item -Path $LocalPath -ItemType Directory)
}

# Download the content file
Start-BitsTransfer -Source $SourceURL -Destination "$LocalPath\MECM.zip"

# Extract the contents
Expand-Archive -Path "$LocalPath\MECM.zip" -DestinationPath $LocalPath

# Update the module files - newer versions may be in Automation-Public
Invoke-WebRequest -Uri "${ModuleURL}/Ensono.MECM.psd1" -OutFile "$LocalPath\Module\Ensono.MECM.psd1"
Invoke-WebRequest -Uri "${ModuleURL}/Ensono.MECM.psm1" -OutFile "$LocalPath\Module\Ensono.MECM.psm1"

# If EnvironmentRef is specified overwrite the control file with the correct one from Automation-Public
if ($EnvironmentRef) {
    Invoke-WebRequest -Uri "${ControlURL}/${EnvironmentRef}/control.json" -OutFile "$LocalPath\Module\control.json"
}

# Import the MECM module
Import-Module -Name "$LocalPath\Module\Ensono.MECM.psd1"

# Add a scheduled task that will start the install
$ScriptCmd = "& {Import-Module '$LocalPath\Module\Ensono.MECM.psd1'; Install-MECM -Mode Full}"
Add-InstallTask -TaskName 'Start-CMProvisioning-T1' `
    -DelayedTask `
    -DelayMinutes 5 `
    -ActionArgument "-Command $ScriptCmd" `
    -TaskDescription 'Installs MECM - phase 1 - pre-reqs, features, SQL Server'
