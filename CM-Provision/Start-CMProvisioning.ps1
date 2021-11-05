<#
    .SYNOPSIS
        Starts MECM provisioning
    .DESCRIPTION
        Mainly intended to be called by an Azure custom script extension. This script will start to provision
        ConfigMgr on a virtual machine. First downloads a set of source files and the Ensono.MECM PowerShell
        module, imports that module and invokes the installation from it.
    .PARAMETER SourceURL
        The URL to download a zip file that contains the content and scripts required for the install.
    .PARAMETER LocalPath
        (Optional) The local folder path to sync the source files to for install, defaults to C:\CM-Install.
#>
param (
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]
    $SourceURL = 'https://dsstorinfgen.blob.core.windows.net/mecmcontent/MECM.zip',

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

# Robocopy the source files
# & Robocopy.exe $SourcePath $LocalPath /MIR /LOG:$LocalPath\Robocopy.log

# Import the DS.ConfigMgr module
Import-Module -Name "$LocalPath\Module\Ensono.MECM.psd1"

# Add a scheduled task that will start the install
Add-InstallTask -TaskName 'Start-CMProvisioning-T1' `
    -DelayedTask `
    -DelayMinutes 5 `
    -ActionArgument "& {Import-Module '$LocalPath\Module\DS.ConfigMgr.psd1'; Install-MECM -Mode Full}" `
    -TaskDescription 'Installs MECM - phase 1 - pre-reqs, features, SQL Server'
