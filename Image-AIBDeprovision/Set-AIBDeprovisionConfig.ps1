param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ContentRoot = 'https://raw.githubusercontent.com/domcsshaw/Automation-Public/main/Image-AIBDeprovision/',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $PSFile = 'DeprovisioningScript.ps1',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $UnattendFile = 'Unattend.xml',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $CacheFolder = "$env:ProgramData\Ensono"
)

# Check to see if the local cache directory is present
if (!(Test-Path -Path $CacheFolder)) {
    # Create the local cache directory
    New-Item -ItemType Directory $CacheFolder -Force -Confirm:$false
}

# Check to see if the cache logs directory exists
if (!(Test-Path -Path "$CacheFolder\Logs")) {
    # Create the local cache directory
    New-Item -ItemType Directory "$CacheFolder\Logs" -Force -Confirm:$false
}

# Start transcript and keep history
Start-Transcript -Path "$CacheFolder\Logs\Set-AIBDeprovisionConfig.log" -Append

# Download and replace custom deprovisioning script
if (Test-Path "C:\$PSFile") {
    Remove-Item "C:\$PSFile" -Force
    Write-Host "Original file: C:\$PSFile deleted"
}
Write-Host "Downloading file: $PSFile"
Invoke-WebRequest -Uri "${ContentRoot}${PSFile}" -OutFile "C:\$PSFile"
Write-Host "File downloaded to: C:\$PSFile"

# Download custom unattend answer file
Write-Host "Downloading file: $UnattendFile"
Invoke-WebRequest -Uri "${ContentRoot}${UnattendFile}" -OutFile "${CacheFolder}\${UnattendFile}"
Write-Host "File downloaded to: ${CacheFolder}\${UnattendFile}"

Stop-Transcript