
param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ContentRoot = 'https://dsstorinfgen.blob.core.windows.net/imagecontent/',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string[]]
    $ContentFiles = 'LangContent-en-gb',

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
Start-Transcript -Path "$CacheFolder\Logs\Install-LangContent.log" -Append

# Disable language pack cleanup task
Write-Host "Disabling language pack cleanup task"
Disable-ScheduledTask -TaskPath "\Microsoft\Windows\AppxDeploymentClient\" -TaskName "Pre-staged app cleanup"

# Download and process lnaguage content
foreach ($File in $ContentFiles) {

    # Download file
    Write-Host "Downloading file: ${File}.zip"
    Invoke-WebRequest -Uri "${ContentRoot}${File}.zip" -OutFile "${CacheFolder}\${File}.zip"
    Write-Host "File downloaded to: ${CacheFolder}\${File}.zip"

    # Extract file
    Write-Host "Extracting file: ${File}.zip"
    Expand-Archive -Path "${CacheFolder}\${File}.zip" -DestinationPath "$CacheFolder"
    Write-Host "File extracted to: ${CacheFolder}\${File}.zip"

    # Attempt to install LXPs from any sub-directories
    $LXPDirs = Get-ChildItem -Path "$CacheFolder\$File" -Directory
    foreach ($LXPDir in $LXPDirs) {
        $AppX = (Get-ChildItem -Path "$($LXPDir.FullName)\*.appx")[0]
        Add-AppxProvisionedPackage -Online -PackagePath $AppX.FullName -LicensePath "$($LXPDir.FullName)\License.xml"
        Write-Host "Installed AppX package: $AppX"
    }

    # Attempt to install LP cab files
    $LPFiles = Get-ChildItem -Path "$CacheFolder\$File" -Recurse -Include "*Client-Language*"
    foreach ($LPFile in $LPFiles) {
        Add-WindowsPackage -Online -PackagePath $LPFile
        Write-Host "Installed package: $LPFile"
    }

    # Attempt to install LP basic cab files
    $LPBasicFiles = Get-ChildItem -Path "$CacheFolder\$File" -Recurse -Include "*LanguageFeatures-Basic*"
    foreach ($LPFile in $LPBasicFiles) {
        Add-WindowsPackage -Online -PackagePath $LPFile
        Write-Host "Installed package: $LPFile"
    }

    # Attempt to install any remaining language feature cab files
    $LPPkgFiles = Get-ChildItem -Path "$CacheFolder\$File" -Recurse -Include "*LanguageFeatures*" -Exclude "*LanguageFeatures-Basic*"
    foreach ($LPFile in $LPPkgFiles) {
        Add-WindowsPackage -Online -PackagePath $LPFile
        Write-Host "Installed package: $LPFile"
    }

    # Attempt to install any remaining cab files
    $PkgFiles = Get-ChildItem -Path "$CacheFolder\$File" -Recurse -Include "*.cab" -Exclude "*Client-Language*","*LanguageFeatures*"
    foreach ($LPFile in $PkgFiles) {
        Add-WindowsPackage -Online -PackagePath $LPFile
        Write-Host "Installed package: $LPFile"
    }

    Write-Host "Installed features from content file: ${File}.zip"
}

Write-Host ''
Stop-Transcript