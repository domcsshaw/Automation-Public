param (
    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $ContentRoot = 'https://dsstorinfgen.blob.core.windows.net/imagecontent/',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $File = "LogViewer.zip",

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]
    $CacheFolder = "$env:ProgramData\Ensono"
)

# Check to see if the local cache directory is present
If ((Test-Path -Path $CacheFolder) -eq $false) {
    # Create the local cache directory
    New-Item -ItemType Directory $CacheFolder -Force -Confirm:$false
}

# Start download of the source files from Azure Blob to the network cache location
Invoke-WebRequest -Uri "${ContentRoot}${File}" -OutFile "${CacheFolder}\${File}"
Write-Host 'Downloaded Zip file ...'

# Extract the install binaries
Expand-Archive -Path "${CacheFolder}\${File}" -DestinationPath $CacheFolder -Force
Write-Host 'Extracted Zip file ...'