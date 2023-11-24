
param (
    [Parameter(Mandatory=$false, HelpMessage="Specify files name with the appx packages to be removed.")]
    [ValidateNotNullOrEmpty()]
    [string[]]$AppsToRemove = @(
        'Microsoft.BingNews',
        'Microsoft.BingWeather',
        'Microsoft.XboxGameOverlay', 
        'Microsoft.XboxGamingOverlay',
        'Microsoft.XboxIdentityProvider',
        'Microsoft.XboxSpeechToTextOverlay',
        'Microsoft.XboxApp',
        'Microsoft.Xbox.TCUI',
        'Microsoft.GamingApp',
        'Microsoft.MicrosoftSolitaireCollection',
        'Microsoft.SkypeApp',
        'Microsoft.People',
        'Microsoft.ZuneMusic',
        'microsoft.windowscommunicationsapps'
    ),
    
    [Parameter(Mandatory=$false, HelpMessage='The local (ProgramData) folder for downloads and logs.')]
    [ValidateNotNullOrEmpty()]
    [string]$CacheFolder = "$env:ProgramData\Ensono"
)

begin {
    # Functions
    function Write-LogEntry {
	    param(
		    [parameter(Mandatory=$true, HelpMessage="Value added to the log file.")]
		    [ValidateNotNullOrEmpty()]
		    [string]$Value,

		    [parameter(Mandatory=$true, HelpMessage="Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
		    [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
		    [string]$Severity,

		    [parameter(Mandatory=$false, HelpMessage="Name of the log file that the entry will be written to.")]
		    [ValidateNotNullOrEmpty()]
		    [string]$FileName = 'Remove-Appx.log'
	    )

	    # Determine log file location
        $LogFilePath = Join-Path -Path "$CacheFolder\Logs" -ChildPath $FileName

        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format 'HH:mm:ss.fff'), '+', (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))

        # Construct date for log entry
        $Date = (Get-Date -Format 'MM-dd-yyyy')

        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""WindowsOptionalFeatures"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"

	    # Add value to log file
        try {
	        Add-Content -Value $LogText -LiteralPath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message 'Unable to append log entry to log file'
        }
    }

    function Remove-AppxApp {
        param (
		    [parameter(Mandatory=$true, HelpMessage="Name of the AppX package or app to remove.")]
		    [ValidateNotNullOrEmpty()]
		    [string]$AppName
        )

        # Attempt to resolve the app name to an installed package
        $AppName = $AppName.TrimEnd()
        $PackageFullName = (Get-AppxPackage $AppName).PackageFullName
        $ProPackageFullName = (Get-AppxProvisionedPackage -Online | Where-Object {$_.Displayname -eq $AppName}).PackageName

        if ($PackageFullName) {
            Write-LogEntry -Value "Removing Package: $AppName" -Severity 1
            Remove-AppxPackage -Package $PackageFullName
        }
        else {
            Write-LogEntry -Value "Unable to find package: $AppName" -Severity 2
        }

        If ($ProPackageFullName) {
            Write-LogEntry -Value "Removing Provisioned Package: $ProPackageFullName" -Severity 1
            Remove-AppxProvisionedPackage -Online -PackageName $ProPackageFullName
        }
        else {
            Write-LogEntry -Value "Unable to find provisioned package: $App" -Severity 2
        }
    }

    # Check to see if the local cache directory exists
    If (!(Test-Path -Path $CacheFolder)) {
        # Create the local cache directory
        New-Item -ItemType Directory $CacheFolder -Force -Confirm:$false
    }

    # Check to see if the cache logs directory exists
    If (!(Test-Path -Path "$CacheFolder\Logs")) {
        # Create the local cache directory
        New-Item -ItemType Directory "$CacheFolder\Logs" -Force -Confirm:$false
    }
}

process {
    # Add required registry key to turn off suggested and promoted apps in the start menu
    $RegPath = 'HKLM:\Software\Policies\Microsoft\Windows\CloudContent'
    $RegKeyName = 'DisableWindowsConsumerFeatures'
    $RegKeyValue = 1
    If(!(Test-Path $RegPath)) {
        Write-LogEntry -Value 'Creating HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent registry key' -Severity 1
        New-Item -Path $RegPath -Force
    }

    # Turn off suggested and promoted apps in the start menu
    Write-LogEntry -Value "Adding HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\CloudContent\$Name as DWord with value $value" -Severity 1
    New-ItemProperty -Path $RegPath -Name $RegKeyName -Value $RegKeyValue -PropertyType DWORD -Force

    # Remove AppX packages
    foreach ($App in $AppsToRemove) {
        Remove-AppxApp -AppName $App
    }

    # Write end of log file
    Write-LogEntry -Value 'Completed removing builtin applications' -Severity 1
}
