
# Module initialization ************************************************************************************************************************
# This code runs when the module is imported into the PS session

# Set error preference to stop execution
$ErrorActionPreference = "Stop"

# Root path
$RootPath = Split-Path -Path $PSScriptRoot -Parent

# Log file variables
$LogPath = "${RootPath}\LogFiles"
$LogFile = "${LogPath}\install-mecm.log"

# Source path
$SourcePath = "${RootPath}\Source"

# Log files folder test + create if not found
if (!(Test-Path -Path $LogPath)) {
    [void](New-Item -Path $RootPath -Name LogFiles -ItemType Directory)
}

# Log file test, create if not found
if (!(Test-Path $LogFile)) {
    [void](New-Item -Path $LogFile -ItemType File)
}

# Read JSON parameters
$Control = Get-Content -Path "${PSScriptRoot}\control.json" | ConvertFrom-Json

# End of module initialization *****************************************************************************************************************

# Internal functions ***************************************************************************************************************************

<#
    .SYNOPSIS
        Runs at every entry point to the module, writes out the module version and reloads 'control' file.
#>
function Initialize-Session {
    [cmdletbinding()]
    param ()

    # Set error preference to stop execution
    $ErrorActionPreference = "Stop"

    # Write some info to the console
    $Version = (Get-Module -Name Ensono.MECM).Version.ToString()
    Write-LogInfo -Message "Ensono.MECM Powershell module, version: $Version" -Severity 1

    # Read JSON parameters
    $Control = Get-Content -Path "${PSScriptRoot}\control.json" | ConvertFrom-Json
    Write-LogInfo -Message "Reloaded control file from: ${PSScriptRoot}" -Severity 1
    $Control
}

<#
    .SYNOPSIS
        Writes information, warnings and errors to the log file and the console.
    .DESCRIPTION
        This function writes messages to the module log file (root\LogFiles\install-mecm.log) and also to the
        PowerShell console window, the messages are either informational, warning or errors.
    .PARAMETER Message
        The message to write to the log and command line.
    .PARAMETER Severity
        Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.
    .PARAMETER BlankLine
        Switch to specify that a blank spacer line is written to the console after this message.
#>
function Write-LogInfo {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Message,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [ValidateSet('1', '2', '3')]
        [string]
        $Severity,

        [Parameter(Mandatory = $false)]
        [switch]
        $BlankLine = $false
    )

    # Construct time stamp for log entry
    $Time = -join @((Get-Date -Format 'HH:mm:ss.fff'), '+', (Get-CimInstance -ClassName Win32_TimeZone | Select-Object -ExpandProperty Bias))
    # Construct date for log entry
    $Date = (Get-Date -Format 'MM-dd-yyyy')
    # Construct context for log entry
    $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
    # Construct final log entry
    $LogText = "<![LOG[$($Message)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""Install-MECM"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"

    # Add value to log file
    Add-Content -Path $LogFile -Value $LogText

    # Write message to output
    switch ($Severity) {
        1 {Write-Host -Object $Message}
        2 {Write-Warning -Message $Message}
        3 {throw $Message}
    }

    # Write a blank line, if required
    if ($BlankLine) {
        Write-Host ''
    }
}

<#
    .SYNOPSIS
        Expands a given 7z archive file to a target folder.
    .PARAMETER ArchivePath
        The path and filename of a 7z file to expand.
    .PARAMETER ExpandedPath
        The folder file path to expand into.
#>
function Expand-7zArchive {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ArchivePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ExpandedPath
    )

    # Target folder exists - delete it to ensure clean unzip
    if (Test-Path -Path $ExpandedPath) {
        Remove-Item -Path $ExpandedPath -Recurse -Force
        Write-LogInfo -Message "Deleted existing folder ($ExpandedPath)" -Severity 1
    }

    # Create target folder
    [void](New-Item -Path $ExpandedPath -ItemType Directory)
    Write-LogInfo -Message "Created new folder ($ExpandedPath)" -Severity 1

    # Unzip archive to target folder
    try {
        Write-LogInfo -Message "Attempting to unzip file: $ArchivePath" -Severity 1
        & "$SourcePath\7z\7za.exe" x -o"$ExpandedPath" "$ArchivePath"
    }
    catch {
        Write-LogInfo -Message `
            "Error unzipping: ${ArchivePath}: $($PSItem.Exception.Message)" `
            -Severity 3
    }

    Write-LogInfo "Completed unzip operation of $ArchivePath" -Severity 1 -BlankLine
}

<#
    .SYNOPSIS
        Checks an input string for formatting to use as a local drive during the install process.
    .PARAMETER DriveParam
        The drive parameter (as a string) to check for formatting.
#>
function Test-DriveParameter {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $DriveParam
    )

    if (($DriveParam.Length -ne 2) -or (!($DriveParam.EndsWith(":")))) {
        Write-LogInfo -Message `
            "Validation Error: drive parameter ($DriveParam) not formatted correctly - check control.json" `
            -Severity 3
    }
    else {
        Write-LogInfo -Message "Drive parameter correctly formatted ($DriveParam)" -Severity 1
    }
}

<#
    .SYNOPSIS
        Validates input parameters specific to the install of MECM specifically, not other components/modules.
#>
function Confirm-CMValues {
    [cmdletbinding()]
    param ()

    # Check site code length
    if ($Control.SiteCode.Length -ne 3) {
        Write-LogInfo -Message `
            'Validation Error: Site Code not 3 characters - check control.json' `
            -Severity 3
    }
    else {
        Write-LogInfo -Message "Site code for install is: $($Control.SiteCode)" -Severity 1
    }

    # Check a site name has been specified
    if ($Control.SiteName -eq '') {
        Write-LogInfo -Message 'Validation Error: Site name not specified - check control.json' -Severity 3
    }
    else {
        Write-LogInfo -Message "Site name for install is: $($Control.SiteName)" -Severity 1
    }

    # Check formatting of drive letter params
    Write-LogInfo -Message "Install drive set to: $($Control.InstallDrive)" -Severity 1
    Test-DriveParameter -DriveParam $Control.InstallDrive
    foreach ($ContentDrive in $Control.ContentDrives) {
        Write-LogInfo -Message "Content drive: $ContentDrive" -Severity 1
        Test-DriveParameter -DriveParam $ContentDrive
    }

    Write-LogInfo -Message 'Validation of MECM-specific control values completed' -Severity 1
}

<#
    .SYNOPSIS
        Validates input parameters specific to the install of SQL Server locally.
#>
function Confirm-SQLLocalValues {
    [cmdletbinding()]
    param ()

    begin {
        # Retrieve and validate SQL parameters from JSON - first get property names
        $PrmNames = $Control | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    }

    process {
        # Loop for validation of SQL parameters
        $SQLPrmNames = $PrmNames | Select-String -Pattern 'SQL*'
        foreach ($SQLPrm in $SQLPrmNames) {
            $SQLVal = $Control.$SQLPrm
            # Drives
            if ($SQLPrm -like 'SQLDr*') {
                Write-LogInfo -Message "SQL drive parameter ($SQLPrm) set to: $SQLVal" -Severity 1
                Test-DriveParameter -DriveParam $SQLVal
            }
            # Service accounts
            if ($SQLPrm -like 'SQLSv*') {
                if ($SQLVal -eq '') {
                    Write-LogInfo -Message `
                        "SQL service account parameter ($SQLPrm) not set, will use default" `
                        -Severity 2
                }
                else {
                    Write-LogInfo -Message `
                        "SQL service account parameter ($SQLPrm) set to: $SQLVal" `
                        -Severity 1
                }
            }
            # SysAdmin accounts
            if ($SQLPrm -like 'SQLSA*') {
                if ($SQLVal -eq '') {
                    Write-LogInfo -Message `
                        "Validation Error: SQL sysadmin account parameter ($SQLPrm) not set - check control.json" `
                        -Severity 3
                }
                else {
                    Write-LogInfo -Message `
                        "SQL service account parameter ($SQLPrm) set to: $SQLVal" `
                        -Severity 1
                }
            }
            # TempDB settings
            if ($SQLPrm -like 'SQLTmp*') {
                if ($SQLVal -is [int]) {
                    Write-LogInfo -Message "SQL TempDB parameter ($SQLPrm) set to: $SQLVal" -Severity 1
                }
                else {
                    Write-LogInfo -Message `
                        "Validation Error: SQL TempDB parameter ($SQLPrm) not set to an integer - check control.json" `
                        -Severity 3
                }
            }
        }
    }

    end {
        # For service accounts check for a pw if the account is specified
        if (($Control.SQLSvEngAc -ne '') -and ($Control.SQLSvEngPw -eq '')) {
            Write-LogInfo -Message `
                'Validation Error: SQL Engine account specified but no password set - check control.json' `
                -Severity 3
        }
        if (($Control.SQLSvAgtAc -ne '') -and ($Control.SQLSvAgtPw -eq '')) {
            Write-LogInfo -Message `
                'Validation Error: SQL Agent account specified but no password set - check control.json' `
                -Severity 3
        }

        Write-LogInfo -Message 'Validation of SQL-specific control values completed' -Severity 1
    }
}

<#
    .SYNOPSIS
        Validates input parameters specific to of SQL Server as a remote service.
#>
function Confirm-SQLRemoteValues {
    [cmdletbinding()]
    param ()

    # Check SQL Server is specified
    if ($Control.SQLServer -eq '') {
        Write-LogInfo -Message `
            'Validation Error: SQL Server not specified for remote SQL - check control.json' `
            -Severity 3
    }
    else {
        Write-LogInfo -Message "Remote SQL Server name for install is: $($Control.SQLServer)" -Severity 1
    }
}

<#
    .SYNOPSIS
        Installs required Windows ADK features.
    .PARAMETER InstallDrive
        String to specify the drive to install ADK features to.
#>
function Install-ADK {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $InstallDrive
    )

    # Test the install drive parameter
    Test-DriveParameter -DriveParam $InstallDrive

    # Paths
    $ADKSourcePath = "$SourcePath\ADK\adksetup.exe"
    Write-LogInfo -Message "ADK source path is: $ADKSourcePath" -Severity 1
    $ADKWinPESourcePath = "$SourcePath\ADKWinPEAddons\adkwinpesetup.exe"
    Write-LogInfo -Message "ADK Win PE source path is: $ADKWinPESourcePath" -Severity 1
    $ADKInstallPath = "$InstallDrive\Program Files (x86)\Windows Kits\10"
    Write-LogInfo -Message "ADK install path is: $ADKInstallPath" -Severity 1

    # Check that setup files exist in the expected location
    if (Test-Path -Path $ADKSourcePath) {
        Write-LogInfo -Message 'ADK setup file found OK' -Severity 1            
    }
    else {
        Write-LogInfo -Message "Error: Cannot find ADK setup file at: $ADKSourcePath" -Severity 3
    }
    if (Test-Path -Path $ADKWinPESourcePath) {
        Write-LogInfo -Message 'ADK WinPE setup file found OK' -Severity 1
    }
    else {
        Write-LogInfo -Message "Error: Cannot find ADK WinPE setup file at: $ADKWinPESourcePath" -Severity 3
    }

    try {
        # ADK features to install
        $ADKFeatures = 'OptionId.DeploymentTools OptionId.UserStateMigrationTool'

        # Main ADK features
        Write-LogInfo -Message "Installing Windows ADK from $ADKSourcePath to $ADKInstallPath" -Severity 1
        Write-LogInfo -Message "ADK Features to install are: $ADKFeatures" -Severity 1
        $ADKArgs = @('/quiet', 
            "/features $ADKFeatures", 
            '/norestart', 
            "/installpath `"$ADKInstallPath`"", 
            '/ceip off')
        Write-LogInfo -Message "Command line arguments: $ADKArgs" -Severity 1

        # Start the installer, output the result
        $ADKResult = Start-Process -FilePath "$ADKSourcePath" -ArgumentList $ADKArgs -Wait -PassThru
        Write-LogInfo -Message "ADK install exit code: $($ADKResult.ExitCode)" -Severity 1
        
        # Process result
        if ($ADKResult.ExitCode -in 0, 1641, 3010) {
            Write-LogInfo -Message 'Successfully installed Windows ADK features' -Severity 1 -BlankLine
        }
        else {
            Write-LogInfo -Message 'Error installing Windows ADK features' -Severity 3
        }

        # ADK Win PE addon
        Write-LogInfo -Message `
            "Installing Windows ADK Win PE add-on from $ADKWinPESourcePath to $ADKInstallPath" `
            -Severity 1
        $ADKWinPEArgs = @('/quiet', 
            '/features +', 
            '/norestart', 
            "/installpath `"$ADKInstallPath`"", 
            '/ceip off')
        Write-LogInfo -Message "Command line arguments: $ADKWinPEArgs" -Severity 1

        # Start the installer, output the result
        $ADKWPEResult = Start-Process -FilePath "$ADKWinPESourcePath" `
            -ArgumentList $ADKWinPEArgs -Wait -PassThru
        Write-LogInfo -Message "ADK WinPE install exit code: $($ADKWPEResult.ExitCode)" -Severity 1

        # Process result
        if ($ADKWPEResult.ExitCode -in 0, 1641, 3010) {
            Write-LogInfo -Message 'Successfully installed Windows ADK WinPE feature' -Severity 1 -BlankLine
        }
        else {
            Write-LogInfo -Message 'Error installing Windows ADK WinPE feature' -Severity 3
        }
    }
    catch {
        Write-LogInfo -Message `
            "Error while installing Windows ADK: $($PSItem.Exception.Message)" `
            -Severity 3
    }

    Write-LogInfo -Message 'Windows ADK installation processing completed' -Severity 1
}

<#
    .SYNOPSIS
        Internal function that installs Windows features based on an input array of feature names.
    .PARAMETER Features
        A string array of features to be installed.
#>
function Install-Features {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Features
    )

    # Log feature set
    foreach ($Feature in $Features) {
        Write-LogInfo -Message "Windows feature to install: $Feature" -Severity 1
    }
    Write-Host ''

    # Loop to install features
    try {
        foreach ($Feature in $Features) {
            Write-LogInfo -Message "Installing Windows feature: $Feature" -Severity 1
            $Result = (Install-WindowsFeature -Name $Feature).ExitCode
            Write-LogInfo -Message "Install feature result was: $Result" -Severity 1 -BlankLine
        }
        Write-LogInfo -Message 'Successfully installed Windows feature set' -Severity 1
    }
    catch {
        Write-LogInfo -Message `
            "Error installing Windows pre-requisite features: $($PSItem.Exception.Message)" `
            -Severity 3
    }
}

<#
    .SYNOPSIS
        Enables and configures correct TempDB setup for Azure VMs.
    .DESCRIPTION
        This function configures the SQL TempDB for Azure VMs (i.e. move the TempDB to the Azure Temporary
        drive as recommended). This setup comprises a PS script that is copied locally, setting the SQL DB
        Engine service to manual startup and registering a scheduled task that will run at system startup and
        create the folder for the TempDB files and start the SQL service.
#>
function Enable-AzureTempDB {
    [cmdletbinding()]
    param ()

    Write-LogInfo -Message 'This is an Azure VM, setup TempDB...' -Severity 1 -BlankLine
    # Create C:\Scripts folder if it doesn't exist
    if (!(Test-Path 'C:\Scripts')) {
        [void](New-Item -Path 'C:\' -Name 'Scripts' -ItemType Directory)
        Write-LogInfo -Message 'Created new folder C:\Scripts' -Severity 1
    }

    # Copy SQL start up script
    Copy-Item -Path "$SourcePath\SQLTempDB\Start-SQL.ps1" -Destination 'C:\Scripts' -Force
    Write-LogInfo -Message 'Copied Start-SQL.ps1 to C:\Scripts' -Severity 1

    # Change startup type for SQL Service to manual
    Set-Service -Name 'MSSQLSERVER' -StartupType Manual
    Write-LogInfo -Message 'SQL Server service set to manual startup' -Severity 1

    # Add the task
    Add-InstallTask -TaskName 'Start-SQL' `
        -StartupTask `
        -ActionArgument "-File C:\Scripts\Start-SQL.ps1 -TempPath $($Control.AzureTempDrive)\SQLTempDB" `
        -TaskDescription 'Ensures SQLTempDB directory exists on D:\ and starts SQL db service'
}

<#
    .SYNOPSIS
        Initializes and formats data disks on Azure VMs
    .DESCRIPTION
        This function initializes, formats and assigns drive letters on all data disks attached to the local
        server, this is required for Azure VMs where the intention is to provision the VM and install all the
        software using automation. This function will only process RAW disks but will assume that disks
        should be initialized, formatted and assigned in LUN-attached order. It is therefore important that
        the config file drive letter assignments match the data disk order assigned to the VM in Azure.
#>
function Initialize-AzureDisks {
    [cmdletbinding()]
    param ()

    if (!$Control.DiskLayout) {
        # Nothing to do
        Write-LogInfo -Message 'Nothing found in DiskLayout, cannot initialize or format disks' -Severity 2
        return
    }

    Write-LogInfo -Message 'This is an Azure VM; initialize and format disks...' -Severity 1

    # There may be a CD-ROM attached if this is a new VM from a marketplace image; if so force it to Z:
    $CDDrive = Get-CimInstance -ClassName Win32_Volume -Filter "DriveType = 5"
    if ($CDDrive) {
        $CDDrive | Set-CimInstance -Property @{DriveLetter ='Z:'}
        Write-LogInfo -Message 'Found a CD-ROM drive; driver letter reassigned to Z:' -Severity 1
    }
    else {
        Write-LogInfo -Message 'No CD-ROM drive present, continuing...' -Severity 1
    }

    # Online and initialize disk LUNs
    foreach ($Disk in $Control.DiskLayout) {
        # We must assume since this is standard Azure VM that the disk number will be the data disk LUN no
        # plus 2 (OS = 0, Temp = 1) - e.g. LUN0 = disk 2, LUN1 = disk 3
        $DiskNo = $Disk.LUN + 2

        # Initialize / online the disk as GPT (default)
        try {
            Initialize-Disk -Number $DiskNo -ErrorAction Stop
            Write-LogInfo -Message "Disk no $DiskNo, (LUN$($Disk.LUN)) initialized" -Severity 1
        }
        catch {
            Write-LogInfo -Message `
                "Exception occurred initializing disk ${DiskNo}: $($PSItem.Exception.Message)" `
                -Severity 2
        }

        # Create volumes on this disk
        foreach ($Vol in $Disk.Volumes) {
            # Build the parameters for this partition/volume
            $VolParams = @{
                'DiskNumber' = $DiskNo
                'DriveLetter' = $Vol.Letter
            }
            if ($Vol.Size -ne '0') {
                # / 1 here 'forces' the type conversion - string to UInt64 (.Net does not understand the
                # PS-native xKB, xMB, xGB syntax)
                [UInt64]$VolumeSize = ($Vol.Size / 1)
                $VolParams.Add('Size', $VolumeSize)
            }
            else {
                $VolParams.Add('UseMaximumSize', $true)
            }

            # Attempt to create the partition and format it
            try {
                New-Partition @VolParams -ErrorAction Stop | `
                    Format-Volume -FileSystem $Vol.FS -NewFileSystemLabel $Vol.Label -ErrorAction Stop | `
                    Out-Null
                Write-LogInfo -Message `
                    "New volume created; drive letter: $($Vol.Letter):, size: $($Vol.Size), file system: $($Vol.FS)" `
                    -Severity 1
            }
            catch {
                Write-LogInfo -Message `
                    "Exception occurred creating and formatting volume: $($Vol.Letter): $($PSItem.Exception.Message)" `
                    -Severity 2
            }
        }
    }

    Write-LogInfo -Message 'Disk initialization and formatting complete' -Severity 1 -BlankLine
}

<#
    .SYNOPSIS
        Performs a non-query SQL command using the .Net SqlClient and returns the result
    .DESCRIPTION
        This function uses the .Net SqlClient to connect to a given SQL Server and run a non-query command.
        The connection to the server can either use integrated security (current user) or SQL authentication
        given a username and password.
    .PARAMETER Server
        The name of the SQL Server to connect to.
    .PARAMETER Database
        The name of the database to run the command against.
    .PARAMETER Username
        The username to pass to the SQL Server for login (ParameterSet - Not_Integrated).
    .PARAMETER Password
        The password (SecureString) to pass to the SQL Server for login (ParameterSet - Not_Integrated).
    .PARAMETER UseWindowsAuth
        A switch that determines whether to use integrated security with the logged in account to connect
        (ParameterSet - [Default] Integrated). Should always be set when integrated security is required.
    .PARAMETER Query
        The valid T-SQL command to run as a string.
    .PARAMETER Timeout
        (Optional) The query timeout value to pass to the server, default value is 0 (unlimited).
    .INPUTS
        System.String
        System.Int32
        System.Security.SecureString
    .OUTPUTS
        System.Int32
#>
function Invoke-SqlCmdNet() {
    [cmdletbinding(DefaultParameterSetName = 'Integrated')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('ServerInstance')]
        [string]
        $Server,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Database,

        [Parameter(Mandatory = $true,
            ParameterSetName = 'Not_Integrated')]
        [ValidateNotNullOrEmpty()]
        [string]
        $Username,

        [Parameter(Mandatory = $true, 
            ParameterSetName = 'Not_Integrated')]
        [ValidateNotNullOrEmpty()]
        [securestring]
        $Password,

        [Parameter(Mandatory = $false,
            ParameterSetName = 'Integrated')]
        [switch]
        $UseWindowsAuth = $false,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Query,

        [Parameter(Mandatory = $false)]
        [int]
        $Timeout = 0
    )

    # Build connection string
    $CnnStr = "Server=$Server; Database=$Database; "
    if ($PSCmdlet.ParameterSetName -eq 'Not_Integrated') {
        $CnnStr += "User ID=$Username; Password=$Password;"
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'Integrated') {
        $CnnStr += 'Trusted_Connection=Yes; Integrated Security=SSPI;'
    }

    # Connect to database
    $Cnn = New-Object System.Data.SqlClient.SqlConnection($CnnStr)
    $Cnn.Open()

    # Build SqlCommand object
    $Command = $Cnn.CreateCommand()
    $Command.CommandText = $Query
    $Command.CommandTimeout = $Timeout

    # Run SqlCommand - non-query
    try {
        $Result = $Command.ExecuteNonQuery()
    }
    catch {
        Write-LogInfo -Message `
            "Exception occurred running a SQL command: $($PSItem.Exception.Message)" `
            -Severity 3
    }
    finally {
        $Cnn.Close()
    }

    return $Result
}

<#
    .SYNOPSIS
        Performs a non-query SQL command using SQLCMD.exe and returns the result
    .DESCRIPTION
        This function uses the SQLCMD.exe command-line tool to connect to a given SQL Server and run a non-
        query command. The connection to the server must use integrated security but a PSCredential can be
        passed to specify the user account to 'run-as'.
    .PARAMETER Server
        The name of the SQL Server to connect to.
    .PARAMETER Database
        The name of the database to run the command against.
    .PARAMETER Query
        The valid T-SQL command to run as a string.
    .PARAMETER Credential
        (Optional) A PSCredential object to be used for the server connection, if not specified the logged in
        credentials will be used.
    .PARAMETER Timeout
        (Optional) The query timeout value to pass to the server, default value is 0 (unlimited).
    .INPUTS
        System.String
        System.Int32
        System.Management.Automation.PSCredential
    .OUTPUTS
        System.Diagnostics.Process
#>
function Invoke-SqlCmdExe {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [Alias('ServerInstance')]
        [string]
        $Server,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Database,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Query,
        
        [Parameter(Mandatory = $false)]
        [PSCredential]
        $Credential,

        [Parameter(Mandatory = $false)]
        [int]
        $Timeout = 0
    )

    # Array of common options for SQLCMD.exe
    $SQLCmdOps = @(
        "-S $Server",
        "-d $Database",
        "-Q `"$Query`""
    )

    # Add timeout option if specified
    if ($Timeout -gt 0) {
        $SQLCmdOps += "-t $Timeout"
    }

    # Hashtable of args for the process to be created
    $ProcArgs = @{
        FilePath = 'SQLCMD.exe'
        ArgumentList = $SQLCmdOps
        RedirectStandardOutput = "$LogPath\sqlcmd.txt"
        Wait = $true
        PassThru = $true
    }

    if ($Credential) {
        # Add the credential to the arg list
        $ProcArgs['Credential'] = $Credential 
    }

    # Run SQLCMD.exe with given parameters as a process
    try {
        $Result = Start-Process @ProcArgs
    }
    catch {
        Write-LogInfo -Message `
            "Exception occurred running a SQL command: $($PSItem.Exception.Message)" `
            -Severity 3
    }

    return $Result
}

<#
    .SYNOPSIS
        Sets a particular value in an ini file given the key or deletes all keys that contain a string
    .DESCRIPTION
        This function will set a value against the given key in an ini file or alternatively delete all keys
        that contain the value passed to the 'Key' parameter. The content of the ini file should be passed
        to the 'Content' parameter (as an object array). If the 'Value' parameter is omitted the function
        will delete content, else it will set the value.
    .PARAMETER Content
        The content of the ini file as an array of objects, the modified content will be returned.
    .PARAMETER Key
        A string for the ini key that will be set or deleted. For setting a value this needs to be an exact
        match for the ini file key, for deleting content any key that contains this string will be removed.
    .PARAMETER Value
        (Optional) A string that is the value to set in the ini file. If omitted keys will be deleted.
    .INPUTS
        System.Array
        System.String
    .OUTPUTS
        System.Array
#>
function Set-IniValue {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]
        $Content,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $true)]
        [string]
        $Key,

        [ValidateNotNullOrEmpty()]
        [Parameter(Mandatory = $false)]
        [string]
        $Value = $null
    )

    # If a value is passed, add the value to the key
    if ($Value) {
        $Content = $Content -replace "$Key=", "$Key=$Value"
        Write-LogInfo -Message "Ini value set to: $Key=$Value" -Severity 1
    }
    # If no value, delete the key from the content
    else {
        $Content = $Content | Where-Object {$_ -notmatch $Key}
        Write-LogInfo -Message "Ini value removed: $Key" -Severity 1
    }

    return $Content
}

<#
    .SYNOPSIS
        Installs the MECM primary site
    .DESCRIPTION
        This cmdlet will install a MECM primary site on the local server. No pre-requisites will be installed
        using this command. The SQLServer parameter in control.json should be used to specify the database
        server for this install.
#>
function Install-CMPrimarySite {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [bool]
        $LocalSql,

        [Parameter(Mandatory = $true)]
        [ValidateSet(2016, 2017, 2019)]
        [int]
        $SqlVersion
    )

    # Start MECM install processing
    Write-LogInfo -Message `
        'Starting Microsoft Endpoint Configuration Manager Primary Site install...' `
        -Severity 1 -BlankLine

    # Paths
    $CM7zPath = "$SourcePath\CM.7z"
    $CMSourcePath = "$SourcePath\CM\"

    # Check source file exists
    if (Test-Path -Path $CM7zPath) {
        Write-LogInfo -Message 'MECM 7z file found OK' -Severity 1
    }
    else {
        Write-LogInfo -Message "Error: Cannot find MECM 7z file at: $CM7zPath" -Severity 3
    }

    # Unpack SQL with 7-zip
    Expand-7zArchive -ArchivePath $CM7zPath -ExpandedPath $CMSourcePath

    # Set the path to MECM setup exe
    $CMSetupPath = "${CMSourcePath}SMSSETUP\BIN\X64\setup.exe"
    Write-LogInfo -Message "MECM setup file path: $CMSetupPath" -Severity 1

    # Set the path to MECM script file
    $CMScriptPath = "$SourcePath\CMScript\setup.ini"
    Write-LogInfo -Message "MECM install script path: $CMScriptPath" -Severity 1

    # Create the downloads directory, if it doesn't already exist
    if (!(Test-Path -Path "$($Control.InstallDrive)\Downloads")) {
        [void](New-Item -Path "$($Control.InstallDrive)\" -Name 'Downloads' -ItemType Directory)
    }

    # Get local computer FQDN - required for multiple install options
    $CompInfo = Get-ComputerInfo
    $CompFQDN = "$($CompInfo.CsName).$($CompInfo.CsDomain)"
    Write-LogInfo -Message "Retrieved fully-qualified hostname from local server: $CompFQDN" -Severity 1

    # Set variables for SQL so the CM DB can be created (we are assuming SQL is installed and available here)
    $SQLFQDN = $CompFQDN
    if (!$LocalSql) {$SQLFQDN = $Control.SQLServer}
    Write-LogInfo -Message "SQL Server for install is: $SQLFQDN" -Severity 1

    # Use the SQL version to determine the data and log file paths for DB files
    $SQLVerInstDir = ''
    switch ($SqlVersion) {
        2016 {$SQLVerInstDir = 'MSSQL13.MSSQLSERVER'}
        2017 {$SQLVerInstDir = 'MSSQL14.MSSQLSERVER'}
        2019 {$SQLVerInstDir = 'MSSQL15.MSSQLSERVER'}
    }
    $SQLDataFilePath = "$($Control.SQLDrData)\Program Files\Microsoft SQL Server\$SQLVerInstDir\MSSQL\DATA"
    $SQLLogFilePath = "$($Control.SQLDrLog)\Program Files\Microsoft SQL Server\$SQLVerInstDir\MSSQL\DATA"

    # Run SQL commands to pre-create the CM database here
    Write-LogInfo -Message "Pre-creating the MECM database" -Severity 1
    $SQLCreateDBCmd = "CREATE DATABASE CM_$($Control.SiteCode)
    ON 
    PRIMARY 
        (NAME = CM_$($Control.SiteCode)_1, 
        FILENAME = '${SQLDataFilePath}\CM_$($Control.SiteCode)_1.mdf', 
        SIZE = $($Control.SQLCMDBFileSize), 
        MAXSIZE = Unlimited, 
        FILEGROWTH = $($Control.SQLCMDBFileGrw))"

    # For multiple data files add these to the query statement
    for ($i = 2; $i -le $Control.SQLCMDBFiles; $i++) {
        $SQLCreateDBCmd += ", 
        (NAME = CM_$($Control.SiteCode)_$i, 
        FILENAME = '${SQLDataFilePath}\CM_$($Control.SiteCode)_$i.mdf',
        SIZE = $($Control.SQLCMDBFileSize), 
        MAXSIZE = Unlimited, 
        FILEGROWTH = $($Control.SQLCMDBFileGrw))"
    }

    # Add the log file to the query statement
    $SQLCreateDBCmd += "
    LOG ON
        (NAME = CM_$($Control.SiteCode)_log, 
        FILENAME = '${SQLLogFilePath}\CM_$($Control.SiteCode).ldf',
        SIZE = $($Control.SQLCMDBLogFileSize), 
        MAXSIZE = $($Control.SQLCMDBLogFileSize),
        FILEGROWTH = $($Control.SQLCMDBLogFileGrw))"

    # Write out the full T-SQL statement
    Write-LogInfo -Message "Create DB command will be:" -Severity 1
    Write-LogInfo -Message "$SQLCreateDBCmd" -Severity 1

    # Set PSCredential object to 'Empty' credential - will be used later to initiate the MECM install but may
    # be overwritten in the next section if this code is running in SYSTEM context.
    $CMAdmCred = [System.Management.Automation.PSCredential]::Empty

    # Check user context - if we are running as SYSTEM we will have to run the T-SQL command as a user
    # because SYSTEM does not have permissions to create databases by default.
    if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        Write-LogInfo -Message 'Process is running under SYSTEM account' -Severity 1
        # Attempt to read in admin password (should have been passed in via the bootstrap script) from file
        if (Test-Path "$PSScriptRoot\admin.txt") {
            $CMAdmPw = Get-Content -Path "$PSScriptRoot\admin.txt" |
                ConvertTo-SecureString
            Write-LogInfo -Message "Retrived encrypted CM admin password from file" -Severity 1
        }
        else {
            Write-LogInfo -Message "Cannot find encrypted CM admin password file" -Severity 3
        }

        # Create a PSCredential object from the above password and account specified in control
        $CMAdmCred = New-Object System.Management.Automation.PSCredential($Control.CMAdminAc, $CMAdmPw)

        # Run the SQL command that was built above using the Invoke-SqlCmdExe function which allows us to
        # pass credentials in because it executes commands using SQLCMD.exe in a separate process.
        Write-LogInfo -Message 'Running create DB command using SQLCMD.exe' -Severity 1
        $SQLCreateDBResult = Invoke-SqlCmdExe -Server $SQLFQDN `
            -Database 'master' `
            -Query $SQLCreateDBCmd `
            -Credential $CMAdmCred
        Write-LogInfo -Message `
            "Create DB command (SQLCMD.exe process) result was: $SQLCreateDBResult" `
            -Severity 1
    }
    else {
        # Run the SQL command using .Net SqlClient in current user context using the Invoke-SqlCmdNet function
        Write-LogInfo -Message 'Running create DB command using .Net SqlClient' -Severity 1
        $SQLCreateDBResult = Invoke-SqlCmdNet -Server $SQLFQDN `
            -Database 'master' `
            -UseWindowsAuth `
            -Query $SQLCreateDBCmd
        Write-LogInfo -Message "Create DB command (SqlClient) result was: $SQLCreateDBResult" -Severity 1
    }

    # Set the ini file options - first get the file contents
    $CMIni = Get-Content -Path $CMScriptPath
    Write-LogInfo -Message "Loaded MECM install ini file from: $CMScriptPath" -Severity 1

    # Set site code and name from control
    Write-LogInfo -Message 'Setting MECM install ini file values...' -Severity 1
    $CMIni = Set-IniValue -Content $CMIni -Key 'SiteCode' -Value $Control.SiteCode
    $CMIni = Set-IniValue -Content $CMIni -Key 'SiteName' -Value $Control.SiteName

    # Set install location, SMS provider and downloads/pre-reqs path
    $CMIni = Set-IniValue -Content $CMIni -Key 'SMSInstallDir' `
        -Value "$($Control.InstallDrive)\Program Files\Microsoft Configuration Manager"
    $CMIni = Set-IniValue -Content $CMIni -Key 'SDKServer' -Value $CompFQDN
    $CMIni = Set-IniValue -Content $CMIni -Key 'PrerequisitePath' -Value "$($Control.InstallDrive)\Downloads"

    # Set MP options, if required
    if ($Control.MP) {
        $CMIni = Set-IniValue -Content $CMIni -Key 'ManagementPoint' -Value $CompFQDN
    }
    else {
        $CMIni = Set-IniValue -Content $CMIni -Key 'ManagementPoint'
    }

    # Set DP options, if required
    if ($Control.DP) {
        $CMIni = Set-IniValue -Content $CMIni -Key 'DistributionPoint' -Value $CompFQDN
    }
    else {
        $CMIni = Set-IniValue -Content $CMIni -Key 'DistributionPoint'
    }

    # Set SQL Server options
    $CMIni = Set-IniValue -Content $CMIni -Key 'SQLServerName' -Value $SQLFQDN
    $CMIni = Set-IniValue -Content $CMIni -Key 'DatabaseName' -Value "CM_$($Control.SiteCode)"

    # Set cloud connector server
    $CMIni = Set-IniValue -Content $CMIni -Key 'CloudConnectorServer' -Value $CompFQDN

    # Write back the new settings to the ini file on disk
    $CMIni | Set-Content -Path $CMScriptPath
    Write-LogInfo -Message "Saved MECM install ini file values" -Severity 1 -BlankLine

    # MECM install command line options
    $CMOps = @('/HIDDEN', 
        "/SCRIPT `"$CMScriptPath`"")

    # Run the MECM installer
    Write-LogInfo -Message 'Run MECM command line install...' -Severity 1
    Write-LogInfo -Message "${CMSetupPath} ${CMOps}" -Severity 1 -BlankLine
    $CMResult = Start-Process -FilePath "$CMSetupPath" `
        -ArgumentList $CMOps `
        -Credential $CMAdmCred `
        -Wait `
        -PassThru
    Write-LogInfo -Message "MECM install exit code: $($CMResult.ExitCode)" -Severity 1
    Write-LogInfo -Message 'MECM install completed' -Severity 1

    # Process result
    if ($CMResult.ExitCode -in 0, 1641, 3010) {
        Write-LogInfo -Message 'Successfully installed MECM primary site' -Severity 1 -BlankLine
    }
    else {
        Write-LogInfo -Message 'Error installing MECM primary site' -Severity 3
    }
}

# End of internal functions *************************************************************************************************************************

# Export functions **********************************************************************************************************************************

<#
    .SYNOPSIS
        Adds a Windows scheduled task that will perform a (Powershell) install action
    .DESCRIPTION
        This cmdlet will create a new Windows scheduled task based on the input parameters. The task can be
        either set to run on startup or once at a specific delayed time. The task will be added to the 'MECM'
        folder and any existing task (with the same name) will be removed and replaced. The task action will
        always be a Powershell command; the specific action can be set with the -ActionArgument parameter.
    .PARAMETER TaskName
        A string that will set the 'Name' property of the new task, if a task with this name already exists
        it will be deleted and replaced.
    .PARAMETER StartupTask
        Switch to set the new task to run at computer startup (ParameterSet - StartupTask).
    .PARAMETER DelayedTask
        Switch to set the new task to run once at a time offset by -DelayMinutes (ParameterSet - [Default]
        DelayedTask).
    .PARAMETER DelayMinutes
        An integer that specifies the task start delay (from the current time) in minutes, can be a value
        between 0-120 inclusive (ParameterSet - [Default] DelayedTask).
    .PARAMETER ActionArgument
        A string that specifies the Powershell command to be run by the new task, should be either a script
        file '-File <path to Powershell script>' or a command block '-Command & {<Some-Commands | To-Do>}'.
    .PARAMETER TaskDescription
        (Optional) a string that will be set as the new task 'Description' property.
#>
function Add-InstallTask {
    [CmdletBinding(DefaultParameterSetName = 'DelayedTask')]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $TaskName,

        [Parameter(Mandatory = $false,
            ParameterSetName = 'StartupTask')]
        [switch]
        $StartupTask = $false,

        [Parameter(Mandatory = $false,
            ParameterSetName = 'DelayedTask')]
        [switch]
        $DelayedTask = $false,

        [Parameter(Mandatory = $true,
            ParameterSetName = 'DelayedTask')]
        [ValidateRange(0, 120)]
        [int]
        $DelayMinutes,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ActionArgument,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $TaskDescription = 'MECM install task'
    )

    Initialize-Session
    Write-LogInfo -Message 'Start adding an install task...' -Severity 1 -BlankLine

    # Create a task folder, if it doesn't already exist
    $SchedObj = New-Object -ComObject Schedule.Service
    $SchedObj.Connect()
    try {
        [void]($SchedObj.GetFolder('\MECM'))
    }
    catch {
        $SchTskRoot = $SchedObj.GetFolder('\')
        [void]($SchTskRoot.CreateFolder('MECM'))
        Write-LogInfo -Message 'Created scheduled tasks folder for MECM' -Severity 1
    }

    # Create scheduled task based on input parameters

    # Startup task trigger
    if ($StartupTask) {
        $TaskStartupTrigger = New-ScheduledTaskTrigger -AtStartup
        Write-LogInfo -Message 'A startup type task will be created' -Severity 1
    }

    # Delayed task trigger
    if ($DelayedTask) {
        $TaskStart = (Get-Date).AddMinutes($DelayMinutes)
        $TaskStartupTrigger = New-ScheduledTaskTrigger -Once -At $TaskStart
        Write-LogInfo -Message `
            "A delayed task will be created and it will run in $DelayMinutes mins" `
            -Severity 1
    }

    # Check if this task already exists, if so delete it
    $ExistingTask = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($null -ne $ExistingTask) {
        Write-LogInfo -Message "Scheduled task $TaskName already exists." -Severity 1
        [void](Disable-ScheduledTask -InputObject $ExistingTask)
        Unregister-ScheduledTask -InputObject $ExistingTask -Confirm:$false
        Write-LogInfo -Message `
            "Existing scheduled task $TaskName unregistered; will be re-created" `
            -Severity 1
    }

    # Add the new task, to run as SYSTEM
    $TaskStartupAction = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-ExecutionPolicy Bypass $ActionArgument"
    $TaskStartupPrc = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -RunLevel Highest
    [void](Register-ScheduledTask -TaskName $TaskName `
        -TaskPath '\MECM' `
        -Action $TaskStartupAction `
        -Trigger $TaskStartupTrigger `
        -Principal $TaskStartupPrc `
        -Description $TaskDescription)

    Write-LogInfo -Message "Registered $TaskName scheduled task" -Severity 1 -BlankLine
}

<#
    .SYNOPSIS
        Installs a MECM primary site.
    .DESCRIPTION
        This cmdlet will install a MECM primary site on the local server. SQL will be installed locally, if
        required, or can be remote. All the pre-requisite Windows Server roles and features will be installed
        as well. This is the FULL install, other cmdlets in this module are essentially subsets of this
        cmdlet. All parameters are contained in 'control.json'.
    .PARAMETER Mode
        Determines the installation set that will be attempted, can be one of the following values:
            AllPreReqs - will install all pre-requisite features and SQL Server (where LocalSql is true) but
                not the MECM Primary site itself.
            CMOnly - will install the MECM Primary site only (pre-req configuration must be already
                complete).
            Full - will install the complete configuration.
    .PARAMETER LocalSql
        Switch to install a local SQL Server instance for the database, otherwise a remote SQL server/
        instance must be specified in control.json. When this switch is enabled it will override the value of
        'LocalSql' in 'control.json'.
    .PARAMETER SqlVersion
        (Optional) Specify the version of SQL to be installed, should match the source files, can be 2016,
        2017 or 2019, the value set here will override the value of SqlVersion in 'control.json'. Has no
        effect unless -LocalSql is set here or true in 'control.json'.
#>
function Install-MECM {
    [cmdletbinding(PositionalBinding = $true)]
    param (
        [Parameter(Mandatory = $true, 
            Position = 1)]
        [ValidateSet('AllPreReqs', 'CMOnly', 'Full')]
        [string]
        $Mode,

        [Parameter(Mandatory = $false)]
        [switch]
        $LocalSql = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet(2016, 2017, 2019)]
        [int]
        $SqlVersion = 0
    )

    # Start message
    Initialize-Session
    Write-LogInfo -Message 'Start proccessing MECM install actions...' -Severity 1
    Write-LogInfo -Message "Install-MECM mode is: $Mode" -Severity 1 -BlankLine

    # Set LocalSql if Control value is true
    if ($Control.LocalSql) {
        $LocalSql = $true
    }

    # Where SqlVersion is default value 0, set this parameter from Control
    if ($SqlVersion -eq 0) {
        $SqlVersion = $Control.SqlVersion
    }

    # CMOnly mode - start the MECM install and return
    if ($Mode -eq 'CMOnly') {
        Install-CMPrimarySite -LocalSql $LocalSql -SqlVersion $SqlVersion
        return
    }

    # Otherwise continue

    # Log the Sql Parameters
    Write-LogInfo -Message "The value of LocalSql is: $LocalSql" -Severity 1
    Write-LogInfo -Message "SQL Server version to be installed is: $SqlVersion" -Severity 1

    # Validate MECM specific control parameters
    Confirm-CMValues

    # Validate SQL specific control parameters
    if ($LocalSql) {
        Confirm-SQLLocalValues
    }
    else {
        Confirm-SQLRemoteValues
    }

    # Validation complete
    Write-LogInfo -Message 'Parameter validation complete' -Severity 1 -BlankLine

    # Format drives for Azure VM according to 'DiskLayout' in 'control.json'
    Initialize-VMDisks

    # Install ADK pre-requisite
    Install-PreReqADK

    # Install all Windows pre-requisite features
    Install-PreReqFeatures -FeatureSet All

    # Process drives for SMS files
    Install-SMSFiles

    # Install SQL if required
    if ($LocalSql) {
        Install-SQLServer -SqlVersion $SqlVersion
    }
    else {
        Write-LogInfo -Message 'SQL Server install skipped' -Severity 1 -BlankLine
    }

    # Install SQL management tools
    Install-SQLTools

    # AllPreReqs mode - now done so return
    if ($Mode -eq 'AllPreReqs') {
        return
    }

    # If we're still running here, it must be 'Full' mode - we now need to reboot and run the last bits of
    # the install - 'CMOnly' mode.

    # Check user context - if we are running as SYSTEM it must be fully non-interactive scenario so set up a
    # scheduled task to continue and restart, otherwise tell the user to do so manually.
    if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem) {
        # Add a task to run the CM Site install
        $ScriptCmd = "& {Import-Module '${PSScriptRoot}\Ensono.MECM.psd1'; Install-MECM -Mode CMOnly}"
        Add-InstallTask -TaskName 'Start-CMProvisioning-T2' `
            -DelayedTask `
            -DelayMinutes 10 `
            -ActionArgument "-Command $ScriptCmd" `
            -TaskDescription 'Installs MECM - phase 2 - MECM primary site'
        Write-LogInfo -Message 'Pre-requisite phase complete, T2 task will run in 10 minutes' -Severity 1

        # A small pause before restarting
        Write-LogInfo -Message 'Pausing for 30 seconds...' -Severity 1
        Start-Sleep -Seconds 30

        # Reboot because all the pre-reqs, SQL etc
        Write-LogInfo -Message 'Restarting local machine...' -Severity 1
        Restart-Computer -Force
    }
    else {
        # Output information to the user, await ENTER key press to restart
        Write-LogInfo -Message 'Pre-requisite phase complete' -Severity 1
        Write-LogInfo -Message 'Script is running interactively' -Severity 1
        Write-LogInfo -Message 'The system now needs to restart, once done, please log in again' -Severity 1
        Write-LogInfo -Message 'Run ''Install-MECM -Mode CMOnly'' to complete the install' -Severity 1
        Read-Host -Prompt 'Press ENTER to restart...'
        Restart-Computer -Force
    }
}

<#
    .SYNOPSIS
        Initializes and formats disks on the server.
    .DESCRIPTION
        This cmdlet will initialize, partition and format disks on the target computer. It is intended to aid
        automated set up of an Azure VM (because the disks will be uninitialized, raw and empty by default).
        The 'control.json' parameter 'AzureVM' must be set and the cmdlet will use the contents of the
        'DiskLayout' node in 'control.json' to determine how to partition and format the disks.
#>
function Initialize-VMDisks {
    [cmdletbinding()]
    param ()

    Initialize-Session

    # Where 'AzureVM' is true do the disk initialization, formatting etc
    if ($Control.AzureVM) {
        Initialize-AzureDisks
    }
    else {
        Write-LogInfo -Message 'Disk initialization skipped - control value is false'
    }
}

<#
    .SYNOPSIS
        Installs Windows ADK features required for MECM.
    .DESCRIPTION
        This cmdlet will install all Windows ADK features required for MECM primary site on the local server.
        The install drive can be specified as a parameter, otherwise the value will be taken from the
        control.json file.
    .PARAMETER InstallDrive
        String to specify the drive to install ADK features to, if specified, this overrides control value.
#>
function Install-PreReqADK {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $InstallDrive = $Control.InstallDrive
    )

    Initialize-Session
    Write-LogInfo -Message 'Start installing Windows ADK...' -Severity 1 -BlankLine

    # Do ADK install
    Install-ADK -InstallDrive $InstallDrive
}

<#
    .SYNOPSIS
        Installs Windows Server features required for MECM.
    .DESCRIPTION
        This script will install Windows Server features required for MECM primary site or other roles on the
        local server, the exact features installed are determined by the FeatureSet input parameter and
        control.json lists the actual feature names.
    .PARAMETER FeatureSet
        String to specify the set of features to install, when 'All' is specified MP & DP features are on/off
        according to control.json, otherwise only the specified set(s) of features are installed.
#>
function Install-PreReqFeatures {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet('All', 'Primary', 'DP', 'MP', 'DP&MP')]
        [string]
        $FeatureSet
    )

    # Introduction
    Initialize-Session
    Write-LogInfo -Message 'Start installing Windows pre-requisite features...' -Severity 1 -BlankLine

    # Install primary features if All or Primary
    if (($FeatureSet -eq 'All') -or ($FeatureSet -eq 'Primary')) {
        # Primary site features
        Write-LogInfo -Message 'Installing Windows pre-requisite features for primary site...' -Severity 1
        $FeaturesRetVal = Install-Features -Features $Control.WindowsFeatures
        Write-LogInfo -Message `
            "Windows features for primary site installed, return value: $FeaturesRetVal" `
            -Severity 1 -BlankLine
    }
    else {
        Write-LogInfo -Message 'Primary site pre-requisite features skipped' -Severity 1 -BlankLine
    }

    # Extra roles and features for MP & DP (optional)

    # Management Point (MP)
    if ((($FeatureSet -eq 'All') -and ($Control.MP)) -or ($FeatureSet -in 'MP','DP&MP')) {
        # Get feature list
        Write-LogInfo -Message 'MP to be installed...' -Severity 1

        # Install set of features
        Write-LogInfo -Message 'Installing Windows pre-requisite features for MP...' -Severity 1
        Install-Features -Features $Control.MPFeatures
        Write-LogInfo -Message "Windows features for MP installed sucessfully" -Severity 1 -BlankLine
    }
    else {
        Write-LogInfo -Message 'MP pre-requisite features skipped' -Severity 1 -BlankLine
    }

    # Distribution Point (DP)
    if ((($FeatureSet -eq 'All') -and ($Control.DP)) -or ($FeatureSet -in 'DP','DP&MP')) {
        # Get feature list
        Write-LogInfo -Message 'DP to be installed...' -Severity 1
    
        # Install set of features
        Write-LogInfo -Message 'Installing Windows pre-requisite features for DP...' -Severity 1
        Install-Features -Features $Control.DPFeatures
        Write-LogInfo -Message "Windows features for DP installed sucessfully" -Severity 1 -BlankLine
    }
    else {
        Write-LogInfo -Message 'DP pre-requisite features skipped' -Severity 1 -BlankLine
    }
}

<#
    .SYNOPSIS
        Installs no_sms_on_drive.sms files to local drives
    .DESCRIPTION
        This script will create no_sms_on_drive.sms on all local drives, drives included in ContentDrives in
        control.json are skipped.
#>
function Install-SMSFiles {
    [cmdletbinding()]
    param ()

    # Create no_sms_on_drive.sms files
    Initialize-Session
    Write-LogInfo -Message 'Start adding no_sms_on_drive.sms file to local drives...' -Severity 1 -BlankLine

    # Get local fixed drives
    $LocalDrives = Get-Volume | Where-Object -Property DriveType -eq Fixed

    # Loop through fixed drives
    foreach ($Drive in $LocalDrives) {
        $DriveLet = $Drive.DriveLetter
        # Check a drive letter is assigned - skip system/recovery volumes etc
        if ($null -ne $DriveLet) {
            Write-LogInfo -Message "Found fixed drive: ${DriveLet}:" -Severity 1
            # Check against array of content drives from parameters - skip these
            if ("${DriveLet}:" -in $Control.ContentDrives) {
                Write-LogInfo -Message `
                    "Skipping fixed drive ${DriveLet}: because it is marked as a content drive" `
                    -Severity 1 -BlankLine
            }
            else {
                # Create the .sms file
                if (!(Test-Path -Path "${DriveLet}:\no_sms_on_drive.sms")) {
                    [void](New-Item -Path "${DriveLet}:\" -Name 'no_sms_on_drive.sms' -ItemType File)
                    Write-LogInfo -Message "${DriveLet}:\no_sms_on_drive.sms added" -Severity 1 -BlankLine
                }
                else {
                    Write-LogInfo -Message `
                        "${DriveLet}:\no_sms_on_drive.sms already exists" `
                        -Severity 1 -BlankLine
                }
            }
        }
    }
    Write-LogInfo -Message 'no_sms_on_drive.sms file processing complete' -Severity 1 -BlankLine
}

<#
    .SYNOPSIS
        Installs SQL Server database engine on the local server
    .DESCRIPTION
        This script will install SQL Server on the local server for MECM. If not specified will default to
        the value from 'control.json'. Make sure that the source file (SQL.7z) contains the correct version
        files. Other parameters for the install of SQL are contained in 'control.json'.
    .PARAMETER SQLVersion
        (Optional) Specify the version of SQL to be installed, should match the source files, can be 2016,
        2017 or 2019, the value set here will override the value of SqlVersion in 'control.json'.
#>
function Install-SQLServer {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateSet(2016, 2017, 2019)]
        [int]
        $SqlVersion = 0
    )

    Initialize-Session
    Write-LogInfo -Message 'Start installing SQL Server locally...' -Severity 1 -BlankLine

    # Where SqlVersion is default value 0, set this parameter from Control
    if ($SqlVersion -eq 0) {
        $SqlVersion = $Control.SqlVersion
    }

    # Determine the version to be installed
    Write-LogInfo -Message "SQL Server version to be installed is: $SQLVersion" -Severity 1
    $SQLVerInstDir = ''
    switch ($SqlVersion) {
        2016 {$SQLVerInstDir = 'MSSQL13.MSSQLSERVER'}
        2017 {$SQLVerInstDir = 'MSSQL14.MSSQLSERVER'}
        2019 {$SQLVerInstDir = 'MSSQL15.MSSQLSERVER'}
    }

    # Paths
    $SQL7zPath = "$SourcePath\SQL.7z"
    $SQLSourcePath = "$SourcePath\SQL\"

    # Check source file exists
    if (Test-Path -Path $SQL7zPath) {
        Write-LogInfo -Message 'SQL Server 7z file found OK' -Severity 1
    }
    else {
        Write-LogInfo -Message "Error: Cannot find SQL Server 7z file at: $SQL7zPath" -Severity 3
    }

    # Unzip SQL with 7-zip
    Expand-7zArchive -ArchivePath $SQL7zPath -ExpandedPath $SQLSourcePath

    # Set path to SQL setup exe
    $SQLSetupPath = "${SQLSourcePath}setup.exe"
    Write-LogInfo -Message "SQL Server setup file path: $SQLSetupPath" -Severity 1

    # Pre-setup for Azure VM TempDB - create the TempDB folder and override the TempDB install file location
    $SQLTempLoc = "$($Control.SQLDrTemp)\Program Files\Microsoft SQL Server\$SQLVerInstDir\MSSQL\Data"
    if ($Control.AzureVM) {
        if (!(Test-Path -Path "$($Control.AzureTempDrive)\SQLTempDB")) {
            New-Item -ItemType Directory -Path "$($Control.AzureTempDrive)\SQLTempDB"
            Write-LogInfo -Message "Folder created for tempdb files: $($Control.AzureTempDrive)\SQLTempDB" -Severity 1
        }
        $SQLTempLoc = "$($Control.AzureTempDrive)\SQLTempDB"
    }

    # Build command line parameters for SQL install
    Write-LogInfo -Message 'Building SQL Server install parameters...' -Severity 1
    $SQLOpQ = '/Q'
    $SQLOpLic = '/IACCEPTSQLSERVERLICENSETERMS'
    $SQLOpUpdSrc = "/UpdateSource=`"$SourcePath\SQLPatch`""
    $SQLOpAct = '/ACTION="INSTALL"'
    $SQLOpProgress = '/INDICATEPROGRESS'
    $SQLOpFeat = '/FEATURES=SQLENGINE'
    $SQLOpInstNm = '/INSTANCENAME=MSSQLSERVER'
    $SQLOpCollatn = '/SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"'
    $SQLOpInstDir = "/INSTANCEDIR=`"$($Control.InstallDrive)\Program Files\Microsoft SQL Server`""
    $SQLOpDataDir = "/INSTALLSQLDATADIR=`"$($Control.SQLDrData)\Program Files\Microsoft SQL Server`""
    $SQLOpUsDataDir = "/SQLUSERDBDIR=`"$($Control.SQLDrData)\Program Files\Microsoft SQL Server\$SQLVerInstDir\MSSQL\DATA`""
    $SQLOpUsLogDir = "/SQLUSERDBLOGDIR=`"$($Control.SQLDrLog)\Program Files\Microsoft SQL Server\$SQLVerInstDir\MSSQL\DATA`""
    $SQLOpTmpDir = "/SQLTEMPDBDIR=`"$SQLTempLoc`""
    $SQLOpTmpLgDir = "/SQLTEMPDBLOGDIR=`"$SQLTempLoc`""
    $SQLOpBkupDir = "/SQLBACKUPDIR=`"$($Control.SQLDrBkup)\Program Files\Microsoft SQL Server\$SQLVerInstDir\MSSQL\Backup`""
    $SQLOpSAAccts = "/SQLSYSADMINACCOUNTS="
    foreach ($SAAcct in $Control.SQLSAAccts) {
        $SQLOpSAAccts += "`"$SAAcct`" "
    }

    # Create an array to hold all the parameters
    $SQLOps = @($SQLOpQ, $SQLOpLic, $SQLOpUpdSrc, $SQLOpAct, $SQLOpProgress, $SQLOpFeat, $SQLOpInstNm,
        $SQLOpCollatn, $SQLOpInstDir, $SQLOpDataDir, $SQLOpUsDataDir, $SQLOpUsLogDir, $SQLOpTmpDir,
        $SQLOpTmpLgDir, $SQLOpBkupDir, $SQLOpSAAccts)

    # Build command line parameters for SQL service accounts
    if ($SQLSvEngAc -ne '') {
        $SQLOpEngAc = "/SQLSVCACCOUNT=`"$($Control.SQLSvEngAc)`""
        $SQLOpEngPw = "/SQLSVCPASSWORD=`"$($Control.SQLSvEngPw)`""
        if ($SQLSvAgtAc -ne '') {
            $SQLOpAgtAc = "/AGTSVCACCOUNT=`"$($Control.SQLSvAgtAc)`""
            $SQLOpAgtPw = "/AGTSVCPASSWORD=`"$($Control.SQLSvAgtPw)`""
            $SQLOpsSvc = @($SQLOpEngAc, $SQLOpEngPw, $SQLOpAgtAc, $SQLOpAgtPw)
        }
        else {
            $SQLOpsSvc = @($SQLOpEngAc, $SQLOpEngPw)
        }
        $SQLOps += $SQLOpsSvc
    }

    # Build command line parameters for SQL Temp DB settings
    $SQLOpsTmpDB = @()
    if (($Control.SQLTmpFiles -is [int]) -and ($Control.SQLTmpFiles -ge 1) -and ($Control.SQLTmpFiles -le 32)) {
        $SQLOpTmpFiles = "/SQLTEMPDBFILECOUNT=$($Control.SQLTmpFiles)"
        $SQLOpsTmpDB += $SQLOpTmpFiles
    }
    if (($Control.SQLTmpFileSize -is [int]) -and ($Control.SQLTmpFileSize -ge 8) -and ($Control.SQLTmpFileSize -le 262144)) {
        $SQLOpTmpFileSize = "/SQLTEMPDBFILESIZE=$($Control.SQLTmpFileSize)"
        $SQLOpsTmpDB += $SQLOpTmpFileSize
    }
    if (($Control.SQLTmpFileGrw -is [int]) -and ($Control.SQLTmpFileGrw -ge 0) -and ($Control.SQLTmpFileGrw -le 1024)) {
        $SQLOpTmpFileGrw = "/SQLTEMPDBFILEGROWTH=$($Control.SQLTmpFileGrw)"
        $SQLOpsTmpDB += $SQLOpTmpFileGrw
    }
    if (($Control.SQLTmpLogFileSize -is [int]) -and ($Control.SQLTmpLogFileSize -ge 8) -and ($Control.SQLTmpLogFileSize -le 262144)) {
        $SQLOpTmpLogFileSize = "/SQLTEMPDBLOGFILESIZE=$($Control.SQLTmpLogFileSize)"
        $SQLOpsTmpDB += $SQLOpTmpLogFileSize
    }
    if (($Control.SQLTmpLogFileGrw -is [int]) -and ($Control.SQLTmpLogFileGrw -ge 0) -and ($Control.SQLTmpLogFileGrw -le 1024)) {
        $SQLOpTmpLogFileGrw = "/SQLTEMPDBLOGFILEGROWTH=$($Control.SQLTmpLogFileGrw)"
        $SQLOpsTmpDB += $SQLOpTmpLogFileGrw
    }

    # Add the SQL Temp DB parameters to the full parameter array, if any are set
    if ($SQLOpsTmpDB.Length -gt 0) {
        $SQLOps += $SQLOpsTmpDB
    }

    # For SQL Server 2019 we can set some configuration options (memory, maxdop) as install options - yay!
    if ($SqlVersion -eq 2019) {
        if (($Control.SQLMaxDOP -is [int]) -and ($Control.SQLMaxDOP -gt 0)) {
            $SQLOpMaxDOP = "/SQLMAXDOP=$($Control.SQLMaxDOP)"
            $SQLOps += $SQLOpMaxDOP
        }
        if (($Control.SQLMinMemory -is [int]) -and ($Control.SQLMinMemory -gt 0)) {
            $SQLOpMinMem = "/SQLMINMEMORY=$($Control.SQLMinMemory)"
            $SQLOps += $SQLOpMinMem
        }
        if (($Control.SQLMaxMemory -is [int]) -and ($Control.SQLMaxMemory -gt 0)) {
            $SQLOpMaxMem = "/SQLMAXMEMORY=$($Control.SQLMaxMemory)"
            $SQLOps += $SQLOpMaxMem
        }
    }

    # Write out all the specified options
    foreach ($SQLOp in $SQLOps) {
        Write-LogInfo -Message "SQL install option: $SQLOp" -Severity 1
    }
    Write-Host ''

    # Run the SQL Server install
    Write-LogInfo -Message 'Run SQL Server command line install...' -Severity 1
    Write-LogInfo -Message "${SQLSetupPath} ${SQLOps}" -Severity 1 -BlankLine
    $SQLResult = Start-Process -FilePath "$SQLSetupPath" -ArgumentList $SQLOps -Wait -PassThru
    Write-LogInfo -Message "SQL Server install exit code: $($SQLResult.ExitCode)" -Severity 1
    Write-LogInfo -Message 'SQL Server install completed' -Severity 1

    # Process result
    if ($SQLResult.ExitCode -in 0, 1641, 3010) {
        Write-LogInfo -Message 'Successfully installed SQL Server' -Severity 1 -BlankLine
    }
    else {
        Write-LogInfo -Message 'Error installing SQL Server' -Severity 3
    }

    # For Azure VM - ensure configuration for moving TempDB files to temporary disk sticks
    # Check Azure VM
    if ($Control.AzureVM) {
        Enable-AzureTempDB
    }

    # Run SQL commands to configure server settings here

    # For SQL 2016/2017; use sp_configure to set memory, maxdop

    # For all versions; use sp_configure to set cost threshold for parallelism
}

<#
    .SYNOPSIS
        Installs SQL Server management tools on the local server
    .DESCRIPTION
        This script will install SQL Server management tools. The install drive can be specified as a
        parameter, otherwise the value will be taken from the control.json file.
    .PARAMETER InstallDrive
        String to specify the drive to install SSMS to, if specified, this overrides control value.
#>
function Install-SQLTools {
    [cmdletbinding()]
    param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string]
        $InstallDrive = $Control.InstallDrive
    )

    # Start management tools processing
    Initialize-Session
    Write-LogInfo 'Install SQL Server management tools...' -Severity 1 -BlankLine

    # Make sure drive parameter is correctly formatted
    Test-DriveParameter -DriveParam $InstallDrive

    # Paths
    $SQLToolsSrcPath = "$SourcePath\SQLTools\SSMS-Setup-ENU.exe"
    $SQLToolsInstPath = "`"$InstallDrive\Program Files (x86)\Microsoft SQL Server Management Studio 18`""

    # Check source file exists
    if (Test-Path -Path $SQLToolsSrcPath) {
        Write-LogInfo -Message 'SQL tools installer file found OK' -Severity 1
    }
    else {
        Write-LogInfo -Message "Error: Cannot find SQL tools installer file at: $SQLToolsSrcPath" -Severity 3
    }

    # Command line options
    $SQLToolsOps = @('/install','/quiet','/norestart',"SSMSInstallRoot=$SQLToolsInstPath")

    # Run installer
    Write-LogInfo "${SQLToolsSrcPath} ${SQLToolsOps}" -Severity 1
    $SQLToolsResult = Start-Process -FilePath "$SQLToolsSrcPath" -ArgumentList $SQLToolsOps -Wait -PassThru
    Write-LogInfo -Message "SQL tools install exit code: $($SQLToolsResult.ExitCode)" -Severity 1

    # Process result
    if ($SQLToolsResult.ExitCode -in 0, 1641, 3010) {
        Write-LogInfo -Message 'Successfully installed SQL Server management tools' -Severity 1 -BlankLine
    }
    else {
        Write-LogInfo -Message 'Error installing SQL Server management tools' -Severity 3
    }
}
