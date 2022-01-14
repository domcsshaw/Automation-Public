Install-PackageProvider -Name NuGet -Force
Install-Module -Name PSWindowsUpdate -Force
Import-Module PSWindowsUpdate -Force
Get-WindowsUpdate
Install-WindowsUpdate -ForceInstall -AcceptAll -IgnoreReboot