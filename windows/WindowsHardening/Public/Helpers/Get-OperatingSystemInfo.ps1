#Requires -Version 5.1

# Get-OperatingSystemInfo.ps1 - Operating system and DC detection (runs once at module import).

function Get-OperatingSystemInfo {
    [CmdletBinding()]
    param()

    if ($script:HardeningContext.OS) {
        return $script:HardeningContext.OS
    }

    try {
        Write-Verbose "Detecting operating system..."

        # -ErrorAction Stop so a failed query reaches the catch. If both fail, keep going:
        # the OS reports as "Unknown" but DC detection (NTDS service) does not need WMI.
        try {
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        } catch {
            Write-Warning "CIM query failed, falling back to WMI..."
            try {
                $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ErrorAction Stop
            } catch {
                Write-Warning "WMI query failed; OS will be reported as Unknown: $($_.Exception.Message)"
                $osInfo = $null
            }
        }

        $caption = $osInfo.Caption
        $version = $osInfo.Version
        $buildNumber = $osInfo.BuildNumber
        $productType = $osInfo.ProductType
        $isDomainController = Test-IsDomainController

        # Domain membership (a member server or workstation is joined but not a DC).
        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        } catch {
            try { $computerSystem = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction Stop } catch { $computerSystem = $null }
        }
        $isDomainJoined = [bool]($computerSystem -and $computerSystem.PartOfDomain)

        # Server Core: InstallationType is "Server Core", "Server", or "Client" (2008 R2 and
        # later). The GUI-feature check only works on 2012/2012 R2 (Server-Gui-Shell does not
        # exist on 2016+), so it is the fallback. Edition is derived from ProductType
        # (1 = workstation, 2 = DC, 3 = server) rather than the SKU number, which does not
        # map cleanly (SKU 4 is Windows Enterprise, 161/162 are Pro for Workstations).
        $isServerCore = $false
        if ($productType -in 2, 3) {
            $installationType = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name InstallationType -ErrorAction Ignore).InstallationType
            if ($installationType) {
                $isServerCore = $installationType -eq 'Server Core'
            } else {
                try {
                    $guiFeature = Get-WindowsFeature -Name Server-Gui-Shell -ErrorAction Stop
                    $isServerCore = [bool]($guiFeature -and $guiFeature.InstallState -ne 'Installed')
                } catch {
                    $isServerCore = $caption -match 'Server Core'
                }
            }
        }
        $editionName = if ($productType -notin 2, 3) { 'Client' } elseif ($isServerCore) { 'Server Core' } else { 'Server' }

        $osVersion = "Unknown"
        $osFamily = "Unknown"

        if ($caption -match "Windows Server 2025") {
            $osVersion = "Windows Server 2025"
            $osFamily = "Server2025"
        } elseif ($caption -match "Windows Server 2022") {
            $osVersion = "Windows Server 2022"
            $osFamily = "Server2022"
        } elseif ($caption -match "Windows Server 2019") {
            $osVersion = "Windows Server 2019"
            $osFamily = "Server2019"
        } elseif ($caption -match "Windows Server 2016") {
            $osVersion = "Windows Server 2016"
            $osFamily = "Server2016"
        } elseif ($caption -match "Windows 11") {
            $osVersion = "Windows 11"
            $osFamily = "Client11"
        } elseif ($caption -match "Windows 10") {
            $osVersion = "Windows 10"
            $osFamily = "Client10"
        } elseif ($caption -match "Windows 7") {
            $osVersion = "Windows 7"
            $osFamily = "Client7"
        } elseif ($caption -match "Windows Server 2012 R2") {
            $osVersion = "Windows Server 2012 R2"
            $osFamily = "Server2012R2"
        } elseif ($caption -match "Windows Server 2012") {
            $osVersion = "Windows Server 2012"
            $osFamily = "Server2012"
        } elseif ($caption -match "Windows Server 2008 R2") {
            $osVersion = "Windows Server 2008 R2"
            $osFamily = "Server2008R2"
        } elseif ($caption -match "Windows Server 2008") {
            $osVersion = "Windows Server 2008"
            $osFamily = "Server2008"
        } elseif ($caption -match "Windows 8") {
            $osVersion = "Windows 8"
            $osFamily = "Client8"
        } elseif ($caption -match "Windows Vista") {
            $osVersion = "Windows Vista"
            $osFamily = "ClientVista"
        } elseif ($caption -match "Windows XP") {
            $osVersion = "Windows XP"
            $osFamily = "ClientXP"
        }

        $result = [PSCustomObject]@{
            Caption      = $caption
            Version      = $version
            BuildNumber  = $buildNumber
            OSVersion    = $osVersion
            OSFamily     = $osFamily
            Edition      = $editionName
            IsServer     = ($productType -in 2, 3)
            IsServerCore = $isServerCore
            ProductType  = $productType
            IsDomainController = $isDomainController
            IsDomainJoined     = $isDomainJoined
            Domain             = if ($isDomainJoined) { $computerSystem.Domain } else { $null }
            Workgroup          = if ($computerSystem -and -not $isDomainJoined) { $computerSystem.Workgroup } else { $null }
        }

        $role = if ($isDomainController) { "Domain Controller ($($result.Domain))" }
                elseif ($isDomainJoined) { "domain member ($($result.Domain))" }
                else { 'not domain-joined' }
        Write-Host ""
        Write-Status "OS Detection: $($result.OSVersion) (Build $($result.BuildNumber)) - $($result.Edition) - $role" -LogMessage "OS Detection: $($result.OSVersion) (Build $($result.BuildNumber)) - $($result.Edition)"
        if ($isDomainController) {
            Write-Status "Domain Controller detected - AD operations enabled" -LogOnly
        } else {
            Write-Status "Non-domain machine detected - local operations only" -LogOnly
        }

        $script:HardeningContext.OS = $result
        return $result

    } catch {
        Write-Error "Failed to detect operating system: $($_.Exception.Message)"
        throw
    }
}
