# Internal helpers shared by the domain GPO operations.

$script:CcdcGpoModuleRoot = $null
if ($PSScriptRoot) {
    $script:CcdcGpoModuleRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
} elseif ($script:DataPath) {
    $script:CcdcGpoModuleRoot = Split-Path -Path $script:DataPath -Parent
}

$script:CcdcGpoDraftUri = ''
$script:CcdcCoreGpoArchiveUri = 'https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/GPO-Core.zip'
$script:CcdcAdditionalGpoArchiveUri = 'https://raw.githubusercontent.com/BYU-CCDC/public-ccdc-resources/main/windows/GPO-Additional.zip'

$script:CcdcGpoDraftAliases = @{
    'DC Allow AD' = 'CCDC v1 Domain Controller Baseline'
    'Domain Allow AD + Core + Default Block' = 'CCDC v1 Domain Firewall Baseline'
    'Domain GPO Update Interval' = 'CCDC v1 GPO Update Interval'
    'Domain Good-GPO' = 'CCDC v1 Domain Common Baseline'
    'Domain Splomk' = 'CCDC v1 Splunk Outbound'
    'Web Servers Firewall Policy' = 'CCDC v1 Web Firewall Role'
    'Mail Servers Firewall Policy' = 'CCDC v1 Mail Firewall Role'
}
$script:CcdcCoreDraftGpos = @(
    'CCDC v1 Defender Baseline', 'CCDC v1 Domain Audit', 'CCDC v1 Domain Common Baseline'
    'CCDC v1 Domain Controller Baseline', 'CCDC v1 Domain Firewall Baseline'
    'CCDC v1 FTP Access', 'CCDC v1 GPO Update Interval', 'CCDC v1 Mail Firewall Role'
    'CCDC v1 MSSQL Role', 'CCDC v1 RDP Access', 'CCDC v1 SMB Access'
    'CCDC v1 Splunk Outbound', 'CCDC v1 SSH Access', 'CCDC v1 Web Browsing Outbound'
    'CCDC v1 Web Firewall Role', 'CCDC v1 WinRM Access'
)
$script:CcdcAdditionalDraftGpos = @(
    'CCDC v1 ADCS Access', 'CCDC v1 Custom Firewall Port Exception'
    'CCDC v1 Linux SSH Logon', 'CCDC v1 MySQL-MariaDB Ports', 'CCDC v1 Ping Access'
    'CCDC v1 SNMP Access', 'CCDC v1 SQL Browser Access', 'CCDC v1 XAMPP Ports'
)
$script:CcdcRequiredDraftGpos = @($script:CcdcCoreDraftGpos + $script:CcdcAdditionalDraftGpos)
$script:CcdcGpoAdditionalDraftArchivePath = $null
$script:CcdcGpoAdditionalDraftBackupRoot = $null
$script:CcdcGpoArchiveExtractRoot = $null
$script:CcdcGpoUsesSplitDraft = $false
$script:CcdcGpoAdditionalDraftLoaded = $false

function Get-CcdcDraftBackupNames {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    $backupFolders = @(Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction Stop | Where-Object Name -like '{*}')
    if ($backupFolders.Count -eq 0) { throw "Draft package contains no GPO backups under '$BackupRoot'." }
    $foundNames = @{}
    foreach ($folder in $backupFolders) {
        $metadataPath = Join-Path $folder.FullName 'Backup.xml'
        if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) { throw "Draft backup '$($folder.Name)' is missing Backup.xml." }
        try { [xml]$metadata = Get-Content -LiteralPath $metadataPath -Raw -ErrorAction Stop }
        catch { throw "Draft backup '$($folder.Name)' has invalid Backup.xml: $($_.Exception.Message)" }
        $metadataId = $metadata.SelectSingleNode("//*[local-name()='ID']")
        $metadataName = $metadata.SelectSingleNode("//*[local-name()='DisplayName']")
        if (-not $metadataId -or -not $metadataName -or -not $metadataId.InnerText -or -not $metadataName.InnerText) {
            throw "Draft backup '$($folder.Name)' is missing its GPO ID or display name."
        }
        $foundNames[[string]$metadataName.InnerText] = $true
    }
    return $foundNames
}

function Assert-CcdcDraftBackups {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$BackupRoot,
        [Parameter(Mandatory=$true)][string[]]$RequiredNames,
        [Parameter(Mandatory=$true)][string]$PackageLabel
    )

    $foundNames = Get-CcdcDraftBackupNames -BackupRoot $BackupRoot
    $missingNames = @($RequiredNames | Where-Object { -not $foundNames.ContainsKey($_) })
    if ($missingNames.Count -gt 0) {
        throw "$PackageLabel is incomplete; missing required backups: $($missingNames -join ', ')"
    }
}

function Get-CcdcGpoArchive {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Uri,
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$PackageLabel
    )

    $downloadPath = "$Path.download"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $Uri -OutFile $downloadPath -UseBasicParsing -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $downloadPath -PathType Leaf) -or (Get-Item -LiteralPath $downloadPath -ErrorAction Stop).Length -eq 0) {
            throw 'The downloaded file is empty.'
        }
        Move-Item -LiteralPath $downloadPath -Destination $Path -Force -ErrorAction Stop
    } catch {
        Remove-Item -LiteralPath $downloadPath -Force -ErrorAction Ignore
        throw "Could not download $PackageLabel from '$Uri': $($_.Exception.Message)"
    }

    return $Path
}

function Get-CcdcDraftArchiveBackupRoot {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$ExtractRoot)

    $backupRoot = Join-Path $ExtractRoot 'Backups'
    if (Test-Path -LiteralPath $backupRoot -PathType Container) { return $backupRoot }
    if (@(Get-ChildItem -LiteralPath $ExtractRoot -Directory -ErrorAction Stop | Where-Object Name -like '{*}').Count -gt 0) {
        return $ExtractRoot
    }
    $nested = Get-ChildItem -LiteralPath $ExtractRoot -Directory -ErrorAction Stop | Select-Object -First 1
    if ($nested) {
        $nestedBackups = Join-Path $nested.FullName 'Backups'
        if (Test-Path -LiteralPath $nestedBackups -PathType Container) { return $nestedBackups }
        if (@(Get-ChildItem -LiteralPath $nested.FullName -Directory -ErrorAction Stop | Where-Object Name -like '{*}').Count -gt 0) {
            return $nested.FullName
        }
    }
    throw "Draft package contains no GPO backups under '$ExtractRoot'."
}

function Initialize-CcdcGpoDraftEnvironment {
    [CmdletBinding()]
    param(
        [string]$DraftUri,
        [string]$DraftPath,
        [string]$CachePath
    )

    foreach ($moduleName in @('ActiveDirectory', 'GroupPolicy', 'NetSecurity')) {
        if (-not (Get-Module -Name $moduleName)) { Import-Module $moduleName -ErrorAction Stop }
    }
    if (-not $CachePath) { $CachePath = Join-Path ([System.IO.Path]::GetTempPath()) 'CCDC-GPO-v1' }
    New-Item -Path $CachePath -ItemType Directory -Force -ErrorAction Stop | Out-Null

    $script:CcdcGpoAdditionalDraftArchivePath = $null
    $script:CcdcGpoAdditionalDraftBackupRoot = $null
    $script:CcdcGpoArchiveExtractRoot = $CachePath
    $script:CcdcGpoUsesSplitDraft = $false
    $script:CcdcGpoAdditionalDraftLoaded = $false

    $sourcePath = $DraftPath
    $requiredNames = $script:CcdcRequiredDraftGpos
    if (-not $sourcePath -and -not $DraftUri) {
        $script:CcdcGpoUsesSplitDraft = $true
        $requiredNames = $script:CcdcCoreDraftGpos
    }
    if ($sourcePath -and (Test-Path -LiteralPath $sourcePath -PathType Container)) {
        $backupRoot = Join-Path $sourcePath 'Backups'
        if (-not (Test-Path -LiteralPath $backupRoot -PathType Container)) { $backupRoot = $sourcePath }
    } else {
        if ($sourcePath -and (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
            $archivePath = (Resolve-Path -LiteralPath $sourcePath -ErrorAction Stop).Path
        } else {
            if (-not $DraftUri) { $DraftUri = $script:CcdcGpoDraftUri }
            if ($DraftUri) {
                $archivePath = Join-Path $CachePath 'gpo-v1.zip'
                Get-CcdcGpoArchive -Uri $DraftUri -Path $archivePath -PackageLabel 'draft GPO package' | Out-Null
                $script:CcdcGpoUsesSplitDraft = $false
                $requiredNames = $script:CcdcRequiredDraftGpos
            } else {
                $archivePath = Join-Path $CachePath 'GPO-Core.zip'
                Get-CcdcGpoArchive -Uri $script:CcdcCoreGpoArchiveUri -Path $archivePath -PackageLabel 'core GPO package' | Out-Null
                $script:CcdcGpoAdditionalDraftArchivePath = Join-Path $CachePath 'GPO-Additional.zip'
            }
        }
        $extractFolderName = if ($script:CcdcGpoUsesSplitDraft) { 'CoreDraft' } else { 'FullDraft' }
        $extractRoot = Join-Path $CachePath $extractFolderName
        if (Test-Path -LiteralPath $extractRoot) {
            Remove-Item -LiteralPath $extractRoot -Recurse -Force -ErrorAction Stop
        }
        New-Item -Path $extractRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
        try { Expand-Archive -LiteralPath $archivePath -DestinationPath $extractRoot -Force -ErrorAction Stop }
        catch { throw "Draft GPO package is not a readable ZIP: $($_.Exception.Message)" }
        $backupRoot = Get-CcdcDraftArchiveBackupRoot -ExtractRoot $extractRoot
    }

    Assert-CcdcDraftBackups -BackupRoot $backupRoot -RequiredNames $requiredNames -PackageLabel $(if ($script:CcdcGpoUsesSplitDraft) { 'Core draft GPO package' } else { 'Draft package' })
    return $backupRoot
}

function Initialize-CcdcAdditionalGpoDraftEnvironment {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$BackupRoot)

    if (-not $script:CcdcGpoUsesSplitDraft) { return $BackupRoot }
    if ($script:CcdcGpoAdditionalDraftLoaded) { return $script:CcdcGpoAdditionalDraftBackupRoot }
    $archivePath = $script:CcdcGpoAdditionalDraftArchivePath
    if (-not $archivePath -or -not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
        $archivePath = Join-Path $script:CcdcGpoArchiveExtractRoot 'GPO-Additional.zip'
        Get-CcdcGpoArchive -Uri $script:CcdcAdditionalGpoArchiveUri -Path $archivePath -PackageLabel 'additional GPO package' | Out-Null
        $script:CcdcGpoAdditionalDraftArchivePath = $archivePath
    }

    $additionalExtractRoot = Join-Path $script:CcdcGpoArchiveExtractRoot 'AdditionalDraft'
    if (Test-Path -LiteralPath $additionalExtractRoot) {
        Remove-Item -LiteralPath $additionalExtractRoot -Recurse -Force -ErrorAction Stop
    }
    New-Item -Path $additionalExtractRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
    try {
        Expand-Archive -LiteralPath $archivePath -DestinationPath $additionalExtractRoot -Force -ErrorAction Stop
    } catch {
        throw "Additional draft GPO package is not a readable ZIP: $($_.Exception.Message)"
    }

    $additionalBackupRoot = Get-CcdcDraftArchiveBackupRoot -ExtractRoot $additionalExtractRoot
    Assert-CcdcDraftBackups -BackupRoot $additionalBackupRoot -RequiredNames $script:CcdcAdditionalDraftGpos -PackageLabel 'Additional draft GPO package'
    $script:CcdcGpoAdditionalDraftBackupRoot = $additionalBackupRoot
    $script:CcdcGpoAdditionalDraftLoaded = $true
    Write-Status -Level Info 'Additional GPO archive extracted and validated for the selected optional GPOs'
    return $additionalBackupRoot
}

function Find-CcdcGpoBackupId {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$BackupRoot
    )

    foreach ($folder in Get-ChildItem -LiteralPath $BackupRoot -Directory -ErrorAction Stop | Where-Object Name -like '{*}') {
        $metadataPath = Join-Path $folder.FullName 'Backup.xml'
        if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) { continue }
        try { [xml]$metadata = Get-Content -LiteralPath $metadataPath -Raw -ErrorAction Stop } catch { continue }
        $metadataName = $metadata.SelectSingleNode("//*[local-name()='DisplayName']")
        if ($metadataName -and $metadataName.InnerText -eq $Name) { return $folder.Name }
    }
    return $null
}

function Import-CcdcGpo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$BackupRoot,
        [string]$TargetName,
        [string]$Server
    )

    $draftName = if ($script:CcdcGpoDraftAliases.ContainsKey($Name)) { $script:CcdcGpoDraftAliases[$Name] } else { $Name }
    $backupId = if (Test-Path -LiteralPath $BackupRoot -PathType Container) {
        Find-CcdcGpoBackupId -Name $draftName -BackupRoot $BackupRoot
    } else { $null }
    $importBackupRoot = $BackupRoot
    if ($script:CcdcGpoUsesSplitDraft -and $draftName -in $script:CcdcAdditionalDraftGpos) {
        $importBackupRoot = Initialize-CcdcAdditionalGpoDraftEnvironment -BackupRoot $BackupRoot
        $backupId = Find-CcdcGpoBackupId -Name $draftName -BackupRoot $importBackupRoot
    }
    if (-not $backupId) { throw "Draft package has no backup for GPO '$draftName' (requested as '$Name')" }
    if (-not $TargetName) { $TargetName = $Name }

    if ($Server) {
        Import-GPO -BackupId $backupId -Path $importBackupRoot -TargetName $TargetName `
            -CreateIfNeeded -Server $Server -ErrorAction Stop | Out-Null
        return (Get-GPO -Name $TargetName -Server $Server -ErrorAction Stop)
    }
    Import-GPO -BackupId $backupId -Path $importBackupRoot -TargetName $TargetName -CreateIfNeeded -ErrorAction Stop | Out-Null
    return (Get-GPO -Name $TargetName -ErrorAction Stop)
}

function Resolve-CcdcGpoDraftBackupRoot {
    [CmdletBinding()]
    param([string]$DraftPath)

    $candidates = @()
    if ($DraftPath) {
        $candidates += $DraftPath
    } else {
        $moduleRoot = Split-Path -Path (Split-Path -Path $PSScriptRoot -Parent) -Parent
        $repoDraft = Join-Path (Split-Path -Path $moduleRoot -Parent) 'gpo-v1\expanded-draft-package'
        $candidates += $repoDraft
        $candidates += 'C:\GPO-v1\expanded-draft-package'
    }

    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Container)) { continue }
        $possibleRoots = @(
            (Join-Path $candidate 'Backups')
            $candidate
        )
        foreach ($possibleRoot in $possibleRoots) {
            if (-not (Test-Path -LiteralPath $possibleRoot -PathType Container)) { continue }
            foreach ($backupFolder in Get-ChildItem -LiteralPath $possibleRoot -Directory -ErrorAction Ignore | Where-Object Name -Like '{*}') {
                $backupXml = Join-Path $backupFolder.FullName 'Backup.xml'
                if (-not (Test-Path -LiteralPath $backupXml -PathType Leaf)) { continue }
                try { [xml]$metadata = Get-Content -LiteralPath $backupXml -Raw -ErrorAction Stop } catch { continue }
                $metadataName = $metadata.SelectSingleNode("//*[local-name()='DisplayName']")
                if ($metadataName -and $metadataName.InnerText -eq 'CCDC v1 Web Browsing Outbound') { return $possibleRoot }
            }
        }
    }

    if ($DraftPath) {
        throw "Draft GPO backup 'CCDC v1 Web Browsing Outbound' was not found under '$DraftPath'. Pass the expanded gpo-v1 package folder or its Backups folder."
    }
    throw "Draft GPO backup 'CCDC v1 Web Browsing Outbound' was not found. Pass -GpoDraftPath with the expanded gpo-v1 package folder or its Backups folder."
}

function Set-CcdcGpoSecurityFilter {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [string[]]$ComputerName = @(),
        [string[]]$GroupName = @()
    )

    $existingPermissions = @(Get-GPPermission -Name $Name -All -ErrorAction Stop)

    # Keep broad principals read-only so selected computer accounts control policy application.
    foreach ($principal in @(
        @{ Name = 'Authenticated Users'; Type = 'Group' }
        @{ Name = 'Domain Computers'; Type = 'Group' }
    )) {
        $existingPrincipal = @($existingPermissions | Where-Object {
            $_.Trustee.Name -eq $principal.Name
        })
        if ($existingPrincipal) {
            Set-GPPermissions -Name $Name -TargetName $principal.Name -TargetType $principal.Type `
                -PermissionLevel GpoRead -Replace -Confirm:$false -ErrorAction Stop | Out-Null
        }
    }

    foreach ($permission in $existingPermissions) {
        $trusteeName = [string]$permission.Trustee.Name
        if ($trusteeName.EndsWith('$', [StringComparison]::Ordinal)) {
            Set-GPPermissions -Name $Name -TargetName $trusteeName -TargetType Computer `
                -PermissionLevel GpoRead -Replace -Confirm:$false -ErrorAction Stop | Out-Null
        }
    }

    foreach ($computerIdentity in @($ComputerName | ForEach-Object { [string]$_ })) {
        if ([string]::IsNullOrWhiteSpace($computerIdentity)) { continue }
        $computer = Get-ADComputer -Identity $computerIdentity -ErrorAction Stop
        Set-GPPermissions -Name $Name -TargetName ([string]$computer.SamAccountName) -TargetType Computer `
            -PermissionLevel GpoApply -Replace -Confirm:$false -ErrorAction Stop | Out-Null
    }

    foreach ($groupIdentity in @($GroupName | ForEach-Object { [string]$_ })) {
        if ([string]::IsNullOrWhiteSpace($groupIdentity)) { continue }
        Set-GPPermissions -Name $Name -TargetName $groupIdentity -TargetType Group `
            -PermissionLevel GpoApply -Replace -Confirm:$false -ErrorAction Stop | Out-Null
    }
}

function Add-CcdcGpoLink {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Target,
        [string[]]$SecurityFilter,
        [string[]]$SecurityFilterGroup,
        [switch]$Enforced
    )

    # Enforced links win over conflicting OU-linked GPOs and ignore Block Inheritance.
    $enforcedValue = if ($Enforced) { 'Yes' } else { 'No' }
    $inheritance = Get-GPInheritance -Target $Target -ErrorAction Stop
    $existingLink = @($inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $Name }) | Select-Object -First 1
    if ($existingLink) {
        Set-GPLink -Name $Name -Target $Target -LinkEnabled Yes -Enforced $enforcedValue -ErrorAction Stop | Out-Null
    } else {
        New-GPLink -Name $Name -Target $Target -LinkEnabled Yes -Enforced $enforcedValue -ErrorAction Stop | Out-Null
    }

    if ($SecurityFilter -and $SecurityFilter.Count -gt 0) {
        Set-CcdcGpoSecurityFilter -Name $Name -ComputerName $SecurityFilter -GroupName $SecurityFilterGroup
    } elseif ($SecurityFilterGroup -and $SecurityFilterGroup.Count -gt 0) {
        Set-CcdcGpoSecurityFilter -Name $Name -GroupName $SecurityFilterGroup
    }
}

function Invoke-CcdcGpoLinkOperation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$BackupRoot,
        [Parameter(Mandatory=$true)][string]$Target,
        [string[]]$SecurityFilter,
        [string[]]$SecurityFilterGroup,
        [switch]$Enforced
    )

    $gpo = Import-CcdcGpo -Name $Name -BackupRoot $BackupRoot
    Add-CcdcGpoLink -Name $gpo.DisplayName -Target $Target -SecurityFilter $SecurityFilter `
        -SecurityFilterGroup $SecurityFilterGroup -Enforced:$Enforced
    Write-Status -Level Success "Imported '$Name' and linked it to $Target" -LogMessage "Imported GPO '$Name' and linked to '$Target'"
}

function Get-CcdcDomainRootDn {
    (Get-ADDomain -ErrorAction Stop).DistinguishedName
}

function Get-CcdcDomainControllersOu {
    $domain = Get-ADDomain -ErrorAction Stop
    $targets = @()
    foreach ($domainController in Get-ADDomainController -Filter * -ErrorAction Stop) {
        $computerDn = $domainController.ComputerObjectDN
        if (-not $computerDn) {
            throw "Could not determine the computer object's distinguished name for domain controller '$($domainController.HostName)'"
        }
        $ouDn = $computerDn.Substring($computerDn.IndexOf(',') + 1)
        if (-not $ouDn.EndsWith($domain.DistinguishedName, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Domain controller object is outside the current domain: $computerDn"
        }
        $targets += $ouDn
    }
    $uniqueTargets = @($targets | Sort-Object -Unique)
    if ($uniqueTargets.Count -eq 0) { throw 'No domain controller computer objects were found in Active Directory.' }
    return ,$uniqueTargets
}

function Invoke-CcdcGpUpdate {
    [CmdletBinding()]
    param()

    $process = Start-Process -FilePath 'gpupdate.exe' -ArgumentList '/force' -Wait -PassThru -NoNewWindow -ErrorAction Stop
    if ($process.ExitCode -ne 0) {
        throw "gpupdate /force exited with code $($process.ExitCode)"
    }
}

function Set-CcdcGpoFirewallRule {
    # Creates or replaces one allow rule in a domain GPO. $Rule holds the remaining
    # New-NetFirewallRule parameters and must include Name.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$GpoName,
        [Parameter(Mandatory=$true)][hashtable]$Rule
    )

    if (-not (Get-Module -Name NetSecurity)) { Import-Module NetSecurity -ErrorAction Stop }
    $policyStore = "$((Get-ADDomain -ErrorAction Stop).DNSRoot)\$GpoName"
    if (Get-NetFirewallRule -PolicyStore $policyStore -Name $Rule.Name -ErrorAction Ignore) {
        Remove-NetFirewallRule -PolicyStore $policyStore -Name $Rule.Name -ErrorAction Stop
    }
    New-NetFirewallRule -PolicyStore $policyStore -Action Allow -Enabled True @Rule -ErrorAction Stop | Out-Null
}

function Remove-CcdcBroadWebEgress {
    [CmdletBinding()]
    param()

    $gpoName = 'Domain Allow AD + Core + Default Block'
    if (-not (Get-GPO -Name $gpoName -ErrorAction Ignore)) { return }
    $policyStore = "$((Get-ADDomain -ErrorAction Stop).DNSRoot)\$gpoName"
    foreach ($rule in @(Get-NetFirewallRule -PolicyStore $policyStore -DisplayName 'web outbound' -ErrorAction Ignore)) {
        Remove-NetFirewallRule -PolicyStore $policyStore -Name $rule.Name -ErrorAction Stop
    }
}

function Resolve-CcdcFirewallRemoteAddress {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$HostNameOrAddress)

    $parsedAddress = $null
    if ([System.Net.IPAddress]::TryParse($HostNameOrAddress, [ref]$parsedAddress)) {
        return $parsedAddress.ToString()
    }

    try {
        $resolved = @([System.Net.Dns]::GetHostAddresses($HostNameOrAddress) |
            ForEach-Object { $_.ToString() } | Sort-Object -Unique)
    } catch {
        throw "Could not resolve '$HostNameOrAddress' to firewall remote-address entries: $($_.Exception.Message)"
    }
    if ($resolved.Count -eq 0) { throw "No IP addresses resolved for '$HostNameOrAddress'." }
    return $resolved
}

# Service-role GPOs are imported from the draft package. Only domain-specific edits
# remain here; static service, registry, security-template, and firewall settings live
# in the corresponding backup.
$script:CcdcServiceRoles = @{
    Database = @{ GpoName = 'CCDC MSSQL Access' }
    SQLBrowser = @{ GpoName = 'CCDC SQL Browser Access' }
    WinRM = @{ GpoName = 'CCDC Preserve WinRM' }
    SSH = @{ GpoName = 'CCDC SSH Access' }
    LinuxSSH = @{
        GpoName = 'CCDC Linux SSH Logon'
        PrivilegeRights = @(
            @{ Name = 'SeRemoteInteractiveLogonRight'; IncludeDomainUsers = $true; IncludeDomainAdmins = $true }
        )
    }
    RDP = @{
        GpoName = 'CCDC RDP Access'
        PrivilegeRights = @(
            @{ Name = 'SeRemoteInteractiveLogonRight'; Sids = @('S-1-5-32-544', 'S-1-5-32-555'); IncludeDomainAdmins = $true }
        )
    }
    FTP = @{ GpoName = 'CCDC FTP Access' }
    SMB = @{ GpoName = 'CCDC SMB Access' }
    Ping = @{ GpoName = 'CCDC Ping Access' }
    SNMP = @{ GpoName = 'CCDC SNMP Access' }
    ADCS = @{ GpoName = 'CCDC ADCS Access' }
    XAMPP = @{ GpoName = 'CCDC XAMPP Ports' }
    MySQLMariaDB = @{ GpoName = 'CCDC MySQL-MariaDB Ports' }
}

$script:CcdcServiceRoleDraftNames = @{
    Database = 'CCDC v1 MSSQL Role'; SQLBrowser = 'CCDC v1 SQL Browser Access'
    WinRM = 'CCDC v1 WinRM Access'; SSH = 'CCDC v1 SSH Access'
    LinuxSSH = 'CCDC v1 Linux SSH Logon'; RDP = 'CCDC v1 RDP Access'
    FTP = 'CCDC v1 FTP Access'; SMB = 'CCDC v1 SMB Access'
    Ping = 'CCDC v1 Ping Access'; SNMP = 'CCDC v1 SNMP Access'
    ADCS = 'CCDC v1 ADCS Access'; XAMPP = 'CCDC v1 XAMPP Ports'
    MySQLMariaDB = 'CCDC v1 MySQL-MariaDB Ports'
}

function Set-CcdcGpoPrivilegeRight {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$GpoName,
        [Parameter(Mandatory=$true)][string]$RightName,
        [Parameter(Mandatory=$true)][string[]]$Sid
    )

    $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    $gpoPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\{$($gpo.Id)}"
    $securityPath = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\SecEdit'
    $null = New-Item -Path $securityPath -ItemType Directory -Force
    $infPath = Join-Path $securityPath 'GptTmpl.inf'
    if (Test-Path -LiteralPath $infPath) {
        $lines = @(Get-Content -LiteralPath $infPath)
    } else {
        $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO"', 'Revision=1')
    }

    $rightLine = "$RightName = " + (($Sid | Sort-Object -Unique | ForEach-Object { "*$_" }) -join ',')
    $sectionIndex = [Array]::IndexOf($lines, '[Privilege Rights]')
    if ($sectionIndex -lt 0) {
        $lines += '[Privilege Rights]'
        $lines += $rightLine
    } else {
        $nextSection = $lines.Count
        for ($i = $sectionIndex + 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\[[^\]]+\]$') { $nextSection = $i; break }
        }
        $found = $false
        for ($i = $sectionIndex + 1; $i -lt $nextSection; $i++) {
            if ($lines[$i] -match ('^' + [regex]::Escape($RightName) + '\s*=')) {
                $lines[$i] = $rightLine
                $found = $true
            }
        }
        if (-not $found) {
            $before = @($lines[0..($nextSection - 1)])
            $after = if ($nextSection -lt $lines.Count) { @($lines[$nextSection..($lines.Count - 1)]) } else { @() }
            $lines = @($before + $rightLine + $after)
        }
    }
    Set-Content -LiteralPath $infPath -Value $lines -Encoding Unicode

    $adGpo = Get-ADObject -Identity "CN={$($gpo.Id)},CN=Policies,CN=System,$($domain.DistinguishedName)" `
        -Properties gPCMachineExtensionNames, versionNumber -ErrorAction Stop
    $pair = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    $extensions = [string]$adGpo.gPCMachineExtensionNames
    if (-not $extensions.Contains($pair)) {
        Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ gPCMachineExtensionNames = ($extensions + $pair) } -ErrorAction Stop
    }
    $gptIni = Join-Path $gpoPath 'gpt.ini'
    if (-not (Test-Path -LiteralPath $gptIni)) { throw "GPO GPT.INI is missing: $gptIni" }
    $versionText = Get-Content -LiteralPath $gptIni -Raw
    $currentVersion = [int]([regex]::Match($versionText, '(?m)^Version=(\d+)').Groups[1].Value)
    $nextVersion = (($currentVersion -band 0xFFFF0000) -bor ((($currentVersion -band 0xFFFF) + 1) -band 0xFFFF))
    Set-Content -LiteralPath $gptIni -Value ([regex]::Replace($versionText, '(?m)^Version=\d+', "Version=$nextVersion")) -Encoding ASCII
    Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ versionNumber = $nextVersion } -ErrorAction Stop
}

function Set-CcdcGpoSecurityTemplateValue {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$GpoName,
        [Parameter(Mandatory=$true)][string]$Section,
        [Parameter(Mandatory=$true)][string]$Name,
        [Parameter(Mandatory=$true)][string]$Value
    )

    $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    $gpoPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\{$($gpo.Id)}"
    $securityPath = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\SecEdit'
    $null = New-Item -Path $securityPath -ItemType Directory -Force
    $infPath = Join-Path $securityPath 'GptTmpl.inf'
    if (Test-Path -LiteralPath $infPath) {
        $lines = @(Get-Content -LiteralPath $infPath)
    } else {
        $lines = @('[Unicode]', 'Unicode=yes', '[Version]', 'signature="$CHICAGO"', 'Revision=1')
    }
    $header = "[$Section]"
    $sectionIndex = [Array]::FindIndex($lines, [Predicate[string]]{ param($line) $line -ieq $header })
    if ($sectionIndex -lt 0) {
        $lines += $header
        $lines += "$Name = $Value"
    } else {
        $nextSection = $lines.Count
        for ($i = $sectionIndex + 1; $i -lt $lines.Count; $i++) {
            if ($lines[$i] -match '^\[[^\]]+\]$') { $nextSection = $i; break }
        }
        $found = $false
        for ($i = $sectionIndex + 1; $i -lt $nextSection; $i++) {
            if ($lines[$i] -match ('^\s*' + [regex]::Escape($Name) + '\s*=')) {
                $lines[$i] = "$Name = $Value"
                $found = $true
            }
        }
        if (-not $found) {
            $before = @($lines[0..($nextSection - 1)])
            $after = if ($nextSection -lt $lines.Count) { @($lines[$nextSection..($lines.Count - 1)]) } else { @() }
            $lines = @($before + "$Name = $Value" + $after)
        }
    }
    Set-Content -LiteralPath $infPath -Value $lines -Encoding Unicode

    $adGpo = Get-ADObject -Identity "CN={$($gpo.Id)},CN=Policies,CN=System,$($domain.DistinguishedName)" `
        -Properties gPCMachineExtensionNames, versionNumber -ErrorAction Stop
    $pair = '[{827D319E-6EAC-11D2-A4EA-00C04F79F83A}{803E14A0-B4FB-11D0-A0D0-00A0C90F574B}]'
    $extensions = [string]$adGpo.gPCMachineExtensionNames
    if (-not $extensions.Contains($pair)) {
        Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ gPCMachineExtensionNames = ($extensions + $pair) } -ErrorAction Stop
    }
    $gptIni = Join-Path $gpoPath 'gpt.ini'
    $versionText = Get-Content -LiteralPath $gptIni -Raw
    $currentVersion = [int]([regex]::Match($versionText, '(?m)^Version=(\d+)').Groups[1].Value)
    $nextVersion = (($currentVersion -band 0xFFFF0000) -bor ((($currentVersion -band 0xFFFF) + 1) -band 0xFFFF))
    Set-Content -LiteralPath $gptIni -Value ([regex]::Replace($versionText, '(?m)^Version=\d+', "Version=$nextVersion")) -Encoding ASCII
    Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ versionNumber = $nextVersion } -ErrorAction Stop
}

function Set-CcdcGpoLocalGroupPreference {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$GpoName,
        [Parameter(Mandatory=$true)][string]$GroupSid,
        [Parameter(Mandatory=$true)][string]$MemberSid
    )

    $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    $gpoPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\{$($gpo.Id)}"
    $prefPath = Join-Path $gpoPath 'Machine\Preferences\Groups'
    $null = New-Item -Path $prefPath -ItemType Directory -Force
    $groupsXml = Join-Path $prefPath 'Groups.xml'
    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <Group clsid="{6D4A79E4-529C-4481-ABD0-F5BD7EA93BA7}" name="Remote Desktop Users" image="2" changed="$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" uid="{$([guid]::NewGuid())}" userContext="0" removePolicy="0">
    <Properties action="U" groupName="Remote Desktop Users" groupSid="$GroupSid" description="" deleteAllUsers="0" deleteAllGroups="0" removeAccounts="0">
      <Members>
      <Member sid="$MemberSid" action="ADD" />
      </Members>
    </Properties>
  </Group>
</Groups>
"@
    Set-Content -LiteralPath $groupsXml -Value $xml -Encoding UTF8

    $adGpo = Get-ADObject -Identity "CN={$($gpo.Id)},CN=Policies,CN=System,$($domain.DistinguishedName)" `
        -Properties gPCMachineExtensionNames, versionNumber -ErrorAction Stop
    $pair = '[{17D89FEC-5C44-4972-B12D-241CAEF74509}{B087BE9D-ED37-454F-AF9C-04291E351182}]'
    $extensions = [string]$adGpo.gPCMachineExtensionNames
    if (-not $extensions.Contains($pair)) {
        Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ gPCMachineExtensionNames = ($extensions + $pair) } -ErrorAction Stop
    }
    $gptIni = Join-Path $gpoPath 'gpt.ini'
    $versionText = Get-Content -LiteralPath $gptIni -Raw
    $currentVersion = [int]([regex]::Match($versionText, '(?m)^Version=(\d+)').Groups[1].Value)
    $nextVersion = (($currentVersion -band 0xFFFF0000) -bor ((($currentVersion -band 0xFFFF) + 1) -band 0xFFFF))
    Set-Content -LiteralPath $gptIni -Value ([regex]::Replace($versionText, '(?m)^Version=\d+', "Version=$nextVersion")) -Encoding ASCII
    Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ versionNumber = $nextVersion } -ErrorAction Stop
}

function Remove-CcdcGpoStartupScripts {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$GpoName)

    $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    $gpoPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\{$($gpo.Id)}"
    $scriptsPath = Join-Path $gpoPath 'Machine\Scripts'
    if (Test-Path -LiteralPath $scriptsPath) {
        Remove-Item -LiteralPath $scriptsPath -Recurse -Force -ErrorAction Stop
    }

    $adGpo = Get-ADObject -Identity "CN={$($gpo.Id)},CN=Policies,CN=System,$($domain.DistinguishedName)" `
        -Properties gPCMachineExtensionNames, versionNumber -ErrorAction Stop
    $pair = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
    $extensions = [string]$adGpo.gPCMachineExtensionNames
    if ($extensions.Contains($pair)) {
        $extensions = $extensions.Replace($pair, '')
        Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ gPCMachineExtensionNames = $extensions } -ErrorAction Stop
    }
    $gptIni = Join-Path $gpoPath 'gpt.ini'
    $versionText = Get-Content -LiteralPath $gptIni -Raw -ErrorAction Stop
    $currentVersion = [int]([regex]::Match($versionText, '(?m)^Version=(\d+)').Groups[1].Value)
    $nextVersion = (($currentVersion -band 0xFFFF0000) -bor ((($currentVersion -band 0xFFFF) + 1) -band 0xFFFF))
    Set-Content -LiteralPath $gptIni -Value ([regex]::Replace($versionText, '(?m)^Version=\d+', "Version=$nextVersion")) -Encoding ASCII
    Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ versionNumber = $nextVersion } -ErrorAction Stop
}

function Set-CcdcGpoStartupPowerShellScript {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$GpoName,
        [Parameter(Mandatory=$true)][string]$ScriptName
    )

    $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    $gpoPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\{$($gpo.Id)}"
    $scriptsPath = Join-Path $gpoPath 'Machine\Scripts'
    $startupPath = Join-Path $scriptsPath 'Startup'
    $scriptPath = Join-Path $startupPath $ScriptName
    if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
        throw "Imported GPO startup script is missing: $scriptPath"
    }

    $policyRoot = "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies\{$($gpo.Id)}"
    $uncScriptPath = "$policyRoot\Machine\Scripts\Startup\$ScriptName"
    $psIniPath = Join-Path $scriptsPath 'psscripts.ini'
    if (Test-Path -LiteralPath $psIniPath) {
        Remove-Item -LiteralPath $psIniPath -Force -ErrorAction Stop
    }
    $cmdName = [IO.Path]::GetFileNameWithoutExtension($ScriptName) + '.cmd'
    $cmdPath = Join-Path $startupPath $cmdName
    $uncCmdPath = "$policyRoot\Machine\Scripts\Startup\$cmdName"
    $cmdParameters = "/c `"$uncCmdPath`""
    if ($cmdParameters.Length -ge 260) { throw "GPO startup command parameters exceed the Group Policy limit: $uncCmdPath" }
    $cmdLine = '"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $uncScriptPath + '"'
    $wrapper = '@echo off' + "`r`n" + $cmdLine + "`r`n" + 'exit /b %errorlevel%' + "`r`n"
    [System.IO.File]::WriteAllText($cmdPath, $wrapper, [System.Text.Encoding]::ASCII)
    Set-Content -LiteralPath (Join-Path $scriptsPath 'scripts.ini') -Value @(
        '[Startup]'
        '0CmdLine=C:\Windows\System32\cmd.exe'
        "0Parameters=$cmdParameters"
    ) -Encoding Unicode

    $adGpo = Get-ADObject -Identity "CN={$($gpo.Id)},CN=Policies,CN=System,$($domain.DistinguishedName)" `
        -Properties gPCMachineExtensionNames, versionNumber -ErrorAction Stop
    $pair = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
    $extensions = [string]$adGpo.gPCMachineExtensionNames
    if (-not $extensions.Contains($pair)) {
        Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ gPCMachineExtensionNames = ($extensions + $pair) } -ErrorAction Stop
    }
    $gptIni = Join-Path $gpoPath 'gpt.ini'
    if (-not (Test-Path -LiteralPath $gptIni)) { throw "GPO GPT.INI is missing: $gptIni" }
    $versionText = Get-Content -LiteralPath $gptIni -Raw
    $currentVersion = [int]([regex]::Match($versionText, '(?m)^Version=(\d+)').Groups[1].Value)
    $nextVersion = (($currentVersion -band 0xFFFF0000) -bor ((($currentVersion -band 0xFFFF) + 1) -band 0xFFFF))
    Set-Content -LiteralPath $gptIni -Value ([regex]::Replace($versionText, '(?m)^Version=\d+', "Version=$nextVersion")) -Encoding ASCII
    Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ versionNumber = $nextVersion } -ErrorAction Stop
}

function Set-CcdcGpoAdvancedAuditPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$GpoName)

    $gpo = Get-GPO -Name $GpoName -ErrorAction Stop
    $domain = Get-ADDomain -ErrorAction Stop
    $gpoPath = "\\$($domain.PDCEmulator)\SYSVOL\$($domain.DNSRoot)\Policies\{$($gpo.Id)}"
    $auditCsvPath = Join-Path $gpoPath 'Machine\Microsoft\Windows NT\Audit\audit.csv'
    if (-not (Test-Path -LiteralPath $auditCsvPath -PathType Leaf)) {
        throw "Imported GPO advanced audit policy file is missing: $auditCsvPath"
    }

    $auditRows = @(Import-Csv -LiteralPath $auditCsvPath -ErrorAction Stop)
    $requiredColumns = @(
        'Machine Name', 'Policy Target', 'Subcategory', 'Subcategory GUID'
        'Inclusion Setting', 'Exclusion Setting', 'Setting Value'
    )
    if (-not $auditRows -or @($auditRows[0].PSObject.Properties.Name | Where-Object { $_ -notin $requiredColumns }).Count -gt 0 -or
        @($requiredColumns | Where-Object { $_ -notin $auditRows[0].PSObject.Properties.Name }).Count -gt 0) {
        throw "Imported GPO advanced audit policy has an invalid CSV header: $auditCsvPath"
    }

    $expectedAuditSettings = @{
        '{0CCE9215-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE9216-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success'; Value = '1' }
        '{0CCE9217-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Failure'; Value = '2' }
        '{0CCE923F-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE9242-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE9240-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE9235-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE9236-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE9237-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE9238-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE923B-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE923C-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE922F-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE9210-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success'; Value = '1' }
        '{0CCE9211-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE9212-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE9228-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success and Failure'; Value = '3' }
        '{0CCE922B-69AE-11D9-BED3-505054503030}' = @{ Setting = 'Success'; Value = '1' }
    }
    if ($auditRows.Count -ne $expectedAuditSettings.Count) {
        throw "Imported GPO advanced audit policy must contain $($expectedAuditSettings.Count) rows: $auditCsvPath"
    }
    $seenAuditSettings = @{}
    foreach ($row in $auditRows) {
        $subcategoryId = [string]$row.'Subcategory GUID'
        if (-not $expectedAuditSettings.ContainsKey($subcategoryId)) {
            throw "Imported GPO advanced audit policy contains an unexpected subcategory '$subcategoryId'."
        }
        if ($seenAuditSettings.ContainsKey($subcategoryId)) {
            throw "Imported GPO advanced audit policy duplicates subcategory '$subcategoryId'."
        }
        $expectedSetting = $expectedAuditSettings[$subcategoryId]
        if ($row.'Machine Name' -or $row.'Policy Target' -ne 'System' -or
            $row.'Inclusion Setting' -ne $expectedSetting.Setting -or $row.'Exclusion Setting' -or
            $row.'Setting Value' -ne $expectedSetting.Value) {
            throw "Imported GPO advanced audit policy has unexpected values for subcategory '$subcategoryId'."
        }
        $seenAuditSettings[$subcategoryId] = $true
    }
    if ($seenAuditSettings.Count -ne $expectedAuditSettings.Count) {
        throw 'Imported GPO advanced audit policy is missing one or more required subcategories.'
    }

    $adGpo = Get-ADObject -Identity "CN={$($gpo.Id)},CN=Policies,CN=System,$($domain.DistinguishedName)" `
        -Properties gPCMachineExtensionNames, versionNumber -ErrorAction Stop
    $extensions = [string]$adGpo.gPCMachineExtensionNames
    $scriptPair = '[{42B5FAAE-6536-11D2-AE5A-0000F87571E3}{40B6664F-4972-11D1-A7CA-0000F87571E3}]'
    $auditPair = '[{F3CCC681-B74C-4060-9F26-CD84525DCA2A}{0F3F3735-573D-9804-99E4-AB2A69BA5FD4}]'
    $updatedExtensions = $extensions.Replace($scriptPair, '')
    if (-not $updatedExtensions.Contains($auditPair)) { $updatedExtensions += $auditPair }

    if ($updatedExtensions -ne $extensions) {
        Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ gPCMachineExtensionNames = $updatedExtensions } -ErrorAction Stop
        $gptIni = Join-Path $gpoPath 'gpt.ini'
        if (-not (Test-Path -LiteralPath $gptIni -PathType Leaf)) { throw "GPO GPT.INI is missing: $gptIni" }
        $versionText = Get-Content -LiteralPath $gptIni -Raw -ErrorAction Stop
        $versionMatch = [regex]::Match($versionText, '(?m)^Version=(\d+)')
        if (-not $versionMatch.Success) { throw "GPO GPT.INI has no valid Version value: $gptIni" }
        $currentVersion = [int]$versionMatch.Groups[1].Value
        $nextVersion = (($currentVersion -band 0xFFFF0000) -bor ((($currentVersion -band 0xFFFF) + 1) -band 0xFFFF))
        Set-Content -LiteralPath $gptIni -Value ([regex]::Replace($versionText, '(?m)^Version=\d+', "Version=$nextVersion")) -Encoding ASCII
        Set-ADObject -Identity $adGpo.DistinguishedName -Replace @{ versionNumber = $nextVersion } -ErrorAction Stop
    }
}

function Add-CcdcServiceRoleGpo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$Role,
        [Parameter(Mandatory=$true)][string[]]$ComputerName
    )

    $definition = $script:CcdcServiceRoles[$Role]
    if (-not $definition) { throw "Unknown service role '$Role'" }
    $gpoName = $definition.GpoName
    $draftName = $script:CcdcServiceRoleDraftNames[$Role]
    if (-not $draftName) { throw "No draft GPO is mapped for service role '$Role'." }
    $gpo = Import-CcdcGpo -Name $draftName -BackupRoot $script:CcdcGpoActiveBackupRoot -TargetName $gpoName

    if ($Role -eq 'FTP') {
        # FTP's obsolete startup script must not manage anonymous-auth settings.
        Remove-CcdcGpoStartupScripts -GpoName $gpoName
    }
    if ($Role -eq 'SSH') {
        Set-CcdcGpoStartupPowerShellScript -GpoName $gpoName -ScriptName 'Enable-DomainOpenSshAccess.ps1'
    }
    if ($Role -eq 'WinRM') {
        $domainUsersSid = "$((Get-ADDomain -ErrorAction Stop).DomainSID.Value)-513"
        Set-CcdcGpoSecurityTemplateValue -GpoName $gpoName -Section 'Group Membership' `
            -Name "*$domainUsersSid`__Memberof" -Value '*S-1-5-32-580'
    }
    if ($Role -eq 'RDP') {
        Set-CcdcGpoLocalGroupPreference -GpoName $gpoName -GroupSid 'S-1-5-32-555' `
            -MemberSid "$((Get-ADDomain -ErrorAction Stop).DomainSID.Value)-513"
    }
    if ($Role -eq 'ADCS') {
        $fwGpoName = 'Domain Allow AD + Core + Default Block'
        if (Get-GPO -Name $fwGpoName -ErrorAction SilentlyContinue) {
            $caAddresses = @($ComputerName | ForEach-Object {
                $comp = Get-ADComputer -Identity $_ -Properties IPv4Address -ErrorAction SilentlyContinue
                if ($comp.IPv4Address) { $comp.IPv4Address }
            } | Where-Object { $_ } | Sort-Object -Unique)
            if ($caAddresses.Count -gt 0) {
                Set-CcdcGpoFirewallRule -GpoName $fwGpoName -Rule @{
                    Name = 'CCDC-ADCS-Enrollment-RPC-Out'
                    DisplayName = 'CCDC AD CS Enrollment RPC (TCP-Out)'
                    Direction = 'Outbound'; Protocol = 'TCP'
                    RemotePort = @('135', '49152-65535')
                    RemoteAddress = $caAddresses
                }
                Write-Status "Outbound RPC to AD CS server(s) allowed in domain firewall GPO for: $($caAddresses -join ', ')"
            }
        }
    }
    foreach ($right in @($definition.PrivilegeRights)) {
        if (-not $right) { continue }
        $domainSid = (Get-ADDomain -ErrorAction Stop).DomainSID.Value
        $rightSids = @($right.Sids)
        if ($right.IncludeDomainUsers) { $rightSids += "$domainSid-513" }
        if ($right.IncludeDomainAdmins) { $rightSids += "$domainSid-512" }
        Set-CcdcGpoPrivilegeRight -GpoName $gpoName -RightName $right.Name -Sid $rightSids
    }

    Add-CcdcGpoLink -Name $gpo.DisplayName -Target (Get-CcdcDomainRootDn) -SecurityFilter $ComputerName
    Write-Status -Level Success "Created/updated '$gpoName' for $($ComputerName -join ', ')" `
        -LogMessage "Created/updated '$gpoName' for computer account(s): $($ComputerName -join ', ')"
}
