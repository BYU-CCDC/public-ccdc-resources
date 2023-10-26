Import-Module ActiveDirectory

# Load user list from file
[string[]]$UserArray = Get-Content -Path ".\users.txt"

# Undo user creation
foreach ($user in $UserArray) {
    if (Get-ADUser -Filter {Name -eq $user}) {
        Remove-ADUser -Identity $user -Confirm:$false
    }
}

Enable-ADAccount Aaron

# Get all active network adapters
$activeAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }

# Loop through each active adapter and enable IPv6 and File and Printer Sharing
foreach ($adapter in $activeAdapters) {
    # Enable IPv6 on the adapter
    Enable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_tcpip6

    # Enable File and Printer Sharing for Microsoft Networks
    Enable-NetAdapterBinding -Name $adapter.Name -ComponentID ms_server
}

# Get all IP-enabled adapters and enable NetBIOS over TCP/IP (assuming default was to use DHCP settings)
$adapters = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True"
foreach ($adapter in $adapters) {
    # Enable NetBIOS over TCP/IP via DHCP settings (NetbiosOptions = 0)
    $adapter.SetTcpipNetbios(0)
}

function Restore-OriginalGPOSettings {
    # Define GPO and settings
    $gpoName = "Good-GPO"  # Replace with the name of your GPO
    $policyPath = "Machine\Microsoft\Windows NT\SecEdit\GptTmpl.inf"  # Path to the GptTmpl.inf within the GPO

    # Retrieve the path to the GPO on sysvol
    $gpoPath = (Get-GPO -Name $gpoName).Path

    # Construct full path
    $fullPath = "\\$($env:USERDNSDOMAIN)\sysvol\$($env:USERDNSDOMAIN)\Policies\$gpoPath\$policyPath"

    # Restore the GptTmpl.inf from the backup
    if (Test-Path "${fullPath}.backup") {
        Copy-Item -Path "${fullPath}.backup" -Destination $fullPath -Force
        Remove-Item "${fullPath}.backup" -Force  # Delete the backup after restoration
    } else {
        Write-Error "Backup file not found!"
        return
    }

    # Get all computer names in the domain
    $computers = Get-ADComputer -Filter * | Select-Object -ExpandProperty Name

    # Invoke gpupdate on each computer
    Invoke-Command -ComputerName $computers -ScriptBlock {
        gpupdate /force
    } -AsJob  # This will execute as background jobs to avoid waiting for each to finish
}

function Remove-Good-GPO {
    # Fetch the distinguished name of the current domain
    $domainDN = (Get-ADDomain).DistinguishedName

    # Remove the link of the GPO from the domain
    Remove-GPLink -Name "Good-GPO" -Target $domainDN

    # Delete the GPO named "Good GPO"
    Remove-GPO -Name "Good-GPO"
}

# # Execute functions
# Restore-OriginalGPOSettings
Remove-Good-GPO
