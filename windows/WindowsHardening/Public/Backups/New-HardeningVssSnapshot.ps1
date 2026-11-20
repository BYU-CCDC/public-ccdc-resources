function New-HardeningVssSnapshot {
    <#
    .SYNOPSIS
        Creates a VSS snapshot for each local fixed volume.
    .DESCRIPTION
        Creates one persistent, client-accessible VSS snapshot per fixed volume
        before hardening. Windows manages snapshot storage and retention. A failed
        snapshot is reported as a warning; callers may continue hardening.
        Snapshots are local recovery points, not system-state or off-machine backups.
    .OUTPUTS
        PSCustomObject with volume, snapshot ID, and status for each attempted volume.
    #>
    [CmdletBinding()]
    param()

    try {
        $volumes = @(Get-CimInstance -ClassName Win32_Volume -Filter 'DriveType = 3' -ErrorAction Stop |
            Sort-Object DeviceID)
    } catch {
        $message = "Could not enumerate fixed volumes for VSS snapshots: $($_.Exception.Message)"
        Write-Status -Level Warning $message
        return
    }

    if ($volumes.Count -eq 0) {
        Write-Status -Level Warning 'No local fixed volumes were found for VSS snapshots'
        return
    }

    foreach ($volume in $volumes) {
        $volumeId = $volume.DeviceID
        $label = if ($volume.DriveLetter) { $volume.DriveLetter } else { $volumeId }
        if ($volume.FileSystem -notin @('NTFS', 'ReFS')) {
            Write-Status -Level Warning "Skipping VSS snapshot for $label; file system '$($volume.FileSystem)' is not supported by this helper"
            [pscustomobject]@{ Volume = $volumeId; SnapshotId = $null; Status = 'Skipped'; ReturnValue = $null }
            continue
        }
        try {
            $result = Invoke-CimMethod -ClassName Win32_ShadowCopy -MethodName Create -Arguments @{
                Volume  = $volumeId
                Context = 'ClientAccessible'
            } -ErrorAction Stop

            if ($result.ReturnValue -ne 0 -or -not $result.ShadowID) {
                $message = "VSS snapshot failed for $label (return code $($result.ReturnValue))"
                Write-Status -Level Warning $message
                [pscustomobject]@{ Volume = $volumeId; SnapshotId = $null; Status = 'Failed'; ReturnValue = $result.ReturnValue }
                continue
            }

            Write-Status -Level Success "VSS snapshot created for $label (ID $($result.ShadowID))"
            [pscustomobject]@{ Volume = $volumeId; SnapshotId = [string]$result.ShadowID; Status = 'Created'; ReturnValue = 0 }
        } catch {
            Write-Status -Level Warning "VSS snapshot failed for $label; continuing: $($_.Exception.Message)"
            [pscustomobject]@{ Volume = $volumeId; SnapshotId = $null; Status = 'Failed'; ReturnValue = $null; Error = $_.Exception.Message }
        }
    }
}
