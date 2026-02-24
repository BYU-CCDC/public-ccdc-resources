$sshConfigPath = "C:\ProgramData\ssh\sshd_config"

if (Test-Path $sshConfigPath) {
    Write-Host "Found SSH config file at $sshConfigPath. Processing changes..."
    $configLines = Get-Content $sshConfigPath
    $modified = $false
    $newLines = @()
    $pubKeyFound = $false
    $passwordFound = $false

    foreach ($line in $configLines) {
        if ($line -match "^\s*PubKeyAuthentication") {
            $newLines += "PubKeyAuthentication no"
            $pubKeyFound = $true
            $modified = $true
        }
        elseif ($line -match "^\s*PasswordAuthentication") {
            $newLines += "PasswordAuthentication yes"
            $passwordFound = $true
            $modified = $true
        }
        else {
            $newLines += $line
        }
    }

    if (-not $pubKeyFound) {
        $newLines += "PubKeyAuthentication no"
        $modified = $true
    }
    if (-not $passwordFound) {
        $newLines += "PasswordAuthentication yes"
        $modified = $true
    }

    if ($modified) {
        $backupPath = "$sshConfigPath.bak"
        Copy-Item $sshConfigPath $backupPath -Force

        $newLines | Set-Content $sshConfigPath -Force
        Write-Host "SSH configuration updated."

        Write-Host "Restarting sshd service..."
        Restart-Service sshd -Force
    }
    else {
        Write-Host "No changes needed in SSH config."
    }
}
else {
    Write-Host "SSH config file not found at $sshConfigPath."
}

Import-Module WebAdministration -ErrorAction SilentlyContinue

$webdavModule = Get-WebGlobalModule | Where-Object { $_.Name -eq "WebDAVModule" }
if ($webdavModule) {
    Write-Host "WebDAV module found"
    Remove-WebGlobalModule -Name "WebDAVModule"
}
else {
    Write-Host "WebDAV module not present."
}

$iisWebRoot = "C:\inetpub\wwwroot"
if (Test-Path $iisWebRoot) {
    icacls $iisWebRoot /reset /T /C
    Write-Host "Permissions reset"
}
else {
    Write-Host "IIS web root not found at $iisWebRoot."
}

$appPools = Get-ChildItem IIS:\AppPools
foreach ($pool in $appPools) {
    $currentIdentity = $pool.processModel.identityType
    if ($currentIdentity -ne "ApplicationPoolIdentity") {
        Write-Host "Setting ApplicationPoolIdentity for pool: $($pool.Name) (Current: $currentIdentity)"
        Set-ItemProperty "IIS:\AppPools\$($pool.Name)" -Name processModel.identityType -Value "ApplicationPoolIdentity"
    }
    else {
        Write-Host "Pool $($pool.Name) already uses ApplicationPoolIdentity."
    }
}
