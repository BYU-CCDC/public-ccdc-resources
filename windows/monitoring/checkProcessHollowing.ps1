# Get the list of running processes
$processes = Get-Process

# Loop through each process and check if it has been hollowed
foreach ($process in $processes) {

    # Get the process memory information
    $meminfo = Get-Process -Id $process.Id | Select-Object VirtualMemorySize64

    # Get the process image file path
    try {
        $path = (Get-WmiObject -Class Win32_Process -Filter "ProcessId = $($process.Id)" | Select-Object -ExpandProperty ExecutablePath) -replace '"'
    } catch {
        Write-Host "Error: Could not get path of process with PID $($process.Id)"
        continue
    }

    # Get the hash of the process image file
    try {
        $hash = (Get-FileHash $path -Algorithm SHA256).Hash
    } catch {
        Write-Host "Error: Could not get hash of $path"
        continue
    }

    # Check if the process has been hollowed
    $hollowed = $false
    $sections = [System.Diagnostics.ProcessModule]::GetModules($process.Id)
    foreach ($section in $sections) {
        $sectionSize = $section.ModuleMemorySize
        $sectionBaseAddress = $section.BaseAddress.ToInt64()
        $sectionEndAddress = $sectionBaseAddress + $sectionSize
        if ($sectionSize -lt $meminfo.VirtualMemorySize64 -and ($sectionBaseAddress -eq 0 -or $sectionEndAddress -eq $meminfo.VirtualMemorySize64) -and $section.FileVersionInfo.FileDescription -eq $process.ProcessName) {
            $hollowed = $true
            break
        }
    }

    # If the process has been hollowed, print its details
    if ($hollowed) {
        Write-Host "Process $($process.Name) with PID $($process.Id) has been hollowed"
        Write-Host "Image File: $path"
        Write-Host "Image Hash: $hash"
    }
}