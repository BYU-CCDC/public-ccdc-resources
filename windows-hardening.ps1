$param1 = $args[0]
$testing = $args[1]
# $workingDirectory = <Path to working directory>
$workingDirectory = $param1 -eq "-d" ? $pwd : "yeah"
$checker = $false

function Get-ScreenCapture([int]$Wait, [string]$FileType) {
    Start-Sleep -Seconds $Wait
    $File = ""
    for ($i = 0; $i -lt 10000; $i++) {
        $path = Test-Path -Path "$workingDirectory\$FileType-$i.bmp"
        if(-Not $path) {
            $File = "$workingDirectory\$FileType-$i.bmp"
            break
        }
        else {
            # do nothing
        }
    }
    Add-Type -AssemblyName System.Windows.Forms
    Add-type -AssemblyName System.Drawing
    # Gather Screen resolution information
    $Screen = [System.Windows.Forms.SystemInformation]::VirtualScreen
    $Width = $Screen.Width
    $Height = $Screen.Height
    $Left = $Screen.Left
    $Top = $Screen.Top
    # Create bitmap using the top-left and bottom-right bounds
    $bitmap = New-Object System.Drawing.Bitmap $Width, $Height
    # Create Graphics object
    $graphic = [System.Drawing.Graphics]::FromImage($bitmap)
    # Capture screen
    $graphic.CopyFromScreen($Left, $Top, 0, 0, $bitmap.Size)
    # Save to file
    $bitmap.Save($File) 
    Write-Output "Screenshot saved to:"
    Write-Output $File
}

if ((Test-Path "$workingDirectory\AutoRuns") -and (-Not $testing)) {
    Get-ChildItem -Path  $workingDirectory -Recurse -exclude "*.ps1" |
    Select-Object -ExpandProperty FullName |
    Where-Object {$_ -notlike "$workingDirectory\*.ps1"} |
    Sort-Object length -Descending |
    Remove-Item -force
}

Start-Process resmon.exe -WindowStyle Maximized

$checker = $false
Read-Host -Prompt "Loaded?"
Get-ScreenCapture -Wait 0 -FileType "resmon"

if(-Not (Test-Path "$workingDirectory\Autoruns.zip")) {
    try {
        Invoke-WebRequest -Uri "http://download.sysinternals.com/files/Autoruns.zip" -OutFile "$workingDirectory\Autoruns.zip"
        Write-Host "worked"
    }
    catch {
        Write-Host "Error downloading Autoruns64.exe"
    }
}

$checker = $false
if(-Not (Test-Path "$workingDirectory\Autoruns")) {
    while ($checker -eq $false) {
        try {
            Expand-Archive -Path "$workingDirectory\Autoruns.zip" -DestinationPath "$workingDirectory\Autoruns"
            $checker = $true
        }
        catch {
            Write-Host "Error extracting Autoruns64.exe"
        }
    }
}

$checker = $false
while ($checker -eq $false) {
    try {
        .\AutoRuns\Autoruns64.exe
        $checker = $true
    }
    catch {
        Write-Host "Error running Autoruns64.exe"
    }
}

Read-Host -Prompt "Loaded?"
Get-ScreenCapture -Wait 0 -FileType "AutoRuns"
Read-Host -Prompt "Loaded?"
Get-ScreenCapture -Wait 0 -FIleType "AutoRuns"
invoke-expression 'cmd /c start powershell -Command { netstat; Read-Host }'

explorer .

# TinyURL for this file: https://tinyurl.com/54eenapr
