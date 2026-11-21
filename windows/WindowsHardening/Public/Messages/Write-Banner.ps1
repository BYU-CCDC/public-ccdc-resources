#Requires -Version 5.1

# Write-Banner.ps1 - Section and sub-section headers.

function Write-Banner {
    <#
    .SYNOPSIS
        Writes a section header.
    .DESCRIPTION
        Box style (sections):

            ========================================
              Title
              Body line
            ========================================

        Inline style (sub-sections): === Title ===
    .PARAMETER Title
        Header text.
    .PARAMETER Body
        Extra lines inside a box, below the title (Box style only).
    .PARAMETER Style
        Box (default) or Inline.
    .PARAMETER Color
        Title color. Default: Green for Box, Cyan for Inline.
    .PARAMETER Width
        Box width in characters. Default: 40.
    .PARAMETER Log
        Also write the header to the log file. Box banners always do (a section marker);
        inline banners only with -Log, since most are display grouping (menus, lists).
    .EXAMPLE
        Write-Banner "User & Credential Hardening"
    .EXAMPLE
        Write-Banner "Pre-flight Checks" -Style Inline
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Title,

        [string[]]$Body,

        [ValidateSet('Box', 'Inline')]
        [string]$Style = 'Box',

        [ConsoleColor]$Color,

        [ValidateRange(10, 200)]
        [int]$Width = 40,

        [switch]$Log
    )

    if ($Style -eq 'Inline') {
        $titleColor = if ($PSBoundParameters.ContainsKey('Color')) { $Color } else { 'Cyan' }
        Write-Host "`n=== $Title ===" -ForegroundColor $titleColor
        if ($Log) { Write-Log -Level INFO -Message "=== $Title ===" }
        return
    }

    $titleColor = if ($PSBoundParameters.ContainsKey('Color')) { $Color } else { 'Green' }
    $border = '=' * $Width
    Write-Host "`n$border" -ForegroundColor Cyan
    Write-Host "  $Title" -ForegroundColor $titleColor
    foreach ($line in $Body) {
        Write-Host "  $line" -ForegroundColor White
    }
    Write-Host $border -ForegroundColor Cyan

    Write-Log -Level INFO -Message "===== $Title ====="
    foreach ($line in $Body) {
        Write-Log -Level INFO -Message $line
    }
}
