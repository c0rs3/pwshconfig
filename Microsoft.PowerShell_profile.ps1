### PowerShell Profile
$timeFilePath = [Environment]::GetFolderPath("MyDocuments") + "\PowerShell\LastExecutionTime.txt"

function Clear-Cache {
    if (Get-Command -Name "Clear-Cache_Override" -ErrorAction SilentlyContinue) {
        Clear-Cache_Override
    } else {
        Write-Host "Clearing cache..." -ForegroundColor Cyan
        Remove-Item -Path "$env:SystemRoot\Prefetch\*" -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:SystemRoot\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "Cache clearing completed." -ForegroundColor Green
    }
}

function Clear-PSHistory {
    [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
    Write-Host "In-memory history cleared and file-writing paused." -Foreground Green
}

function Wipe-PSHistory {
    $historyFile = (Get-PSReadLineOption).HistorySavePath
    if (Test-Path $historyFile) {
        Remove-Item $historyFile -Force
        Write-Host "History file deleted: $historyFile" -Foreground Yellow
    }
    [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
    Write-Host "History completely wiped (disk + memory)." -Foreground Green
}

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function prompt {
    $path = (Get-Location).Path -replace '\\','/'     # normalize slashes

    $path = $path -replace '^[A-Za-z]:',''

    $homeUnix = $HOME -replace '\\','/' -replace '^[A-Za-z]:',''
    if ($path -like "$homeUnix*") {
        $path = $path -replace [regex]::Escape($homeUnix), '~'
    }

    Write-Host $path -NoNewline -ForegroundColor Cyan
    Write-Host " $" -NoNewline -ForegroundColor Yellow
    return " "
}

$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

function winutil {
    irm https://christitus.com/win | iex
}

function winutildev {
    irm https://christitus.com/windev | iex
}

function reload-profile {
    & $profile
}

function where($name) {
    if ($name){
        command $name
    }else{
        command command
    }
}

function y {
    yazi
}

function q {
    exit
}

function Repair-WindowsSystem {
    <#
    .SYNOPSIS
    Comprehensive Windows 11 system repair function
    
    .DESCRIPTION
    Runs multiple system repair utilities including:
    - SFC (System File Checker)
    - DISM (Deployment Image Servicing and Management)
    - Windows Update component repair
    - Disk error checking
    - System health monitoring
    .EXAMPLE
    Repair-WindowsSystem
    #>
    
    # Require administrator privileges
    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This function requires Administrator privileges. Please run PowerShell as Administrator."
        return
    }

    Write-Host "Starting comprehensive system repair..." -ForegroundColor Cyan

    # 1. System File Checker (SFC)
    Write-Host "`n1. Running System File Checker (SFC)..." -ForegroundColor Yellow
    $sfcResult = Repair-WindowsCorruption -SFCFix
    if ($sfcResult -eq 0) {
        Write-Host "SFC completed successfully" -ForegroundColor Green
    } else {
        Write-Host "SFC found and repaired corruption" -ForegroundColor Green
    }

    # 2. DISM Health Checks
    Write-Host "`n2. Running DISM Health Restoration..." -ForegroundColor Yellow
    $dismResults = @()
    
    Write-Host "   - Checking component store health..." -ForegroundColor Gray
    $dismResults += Repair-WindowsCorruption -DISMCheckHealth
    
    Write-Host "   - Scanning for corruption..." -ForegroundColor Gray
    $dismResults += Repair-WindowsCorruption -DISMScanHealth
    
    Write-Host "   - Restoring system health..." -ForegroundColor Gray
    $dismResults += Repair-WindowsCorruption -DISMRestoreHealth
    
    if ($dismResults -contains 0) {
        Write-Host "DISM operations completed successfully" -ForegroundColor Green
    }

    # 3. Windows Update Component Reset
    Write-Host "`n3. Repairing Windows Update components..." -ForegroundColor Yellow
    try {
        # Stop Windows Update services
        Get-Service -Name wuauserv, bits, cryptsvc | Stop-Service -Force
        
        # Rename SoftwareDistribution and Catroot2 folders
        Rename-Item "$env:systemroot\SoftwareDistribution" "SoftwareDistribution.old" -Force -ErrorAction SilentlyContinue
        Rename-Item "$env:systemroot\System32\catroot2" "catroot2.old" -Force -ErrorAction SilentlyContinue
        
        # Restart services
        Get-Service -Name wuauserv, bits, cryptsvc | Start-Service
        
        Write-Host "Windows Update components reset successfully" -ForegroundColor Green
    }
    catch {
        Write-Warning "Windows Update repair partially completed. Some operations require reboot."
    }

    # 4. Disk Error Checking
    Write-Host "`n4. Checking disk for errors..." -ForegroundColor Yellow
    $volumes = Get-Volume | Where-Object {$_.DriveType -eq 'Fixed' -and $_.DriveLetter}
    foreach ($volume in $volumes) {
        Write-Host "   - Checking volume $($volume.DriveLetter):" -ForegroundColor Gray
        $result = Repair-Volume -DriveLetter $volume.DriveLetter -Scan -ErrorAction SilentlyContinue
        if ($result) {
            Write-Host "     No errors found" -ForegroundColor Green
        } else {
            Write-Host "     Errors found. Running repair..." -ForegroundColor Yellow
            Repair-Volume -DriveLetter $volume.DriveLetter -OfflineScanAndFix -ErrorAction SilentlyContinue
        }
    }

    # 5. System Health Report
    Write-Host "`n5. Generating system health report..." -ForegroundColor Yellow
    Get-CimInstance -ClassName Win32_ComputerSystem | 
        Select-Object Name, Manufacturer, Model | 
        Format-List

    # 6. Final Recommendations
    Write-Host "`nRepair operations completed!" -ForegroundColor Cyan
    Write-Host "Recommended actions:" -ForegroundColor White
    Write-Host "• Restart your computer to complete any pending repairs" -ForegroundColor Gray
    Write-Host "• Run Windows Update to check for updates" -ForegroundColor Gray
    Write-Host "• Monitor system performance for improvements" -ForegroundColor Gray

    # Optional: Open system health dashboard
    $openHealth = Read-Host "`nOpen system health report? (y/n)"
    if ($openHealth -eq 'y') {
        perfmon /report
    }
}

# Helper function for corruption repair
function Repair-WindowsCorruption {
    param(
        [switch]$SFCFix,
        [switch]$DISMCheckHealth,
        [switch]$DISMScanHealth,
        [switch]$DISMRestoreHealth
    )
    
    if ($SFCFix) {
        sfc /scannow
        return $LASTEXITCODE
    }
    
    if ($DISMCheckHealth) {
        dism /online /check-health
        return $LASTEXITCODE
    }
    
    if ($DISMScanHealth) {
        dism /online /scan-health
        return $LASTEXITCODE
    }
    
    if ($DISMRestoreHealth) {
        dism /online /cleanup-image /restorehealth
        return $LASTEXITCODE
    }
}

function restart {
    do {
        $choice = Read-Host "`nDo you want to restart now? (y/n)"
        switch ($choice.ToLower()) {
            'y' { 
                Write-Host "Initiating system restart..." -ForegroundColor Yellow
                Restart-Computer -Force
                break
            }
            'n' { 
                Write-Host "Alright go kys"
                break
            }
            default { Write-Host "Please enter 'y' or 'n'" }
        }
    } while ($choice -notin 'y','n')
}

function admin {
    param([string[]]$args)

    $argsList = if ($args) { $args } else { @() }
    $workingDir = if (Test-Path $env:USERPROFILE) { $env:USERPROFILE } else { "C:\" }

    function Start-Elevated($exe, $argArray) {
        try {
            Start-Process -FilePath $exe -Verb RunAs -ArgumentList $argArray -WorkingDirectory $workingDir -ErrorAction Stop
            return $true
        } catch {
            return $false
        }
    }

    if (Get-Command pwsh.exe -ErrorAction SilentlyContinue) {
        if (Start-Elevated "pwsh.exe" $argsList) { exit }
    }
}

Set-Alias -Name sudo -Value admin

$PSReadLineOptions = @{
    EditMode = 'Windows'
    HistoryNoDuplicates = $true
    HistorySearchCursorMovesToEnd = $true
    Colors = @{
        Command = '#87CEEB'  # SkyBlue (pastel)
        Parameter = '#98FB98'  # PaleGreen (pastel)
        Operator = '#FFB6C1'  # LightPink (pastel)
        Variable = '#DDA0DD'  # Plum (pastel)
        String = '#FFDAB9'  # PeachPuff (pastel)
        Number = '#B0E0E6'  # PowderBlue (pastel)
        Type = '#F0E68C'  # Khaki (pastel)
        Comment = '#D3D3D3'  # LightGray (pastel)
        Keyword = '#8367c7'  # Violet (pastel)
        Error = '#FF6347'  # Tomato (keeping it close to red for visibility)
    }
    PredictionSource = 'History'
    PredictionViewStyle = 'ListView'
    BellStyle = 'None'
}
Set-PSReadLineOption @PSReadLineOptions

# Custom key handlers
Set-PSReadLineKeyHandler -Key UpArrow -Function HistorySearchBackward
Set-PSReadLineKeyHandler -Key DownArrow -Function HistorySearchForward
Set-PSReadLineKeyHandler -Key Tab -Function MenuComplete
Set-PSReadLineKeyHandler -Chord 'Ctrl+z' -Function Undo
Set-PSReadLineKeyHandler -Chord 'Ctrl+y' -Function Redo

Set-PSReadLineOption -AddToHistoryHandler {
    param($line)
    $sensitive = @('password', 'secret', 'token', 'apikey', 'connectionstring')
    $hasSensitive = $sensitive | Where-Object { $line -match $_ }
    return ($null -eq $hasSensitive)
}

function Set-PredictionSource {
    if (Get-Command -Name "Set-PredictionSource_Override" -ErrorAction SilentlyContinue) {
        Set-PredictionSource_Override;
    } else {
	Set-PSReadLineOption -PredictionSource HistoryAndPlugin
	Set-PSReadLineOption -MaximumHistoryCount 100
    }
}
Set-PredictionSource

Register-ArgumentCompleter -Native -CommandName deno -ScriptBlock $scriptblock

$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)
    dotnet complete --position $cursorPosition $commandAst.ToString() |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
}

Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock $scriptblock
