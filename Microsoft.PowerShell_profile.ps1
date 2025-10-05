### PowerShell Profile


# Define the path to the file that stores the last execution time
$timeFilePath = [Environment]::GetFolderPath("MyDocuments") + "\PowerShell\LastExecutionTime.txt"

$updateInterval = 1000000

# Initial GitHub.com connectivity check with 1 second timeout
$global:canConnectToGitHub = Test-Connection github.com -Count 1 -Quiet -TimeoutSeconds 1

# Import Modules and External Profiles
# Ensure Terminal-Icons module is installed before importing
if (-not (Get-Module -ListAvailable -Name Terminal-Icons)) {
    Install-Module -Name Terminal-Icons -Scope CurrentUser -Force -SkipPublisherCheck
}

Import-Module -Name Terminal-Icons
$ChocolateyProfile = "$env:ChocolateyInstall\helpers\chocolateyProfile.psm1"
if (Test-Path($ChocolateyProfile)) {
    Import-Module "$ChocolateyProfile"
}

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
    # PSReadLine history path
    $historyFile = (Get-PSReadLineOption).HistorySavePath
    if (Test-Path $historyFile) {
        Remove-Item $historyFile -Force
        Write-Host "History file deleted: $historyFile" -Foreground Yellow
    }
    # also clear memory
    [Microsoft.PowerShell.PSConsoleReadLine]::ClearHistory()
    Write-Host "History completely wiped (disk + memory)." -Foreground Green
}

# Admin Check and Prompt Customization
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
function prompt {
    if ($isAdmin) { "[" + (Get-Location) + "] # " } else { "[" + (Get-Location) + "] $ " }
}
$adminSuffix = if ($isAdmin) { " [ADMIN]" } else { "" }
$Host.UI.RawUI.WindowTitle = "PowerShell {0}$adminSuffix" -f $PSVersionTable.PSVersion.ToString()

function winutil {
    irm https://christitus.com/win | iex
}

function winutildev {
    if (Get-Command -Name "WinUtilDev_Override" -ErrorAction SilentlyContinue) {
        WinUtilDev_Override
    } else {
        irm https://christitus.com/windev | iex
    }
}

function y {
    yazi
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

function reload-profile {
    & $profile
}

function which($name) {
    if ($name){
        Get-Command $name | Select-Object -ExpandProperty Definition
    }else{
        Write-Host "Say something retard" -Foreground Green
    }
}

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
Set-PSReadLineKeyHandler -Chord 'Ctrl+RightArrow' -Function ForwardWord
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

Register-ArgumentCompleter -Native -CommandName git, npm, deno -ScriptBlock $scriptblock

$scriptblock = {
    param($wordToComplete, $commandAst, $cursorPosition)
    dotnet complete --position $cursorPosition $commandAst.ToString() |
        ForEach-Object {
            [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
        }
}
Register-ArgumentCompleter -Native -CommandName dotnet -ScriptBlock $scriptblock

oh-my-posh init pwsh --config https://raw.githubusercontent.com/JanDeDobbeleer/oh-my-posh/main/themes/cobalt2.omp.json | Invoke-Expression
