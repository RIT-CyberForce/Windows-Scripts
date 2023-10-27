# will download other scripts/tools needed

# Workaround for older Windows Versions (need NET 4.5 or above)
# Load zip assembly: [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
# Unzip file: [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)

$ErrorActionPreference = "Stop"
[ValidateScript({
    if(-not (Test-Path -Path $_ -PathType Container))
    {
        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] Invalid path" -ForegroundColor white
	    break
    }
    $true
})]
$InputPath = Read-Host -Prompt "Input absolute path to download files"
Set-Location -Path $InputPath

# Creating all the directories
$ErrorActionPreference = "Continue"
New-Item -Path $InputPath -Name "scripts" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "installers" -ItemType "directory" | Out-Null
New-Item -Path $InputPath -Name "tools" -ItemType "directory" | Out-Null
$ScriptPath = Join-Path -Path $InputPath -ChildPath "scripts"
$SetupPath = Join-Path -Path $InputPath -ChildPath "installers"
$ToolsPath = Join-Path -Path $InputPath -ChildPath "tools"

New-Item -Path $ScriptPath -Name "conf" -ItemType "directory" | Out-Null
New-Item -Path $ScriptPath -Name "results" -ItemType "directory" | Out-Null
$ConfPath = Join-Path -Path $ScriptPath -ChildPath "conf"
$ResultsPath = Join-Path -Path $ScriptPath -ChildPath "results"

New-Item -Path $ResultsPath -Name "artifacts" -ItemType "directory" | Out-Null
New-Item -Path $ToolsPath -Name "sys" -ItemType "directory" | Out-Null
$SysPath = Join-Path -Path $ToolsPath -ChildPath "sys"

Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Directories created" -ForegroundColor white

# DC detection
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "INFO" -ForegroundColor yellow -NoNewLine; Write-Host "] Domain Controller detected" -ForegroundColor white
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/dc/wc-dc-v1.inf", (Join-Path -Path $ConfPath -ChildPath "wc-dc-secpol.inf"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/dc/%7B3B08545D-C4F0-4257-AAE6-4CB64523ECCA%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{3B08545D-C4F0-4257-AAE6-4CB64523ECCA}.zip"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC GPO and security template downloaded" -ForegroundColor white

    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{3B08545D-C4F0-4257-AAE6-4CB64523ECCA}.zip") -DestinationPath (Join-Path -Path $ConfPath -ChildPath "{3B08545D-C4F0-4257-AAE6-4CB64523ECCA}")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC GPO extracted" -ForegroundColor white
} else {
    (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip", (Join-Path -Path $InputPath -ChildPath "lg.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/member-client/wc-member-client-v6.inf", (Join-Path -Path $ConfPath -ChildPath "wc-mc-secpol.inf"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/member-client/%7B4BB1406C-78CC-44D0-B229-A1B9F6753187%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{4BB1406C-78CC-44D0-B229-A1B9F6753187}.zip"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Non-DC GPO, security template, and LGPO downloaded" -ForegroundColor white

    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "lg.zip") -DestinationPath $ToolsPath
    Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{4BB1406C-78CC-44D0-B229-A1B9F6753187}.zip") -DestinationPath (Join-Path -Path $ConfPath -ChildPath "{4BB1406C-78CC-44D0-B229-A1B9F6753187}")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LGPO and non-DC GPO extracted" -ForegroundColor white
}

# Scripts
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/Colin-Dev/audit.ps1", (Join-Path -Path $ScriptPath -ChildPath "audit.ps1"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/usermgmt.ps1", (Join-Path -Path $ScriptPath -ChildPath "bum.ps1"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/inventory.ps1", (Join-Path -Path $ScriptPath -ChildPath "inventory.ps1"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/firewall.ps1", (Join-Path -Path $ScriptPath -ChildPath "firewall.ps1"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/logging.ps1", (Join-Path -Path $ScriptPath -ChildPath "logging.ps1"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/sbaseline.ps1", (Join-Path -Path $ScriptPath -ChildPath "sbaseline.ps1"))
(New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1", (Join-Path -Path $ScriptPath -ChildPath "Get-InjectedThread.ps1"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Scripts downloaded" -ForegroundColor white

# Config files
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/wc-auditpol-v1.csv", (Join-Path -Path $ConfPath -ChildPath "wc-auditpol.csv"))
(New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/defender-exploit-guard-settings.xml", (Join-Path -Path $ConfPath -ChildPath "def-eg-settings.xml"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Audit policy and Defender Exploit Guard settings downloaded" -ForegroundColor white

# Installers for various tools + Sysinternals
(New-Object System.Net.WebClient).DownloadFile("https://www.malwarebytes.com/api/downloads/mb-windows?filename=MBSetup.exe", (Join-Path -Path $SetupPath -ChildPath "MBSetup.exe"))
(New-Object System.Net.WebClient).DownloadFile("https://patchmypc.com/freeupdater/PatchMyPC.exe", (Join-Path -Path $ToolsPath -ChildPath "PatchMyPC.exe"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] MalwareBytes setup and PatchMyPC downloaded" -ForegroundColor white
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Autoruns.zip", (Join-Path -Path $InputPath -ChildPath "ar.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ListDlls.zip", (Join-Path -Path $InputPath -ChildPath "dll.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessExplorer.zip", (Join-Path -Path $InputPath -ChildPath "pe.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessMonitor.zip", (Join-Path -Path $InputPath -ChildPath "pm.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sigcheck.zip", (Join-Path -Path $InputPath -ChildPath "sc.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/TCPView.zip", (Join-Path -Path $InputPath -ChildPath "tv.zip"))
(New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Streams.zip", (Join-Path -Path $InputPath -ChildPath "st.zip"))
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools downloaded" -ForegroundColor white

# Unzip mode
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "ar.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ar")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "dll.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "dll")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pe.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pe")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pm")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "sc.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sc")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "tv.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "tv")
Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "st.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "st")
Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools extracted" -ForegroundColor white