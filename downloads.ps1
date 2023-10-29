# Objective: downloads scripts/tools needed

# Workaround for older Windows Versions (need NET 4.5 or above)
# Load zip assembly: [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
# Unzip file: [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)

# add logic to ask what box files are being downloaded for
$boxName = Read-Host -Prompt "Enter the AWS name of the box you're downloading files for"
$boxName = $boxName.Trim().ToLower()
$boxes = @("ad/dns","task","cnc")

if ($boxes -contains $boxName) {
    # somehow this block verifies if the path is legit
    $ErrorActionPreference = "Stop"
    [ValidateScript({
        if(-not (Test-Path -Path $_ -PathType Container))
        {
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] Invalid path" -ForegroundColor white
            break
        }
        $true
    })]
    $InputPath = Read-Host -Prompt "Enter absolute path to download files to"
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

    # Wireshark
    # (for now) TLS 1.2 link: https://wireshark.marwan.ma/download/win64/Wireshark-win64-latest.exe
    (New-Object System.Net.WebClient).DownloadFile("https://1.na.dl.wireshark.org/win64/Wireshark-win64-latest.exe", (Join-Path -Path $SetupPath -ChildPath "wsinstall.exe"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Wireshark installer downloaded" -ForegroundColor white
    # VSCode
    (New-Object System.Net.WebClient).DownloadFile("https://code.visualstudio.com/sha/download?build=stable&os=win32-x64-user", (Join-Path -Path $SetupPath -ChildPath "vscodesetup.exe"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] VSCode installer downloaded" -ForegroundColor white

    # Get-InjectedThread
    (New-Object System.Net.WebClient).DownloadFile("https://gist.githubusercontent.com/jaredcatkinson/23905d34537ce4b5b1818c3e6405c1d2/raw/104f630cc1dda91d4cb81cf32ef0d67ccd3e0735/Get-InjectedThread.ps1", (Join-Path -Path $ScriptPath -ChildPath "Get-InjectedThread.ps1"))
    # Audit policy file
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/RIT-CyberForce/Windows-Scripts/main/auditpol.csv", (Join-Path -Path $ConfPath -ChildPath "auditpol.csv"))
    # Wazuh agent
    (New-Object System.Net.WebClient).DownloadFile("https://packages.wazuh.com/4.x/windows/wazuh-agent-4.5.4-1.msi", (Join-Path -Path $SetupPath -ChildPath "wazuhagent.msi"))
    # Wazuh agent conf file
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/RIT-CyberForce/Logging-Scripts/main/ossec_windows.conf", (Join-Path -Path $ConfPath -ChildPath "ossec_windows.conf"))
    # Basic Sysmon conf file
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml", (Join-Path -Path $ConfPath -ChildPath "sysmon.xml"))
    # TODO: insert audit script and backup script
    # (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/Colin-Dev/audit.ps1", (Join-Path -Path $ScriptPath -ChildPath "audit.ps1"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/RIT-CyberForce/Windows-Scripts/main/logging.ps1", (Join-Path -Path $ScriptPath -ChildPath "logging.ps1"))
    (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/RIT-CyberForce/Windows-Scripts/main/inventory.ps1", (Join-Path -Path $ScriptPath -ChildPath "inventory.ps1"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Monitoring scripts, config files, and Wazuh files downloaded" -ForegroundColor white

    # everyone needs sysinternals
    (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Autoruns.zip", (Join-Path -Path $InputPath -ChildPath "ar.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ListDlls.zip", (Join-Path -Path $InputPath -ChildPath "dll.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessExplorer.zip", (Join-Path -Path $InputPath -ChildPath "pe.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/ProcessMonitor.zip", (Join-Path -Path $InputPath -ChildPath "pm.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sigcheck.zip", (Join-Path -Path $InputPath -ChildPath "sc.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/TCPView.zip", (Join-Path -Path $InputPath -ChildPath "tv.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Streams.zip", (Join-Path -Path $InputPath -ChildPath "st.zip"))
    (New-Object System.Net.WebClient).DownloadFile("https://download.sysinternals.com/files/Sysmon.zip", (Join-Path -Path $InputPath -ChildPath "sm.zip"))
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools downloaded" -ForegroundColor white
 
    if ($boxName -ne $boxes[2]) { # trad infra tools only
        # Windows Firewall Control, Malwarebytes, PatchMyPC
        (New-Object System.Net.WebClient).DownloadFile("https://www.binisoft.org/download/wfc6setup.exe", (Join-Path -Path $SetupPath -ChildPath "wfcsetup.exe"))
        (New-Object System.Net.WebClient).DownloadFile("https://www.malwarebytes.com/api/downloads/mb-windows?filename=MBSetup.exe", (Join-Path -Path $SetupPath -ChildPath "MBSetup.exe"))
        (New-Object System.Net.WebClient).DownloadFile("https://patchmypc.com/freeupdater/PatchMyPC.exe", (Join-Path -Path $ToolsPath -ChildPath "PatchMyPC.exe"))
        # Defender exploit guard settings
        (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/RIT-CyberForce/Windows-Scripts/main/defender-exploit-guard-settings.xml", (Join-Path -Path $ConfPath -ChildPath "def-eg-settings.xml"))  
        # user management script
        (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/RIT-CyberForce/Windows-Scripts/main/usermgmt.ps1", (Join-Path -Path $ScriptPath -ChildPath "usermgmt.ps1"))
        # secure baseline script
        (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/RIT-CyberForce/Windows-Scripts/main/secure.ps1", (Join-Path -Path $ScriptPath -ChildPath "sbaseline.ps1"))

        Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Traditional infra tooling downloaded" -ForegroundColor white
        
        # specific tooling for boxes
        if ($boxName -eq $boxes[0]) { # AD/DNS
            # TODO: Downloading GPO and security template
            # (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/dc/wc-dc-v1.inf", (Join-Path -Path $ConfPath -ChildPath "wc-dc-secpol.inf"))
            # (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/dc/%7B3B08545D-C4F0-4257-AAE6-4CB64523ECCA%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{3B08545D-C4F0-4257-AAE6-4CB64523ECCA}.zip"))
            # Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC GPO and security template downloaded" -ForegroundColor white
    
            # Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{3B08545D-C4F0-4257-AAE6-4CB64523ECCA}.zip") -DestinationPath (Join-Path -Path $ConfPath -ChildPath "{3B08545D-C4F0-4257-AAE6-4CB64523ECCA}")
            # Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] DC GPO extracted" -ForegroundColor white
            (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/RIT-CyberForce/Windows-Scripts/main/fw_dns.ps1", (Join-Path -Path $ScriptPath -ChildPath "firewall.ps1"))
 
        } else { # Task box
            (New-Object System.Net.WebClient).DownloadFile("https://download.microsoft.com/download/8/5/C/85C25433-A1B0-4FFA-9429-7E023E7DA8D8/LGPO.zip", (Join-Path -Path $InputPath -ChildPath "lg.zip"))
            # TODO: Downloading GPO and security template 
            # (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/member-client/wc-member-client-v6.inf", (Join-Path -Path $ConfPath -ChildPath "wc-mc-secpol.inf"))
            # (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/CCDC-RIT/Windows-Scripts/master/wc/member-client/%7B4BB1406C-78CC-44D0-B229-A1B9F6753187%7D.zip", (Join-Path -Path $ConfPath -ChildPath "{4BB1406C-78CC-44D0-B229-A1B9F6753187}.zip"))
            
            (New-Object System.Net.WebClient).DownloadFile("https://raw.githubusercontent.com/RIT-CyberForce/Windows-Scripts/main/fw_task.ps1", (Join-Path -Path $ScriptPath -ChildPath "firewall.ps1"))

            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] Non-DC GPO, security template, and LGPO downloaded" -ForegroundColor white
    
            Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "lg.zip") -DestinationPath $ToolsPath
            # Expand-Archive -LiteralPath (Join-Path -Path $ConfPath -ChildPath "{4BB1406C-78CC-44D0-B229-A1B9F6753187}.zip") -DestinationPath (Join-Path -Path $ConfPath -ChildPath "{4BB1406C-78CC-44D0-B229-A1B9F6753187}")
            Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] LGPO and non-DC GPO extracted" -ForegroundColor white
        }
    }

    # Unzip mode
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "ar.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "ar")
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "dll.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "dll")
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pe.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pe")
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "pm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "pm")
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "sc.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sc")
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "tv.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "tv")
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "st.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "st")
    Expand-Archive -LiteralPath (Join-Path -Path $InputPath -ChildPath "sm.zip") -DestinationPath (Join-Path -Path $SysPath -ChildPath "sm")
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "SUCCESS" -ForegroundColor green -NoNewLine; Write-Host "] SysInternals tools extracted" -ForegroundColor white
} else {
    Write-Host "[" -ForegroundColor white -NoNewLine; Write-Host "ERROR" -ForegroundColor red -NoNewLine; Write-Host "] Invalid name" -ForegroundColor white
    exit 1
}
