# setting up logging
WevtUtil sl Application /ms:256000
WevtUtil sl System /ms:256000
WevtUtil sl Security /ms:2048000
WevtUtil sl "Windows PowerShell" /ms:512000
WevtUtil sl "Microsoft-Windows-PowerShell/Operational" /ms:512000
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true
Write-Host "[INFO] Log sizes set"

# Powershell logging
$psLogFolder = Join-Path -Path (Get-Item -Path '..').FullName -ChildPath "scrips"
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f | Out-Null
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d $psLogFolder /f | Out-Null
# Process Creation events (4688) include command line arguments
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[INFO] PowerShell and command-line logging set"

# TODO: import audit policy
auditpol /restore /file:"conf\auditpol.csv"
Write-Host "[INFO] System audit policy set"

# Sysmon setup
..\tools\sys\sm\sysmon64.exe -accepteula -i "conf\sysmon.xml"
WevtUtil sl "Microsoft-Windows-Sysmon/Operational" /ms:1048576000
Write-Host "[INFO] Sysmon installed and configured"

# DNS server logging
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    dnscmd /config /loglevel 0x8000F301
    dnscmd /config /logfilemaxsize 0xC800000
    Write-Host "[INFO] DNS Server logging configured"
}

# IIS logging
if (Get-Service -Name W3SVC 2>$null) {
    try {
        C:\Windows\System32\inetsrv\appcmd.exe set config /section:httpLogging /dontLog:False
        Write-Host "[INFO] IIS Logging enabled"
    }
    catch {
        Write-Host "[ERROR] IIS Logging failed"
    }
}

# TODO: CA auditing 
if (Get-Service -Name CertSvc 2>$null) {
    auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
    certutil -setreg policy\EditFlags +EDITF_AUDITCERTTEMPLATELOAD
    Write-Host "[ERROR] CA logging enabled"
}

# setup wazuh agent, config file, backup
Start-Process -FilePath ..\installers\wazuhagent.msi /q WAZUH_MANAGER="10.0.136.143" -Wait
Remove-Item "C:\Program Files (x86)\ossec-agent\ossec.conf" -Force
Copy-Item -Path "conf\ossec_windows.conf" -Destination "C:\Program Files (x86)\ossec-agent\ossec.conf"
net start Wazuh