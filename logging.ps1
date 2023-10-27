# setting up logging
WevtUtil sl Application /ms:256000
WevtUtil sl System /ms:256000
WevtUtil sl Security /ms:2048000
WevtUtil sl "Windows PowerShell" /ms:512000
WevtUtil sl "Microsoft-Windows-PowerShell/Operational" /ms:512000
wevtutil sl "Microsoft-Windows-DNS-Client/Operational" /e:true
Write-Host "[INFO] Log sizes set"

# Powershell logging
mkdir C:\scrips
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d C:\scrips /f
# Process Creation events (4688) include command line arguments
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f | Out-Null
Write-Host "[INFO] PowerShell and command-line logging set"

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