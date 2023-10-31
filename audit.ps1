$VerbosePreference = "SilentlyContinue"
$currentDir = Get-Location
$firewallPath = Join-Path -Path $currentDir -ChildPath 'results\firewallaudit.txt'
$registryPath = Join-Path -Path $currentDir -ChildPath 'results\registryaudit.txt'
$processPath = Join-Path -Path $currentDir -ChildPath 'results\processaudit.txt'
$thruntingPath = Join-Path -Path $currentDir -ChildPath 'results\threathuntingaudit.txt'
$windowsPath = Join-Path -Path $currentDir -ChildPath 'results\windowsaudit.txt'
$aclPath = Join-Path -Path $currentDir -ChildPath 'results\aclaudit.txt'
#split into different files

Function Show-Firewall{#good
    function Get-FirewallProfiles {
        $profiles = Get-NetFirewallProfile | Select-Object -Property Name, Enabled
        return $profiles
    }
    function Get-FirewallRulesForProfile {
        param (
            [string]$ProfileName
        )
        $rules = Get-NetFirewallRule | Where-Object { $_.Profile -contains $ProfileName } | Select-Object -Property Name, DisplayName, Direction, Action, Enabled
        return $rules
    }
    $firewallProfiles = Get-FirewallProfiles
    foreach ($profile in $firewallProfiles){
        Write-Output "Firewall Profile: $($profile.Name)"
        Write-Output "Enabled: $($profile.Enabled)"
        $profileName = $profile.Name
        $rules = Get-FirewallRulesForProfile -ProfileName $profileName
        Write-Output "========================================================="
        foreach ($rule in $rules){
            Write-Output "Rule Name: $($rule.Name)"
            Write-Output "Display Name: $($rule.DisplayName)"
            Write-Output "Direction: $($rule.Direction)"
            Write-Output "Action: $($rule.Action)"
            Write-Output "Enabled: $($rule.Enabled)"
        }
        Write-Output "End Profile : $($profile.Name)"
    }
}

Function Process-Audit{#good
    $processList = Get-Process -IncludeUserName | Format-List
    Write-Output "Process List with Usernames: "
    Write-Output "$($processList)"
}

Function Hidden-Services{#not good
    $hidden = Compare-Object -ReferenceObject (Get-Service | Select-Object -ExpandProperty Name | % { $_ -replace "_[0-9a-f]{2,8}$" } ) -DifferenceObject (gci -path hklm:\system\currentcontrolset\services | % { $_.Name -Replace "HKEY_LOCAL_MACHINE\\","HKLM:\" } | ? { Get-ItemProperty -Path "$_" -name objectname -erroraction 'ignore' } | % { $_.substring(40) }) -PassThru | ?{$_.sideIndicator -eq "=>"}
    Write-Output "Hidden Service List: "
    Write-Output "$($hidden)"
}

Function Scheduled-Tasks{#good
    $scheduled = Get-ScheduledTask | Format-List
    Write-Output "Scheduled Task List: "
    Write-Output "$($scheduled)"
}

Function StartUp-Programs{ #good
    $startup = Get-CimInstance -ClassName Win32_StartupCommand | Select-Object -Property Command, Description, User, Location
    Write-Output "$($startup)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders")"
}

Function StratUp-Scripts{#good cant find reg keys 
    Write-Output "$(reg query "HKLM\Software\Policies\Microsoft\Windows\System\Scripts" /s)"
    Write-Output "$(reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\Group Policy\Scripts" /s)"
    Write-Output "$(reg query "HKCU\Software\Policies\Microsoft\Windows\System\Scripts" /s)"
}

Function Boot-Keys{ #good
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot" /v "AlternateShell")"
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager" /v "BootExecute")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Output "$(reg query "HKCU\SOFTWARE\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
    Write-Output "$(reg query "HKCU\SOFTWARE\Wow6432Node\Microsoft\Active Setup\Installed Components" /s /v "StubPath")"
}

Function Startup-Services{ #good can't find reg key
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Output "$(reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Output "$(reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
    Write-Output "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices")"
    Write-Output "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce")"
}

Function Run-Keys{ #good - could not find smoe of the regs keys 
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Output "$(reg query "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Output "$(reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Output "$(reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Output "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run")"
    Write-Output "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce")"
    Write-Output "$(reg query "HKCU\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx")"
    Write-Output "$(reg query "HKCU\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run")"
    Write-Output "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run")"
    Write-Output "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce")"
    Write-Output "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\RunonceEx")"
    Write-Output "$(reg query "HKLM\System\CurrentControlSet\Control\Terminal Server\Wds\rdpwd\StartupPrograms")"
}

Function RDP-Debugger-Persistance{
    Write-Output "$(reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs" /s /v "StartExe")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v "Debugger")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options" /s /v "Debugger")"
    Write-Output "RDP enabled if 0, disabled if 1"
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections")"
}

Function COM-Hijacking{
    Write-Output "$(reg query "HKLM\Software\Classes\Protocols\Filter" /s)"
    Write-Output "$(reg query "HKLM\Software\Classes\Protocols\Handler" /s)"
    Write-Output "$(reg query "HKLM\Software\Classes\CLSID" /s /v "InprocServer32")"
    Write-Output "$(reg query "HKLM\Software\Classes\CLSID" /s /v "LocalServer32")"
    Write-Output "$(reg query "HKLM\Software\Classes\CLSID" /s /v "TreatAs")"
    Write-Output "$(reg query "HKLM\Software\Classes\CLSID" /s /v "ProcID")"
}

Function Password-Filter{
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Notification Packages")"
}

Function Authentication-Packages{
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Authentication Packages")"
}

Function Security-Packages{
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "Security Packages" )"
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig" /v "Security Packages")"
}

Function Security-Providers{
    Write-Output "Including WDigest"
    Write-Output "$(reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders" /v SecurityProviders)"
    Write-Output "$(reg query "HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest")"
}

Function Networker-Provider-Order{
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\NetworkProvider\Order" /v "ProviderOrder")"
}

Function Netsh-DLL{
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\NetSh")"
    Write-Output "$(reg query "HKLM\SOFTWARE\WOW6432Node\Microsoft\NetSh")"
}

Function AppInit-DLL{
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs)"
}

Function AppCert-DLL{
    Write-Output "$(reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCertDLLs")"
}

Function Winlogon-DLL{
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Notify)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Shell)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Userinit)"
    Write-Output "$(reg query "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon" /v Notify)"
}

Function Print-Monitor-Ports{
    Write-Output "$(reg query "HKLM\System\CurrentControlSet\Control\Print\Monitors" /s)"
}

Function Windows-Defender-Exclusions{
    $exclusions = Get-MpPreference | findstr /b Exclusion
    Write-Output "$($exclusions)"
}

Function Injected-Threads{
    .\Get-InjectedThread.ps1
}

Function Random-Directories{
    $sus = @("C:\Intel", "C:\Temp")
    foreach ($directory in $sus){
        Write-Output "$(Get-ChildItem $directory)"
    }
}

Function Exporting-Sec-Policy{
    SecEdit /export /cfg "results\artifacts\old_secpol.cfg"
}

Function Current-local-gpo{
    # Use auditpol to get the current local gpo
    gpresult /h "results\artifacts\LocalGrpPolReport.html"
}

Function Programs-Registry{
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /v "DisplayName")"
    Write-Output "$(reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /v "UninstallString")"
}

Function Unsigned-Files{
    ..\tools\sys\sc\sigcheck64 -accepteula -u -e c:\windows\system32
}

Function Ripper{
    # Function to check if the service's binary path is suspicious
    function IsSuspiciousPath($path) {
        return ($path -like "C:\Users\*")
    }

    # Function to check if the service's binary is unsigned
    function IsUnsigned($path) {
        try {
            $Signatures = Get-AuthenticodeSignature -FilePath $path
            return ($Signatures.Status -ne "Valid")
        }
        catch {
            return $true
        }
    }

    # Function to check if the service has a suspicious file extension
    function HasSuspiciousExtension($path) {
        $suspiciousExtensions = @('.vbs', '.js', '.bat', '.cmd', '.scr')
        $extension = [IO.Path]::GetExtension($path)
        return ($suspiciousExtensions -contains $extension)
    }

    $AllServices = Get-WmiObject -Class Win32_Service
    # Create an empty array to store detected suspicious services
    $DetectedServices = New-Object System.Collections.ArrayList
    foreach ($Service in $AllServices){
        $BinaryPathName = $Service.PathName.Trim('"')
        # Check for suspicious characteristics
        $PathSuspicious = IsSuspiciousPath($BinaryPathName)
        $LocalSystemAccount = ($Service.StartName -eq "LocalSystem")
        $NoDescription = ([string]::IsNullOrEmpty($Service.Description))
        $Unsigned = IsUnsigned($BinaryPathName)
        $SuspiciousExtension = HasSuspiciousExtension($BinaryPathName)
        if ($PathSuspicious -or $LocalSystemAccount -or $NoDescription -or $Unsigned -or $SuspiciousExtension){
            $DetectedServices.Add($Service) | Out-Null
        }
    }
    if ($DetectedServices.Count -gt 0) {
        Write-Output "Potentially Suspicious Services Detected"
        Write-Output "----------------------------------------"
        foreach ($Service in $DetectedServices) {
            Write-Output "Name: $($Service.Name) - Display Name: $($Service.DisplayName) - Status: $($Service.State) - StartName: $($Service.StartName) - Description: $($Service.Description) - Binary Path: $($Service.PathName.Trim('"'))"
            # Output verbose information about each suspicious characteristic
            if ($PathSuspicious) {
                Write-Output "`t- Running from a potentially suspicious path`n"
            }
            if ($LocalSystemAccount) {
                Write-Output "`t- Running with a LocalSystem account`n"
            }
            if ($NoDescription) {
                Write-Output "`t- No description provided`n"
            }
            if ($Unsigned) {
                Write-Output "`t- Unsigned executable`n"
            }
            if ($SuspiciousExtension) {
                Write-Output "`t- Suspicious file extension`n"
            }
            Write-Output ""
        }
    } else {
        Write-Output "No potentially suspicious services detected.`n"
    }
}
#only if server 
Function Windows-Features{
    $featureList = Get-WindowsFeature | Where-Object Installed
    Write-Output "Windows Features"
    Write-Output "$(featureList)"
}

Function Uninstall-Keys{
    $productNames = @("*google*")
    $UninstallKeys = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
                        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
                        )
    $results = foreach ($key in (Get-ChildItem $UninstallKeys) ) {
        foreach ($product in $productNames) {
            if ($key.GetValue("DisplayName") -like "$product") {
                [pscustomobject]@{
                    KeyName = $key.Name.split('\')[-1];
                    DisplayName = $key.GetValue("DisplayName");
                    UninstallString = $key.GetValue("UninstallString");
                    Publisher = $key.GetValue("Publisher");
                }
            }
        }
    }
    $results
}

Function Service-CMD-Line{
    # Get a list of all services
    $services = Get-Service

    # Iterate through each service and retrieve command line arguments
    foreach ($service in $services) {
        $serviceName = $service.DisplayName
        $serviceStatus = $service.Status
        $serviceCommand = $null

        try {
            # Access the service's executable path which typically contains command line arguments
            $serviceCommand = (Get-CimInstance Win32_Service | Where-Object { $_.Name -eq $serviceName }).PathName
        }
        catch {
            $serviceCommand = "Error: Unable to retrieve command line arguments"
        }

        # Output service information
        Write-Output "`nService Name: $serviceName"
        Write-Output "`nService Status: $serviceStatus"
        Write-Output "`nCommand Line Arguments: $serviceCommand"
        Write-Output "`n-----------------------------------"
    }
}

Function UnquotedServicePathCheck {
    Write-Output "Fetching the list of services, this may take a while...";
    $services = Get-WmiObject -Class Win32_Service | Where-Object { $_.PathName -inotmatch "`"" -and $_.PathName -inotmatch ":\\Windows\\" -and ($_.StartMode -eq "Auto" -or $_.StartMode -eq "Manual") -and ($_.State -eq "Running" -or $_.State -eq "Stopped") };
    if ($($services | Measure-Object).Count -lt 1) {
    Write-Output "No unquoted service paths were found";
    }
    else {
        $services | ForEach-Object {
            Write-Output "Unquoted Service Path found!`n" -ForegroundColor red
            Write-Output `nName: $_.Name
            Write-Output `nPathName: $_.PathName
            Write-Output `nStartName: $_.StartName 
            Write-Output `nStartMode: $_.StartMode
            Write-Output `nRunning: $_.State
        } 
    }
}

Function Recently-Run-Commands{
    Get-ChildItem HKU:\ -ErrorAction SilentlyContinue | ForEach-Object {
        # get the SID from output
        $HKUSID = $_.Name.Replace('HKEY_USERS\', "")
        $property = (Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -ErrorAction SilentlyContinue).Property
        $HKUSID | ForEach-Object {
            if (Test-Path "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") {
                Write-Output -ForegroundColor Blue "=========||HKU Recently Run Commands"
                foreach ($p in $property) {
                    Write-Output "$((Get-Item "HKU:\$_\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"-ErrorAction SilentlyContinue).getValue($p))" 
                }
            }
        }
    }
}

function Get-ConsoleHostHistory {
    Write-Output $(Get-Content (Get-PSReadLineOption).HistorySavePath | Select-String pa)
    $historyFilePath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
    if (Test-Path $historyFilePath) {
        try {
            $historyContent = Get-Content -Path $historyFilePath
            Write-Output "Console Host Command History:"
            Write-Output "-----------------------------"
            foreach ($command in $historyContent) {
                Write-Output $command
            }
        }
        catch {
            Write-Error "Error occurred while reading the console host history: $_"
        }
    }
    else {
        Write-Warning "Console host history file not found."
    }
}

function Get-Installed{
    Get-CimInstance -class win32_Product | Select-Object Name, Version | 
    ForEach-Object {
        Write-Output $("{0} : {1}" -f $_.Name, $_.Version)  
    }
}

Function Start-ACLCheck {
    param(
        $Target, $ServiceName)
    # Gather ACL of object
    if ($null -ne $target) {
        try {
            $ACLObject = Get-Acl $target -ErrorAction SilentlyContinue
        }
        catch { $null }
        
        # If Found, Evaluate Permissions
        if ($ACLObject) { 
            $Identity = @()
            $Identity += "$env:COMPUTERNAME\$env:USERNAME"
            if ($ACLObject.Owner -like $Identity ) { Write-Output "$Identity has ownership of $Target" -ForegroundColor Red }
            whoami.exe /groups /fo csv | ConvertFrom-Csv | Select-Object -ExpandProperty 'group name' | ForEach-Object { $Identity += $_ }
            $IdentityFound = $false
            foreach ($i in $Identity) {
                $permission = $ACLObject.Access | Where-Object { $_.IdentityReference -like $i }
                $UserPermission = ""
                switch -WildCard ($Permission.FileSystemRights) {
                    "FullControl" { $userPermission = "FullControl"; $IdentityFound = $true }
                    "Write*" { $userPermission = "Write"; $IdentityFound = $true }
                    "Modify" { $userPermission = "Modify"; $IdentityFound = $true }
                }
                Switch ($permission.RegistryRights) {
                    "FullControl" { $userPermission = "FullControl"; $IdentityFound = $true }
                }
                if ($UserPermission) {
                    if ($ServiceName) { Write-Output "$ServiceName found with permissions issue:" -ForegroundColor Red }
                    Write-Output -ForegroundColor red  "Identity $($permission.IdentityReference) has '$userPermission' perms for $Target"
                }
            }    
            # Identity Found Check - If False, loop through and stop at root of drive
            if ($IdentityFound -eq $false) {
                if ($Target.Length -gt 3) {
                    $Target = Split-Path $Target
                    Start-ACLCheck $Target -ServiceName $ServiceName
                }
            }
        }
        else {
        # If not found, split path one level and Check again
            $Target = Split-Path $Target
            Start-ACLCheck $Target $ServiceName
        }
    }
}

Function Get-Process-ACL{
    Get-Process | Select-Object Path -Unique | ForEach-Object { Start-ACLCheck -Target $_.path }
}

Function Get-Registry-ACL{
    Get-ChildItem 'HKLM:\System\CurrentControlSet\services\' | ForEach-Object {
        $target = $_.Name.Replace("HKEY_LOCAL_MACHINE", "hklm:")
        Start-aclcheck -Target $target
    }
}

Function Get-ScheduledTask-ACL{
    if (Get-ChildItem "c:\windows\system32\tasks" -ErrorAction SilentlyContinue) {
        Write-Output "Access confirmed, may need futher investigation"
        Get-ChildItem "c:\windows\system32\tasks"
    }
    else {
        Write-Output "No admin access to scheduled tasks folder."
        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" } | ForEach-Object {
            $Actions = $_.Actions.Execute
            if ($Actions -ne $null) {
                foreach ($a in $actions) {
                    if ($a -like "%windir%*") { $a = $a.replace("%windir%", $Env:windir) }
                    elseif ($a -like "%SystemRoot%*") { $a = $a.replace("%SystemRoot%", $Env:windir) }
                    elseif ($a -like "%localappdata%*") { $a = $a.replace("%localappdata%", "$env:UserProfile\appdata\local") }
                    elseif ($a -like "%appdata%*") { $a = $a.replace("%localappdata%", $env:Appdata) }
                    $a = $a.Replace('"', '')
                    Start-ACLCheck -Target $a
                    Write-Output "`n"
                    Write-Output "TaskName: $($_.TaskName)"
                    Write-Output "-------------"
                    [pscustomobject]@{
                        LastResult = $(($_ | Get-ScheduledTaskInfo).LastTaskResult)
                        NextRun    = $(($_ | Get-ScheduledTaskInfo).NextRunTime)
                        Status     = $_.State
                        Command    = $_.Actions.execute
                        Arguments  = $_.Actions.Arguments 
                    } | Write-Output
                } 
            }
        }
    }
}

Function Get-Startup-ACL{
    @("C:\Documents and Settings\All Users\Start Menu\Programs\Startup",
    "C:\Documents and Settings\$env:Username\Start Menu\Programs\Startup", 
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", 
    "$env:Appdata\Microsoft\Windows\Start Menu\Programs\Startup") | ForEach-Object {
        if (Test-Path $_) {
            # CheckACL of each top folder then each sub folder/file
            Start-ACLCheck $_
            Get-ChildItem -Recurse -Force -Path $_ | ForEach-Object {
                $SubItem = $_.FullName
                if (Test-Path $SubItem) { 
                    Start-ACLCheck -Target $SubItem
                }
            }
        }
    }
    @("registry::HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
    "registry::HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
    "registry::HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce") | ForEach-Object {
    # CheckACL of each Property Value found
        $ROPath = $_
        (Get-Item $_) | ForEach-Object {
            $ROProperty = $_.property
            $ROProperty | ForEach-Object {
                Start-ACLCheck ((Get-ItemProperty -Path $ROPath).$_ -split '(?<=\.exe\b)')[0].Trim('"')
            }
        }
    }
}

$firewallfunction = Show-Firewall
$firewallfunction | Out-File -FilePath $firewallPath

$registryfunction = StartUp-Programs
$registryfunction += StratUp-Scripts
$registryfunction += Boot-Keys
$registryfunction += Startup-Services
$registryfunction += Run-Keys
$registryfunction += RDP-Debugger-Persistance
$registryfunction += COM-Hijacking
$registryfunction += Password-Filter
$registryfunction += Authentication-Packages
$registryfunction += Security-Packages
$registryfunction += Security-Providers
$registryfunction += Networker-Provider-Order
$registryfunction += Netsh-DLL
$registryfunction += AppInit-DLL
$registryfunction += AppCert-DLL
$registryfunction += Winlogon-DLL
$registryfunction += Print-Monitor-Ports
$registryfunction += Programs-Registry
$registryfunction += Uninstall-Keys
$registryfunction | Out-File -FilePath $registryPath

$processfunction = Process-Audit
$processfunction += Hidden-Services
$processfunction += Scheduled-Tasks
$processfunction | Out-File -FilePath $processPath

$thruntingfunction = Windows-Defender-Exclusions
$thruntingfunction += Random-Directories
$thruntingfunction += Unsigned-Files
$thruntingfunction += Ripper 
$thruntingfunction += UnquotedServicePathCheck
$thruntingfunction += Recently-Run-Commands
$thruntingfunction += Get-ConsoleHostHistory
$thruntingfunction | Out-File -FilePath $thruntingPath

$windowsfunction = Get-Installed
$windowsfunction += Current-local-gpo
$windowsfunction += Windows-Features
$windowsfunction | Out-File -FilePath $windowsPath

$aclfunction = Get-Process-ACL
$aclfunction = Get-Registry-ACL
$aclfunction = Get-ScheduledTask-ACL
$aclfunction = Get-Startup-ACL
$aclfunction | Out-File -FilePath $aclPath

#TODO: Print user properties