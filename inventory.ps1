# Objective: Gather basic information about the system
function Get-Inventory {
    # DC detection
    $DC = $false
    if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
        $DC = $true
        Import-Module ActiveDirectory
        Write-Output "[INFO] Domain Controller detected`n"
    }

    # IIS detection - TODO: TEST
    $IIS = $false
    if (Get-Service -Name W3SVC 2>$null) {
        $IIS = $true
        Import-Module WebAdministration
        Import-Module IISAdministration
        Write-Output "[INFO] IIS detected`n"
    }

    # CA detection - TODO: TEST
    $CA = $false
    if (Get-Service -Name CertSvc 2>$null) {
        $CA = $true
        Import-Module ADCSAdministration
        Write-Output "[INFO] CA detected`n"
    }

    # Hostname, domain
    Write-Output "----------- Hostname, Domain -----------"
    Get-CimInstance -Class Win32_ComputerSystem | Format-Table Name, Domain

    # Operating System information
    Write-Output "----------- OS Information -----------"
    Get-CimInstance -Class Win32_OperatingSystem | Format-Table Caption, Version, ServicePackMajorVersion, OSArchitecture, WindowsDirectory

    # MAC address, IP address, Subnet mask, Default gateway
    Write-Output "----------- Network Adapter Information -----------"
    Get-CimInstance -Class Win32_NetworkAdapterConfiguration -Filter IPEnabled=TRUE | Format-Table ServiceName, MACAddress, IPAddress, IPSubnet, DefaultIPGateway

    # DNS Servers
    Write-Output "----------- DNS Servers -----------"
    Get-DnsClientServerAddress -InterfaceIndex (Get-NetAdapter | Select-Object -expand ifindex) | Format-Table InterfaceAlias, ServerAddresses 

    # Network connections/listening ports
    Write-Output "----------- TCP Network Connections -----------"
    Get-NetTCPConnection -State Listen,Established -ErrorAction "SilentlyContinue" | Sort-Object state,localport | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}},@{'Name'='CommandLine';'Expression'={(Get-CimInstance -Class Win32_Process -Filter "ProcessId = $($_.OwningProcess)").CommandLine}} | Format-Table -AutoSize
    
    Write-Output "----------- UDP Network Connections -----------"
    Get-NetUDPEndpoint | Sort-Object localport | Select-Object LocalAddress,LocalPort,OwningProcess,@{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}},@{'Name'='CommandLine';'Expression'={(Get-CimInstance -Class Win32_Process -Filter "ProcessId = $($_.OwningProcess)").CommandLine}} | Format-Table -AutoSize

    # Listing all users
    Write-Output "----------- All Users -----------"
    Get-CimInstance -Class Win32_UserAccount | Format-Table Name, Domain

    # Listing group membership
    if ($DC) { ## Domain groups
        Write-Output "----------- Domain Group Membership -----------`n"
        $Groups = Get-ADGroup -Filter 'SamAccountName -NotLike "Domain Users"' | Select-Object -ExpandProperty name
        $Groups | ForEach-Object {
            $Users = Get-ADGroupMember -Identity $_ | Format-Table name, objectclass
            if ($Users.Count -gt 0) {
                $Users = $Users | Out-String
                # must be Write-Output
                Write-Output "Group: $_"
                Write-Output "$Users"
            }
        }
    # TODO: TEST
    } else { # Local groups
        Write-Output "----------- Local Group Membership -----------`n"
        $Groups = Get-LocalGroup | Select-Object -ExpandProperty Name
        $Groups | ForEach-Object {
            # Get-LocalGroupMember is unreliable
            $Users = net localgroup $_ | Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -Skip 4
            if ($Users.Count -gt 0) {
                $Users = $Users | Out-String
                Write-Output "Group: $_"
                Write-Output "`nname"
                Write-Output "----"
                Write-Output "$Users`n"
            }
        }
    }

    Write-Output "----------- SMB Shares -----------"
    net share

    # If IIS, site bindings
    if ($IIS) {
        Write-Output "----------- IIS Site Bindings -----------"
        $websites = Get-ChildItem IIS:\Sites | Sort-Object name

        foreach ($site in $websites) {
            Write-Output "Website Name: $($site.Name)"
            $bindings = Get-WebBinding -Name $site.name
            foreach ($binding in $bindings) {
                Write-Output "    Binding Information:"
                Write-Output "        Protocol: $($binding.protocol)"
                Write-Output "        IP Address: $($binding.bindingInformation.split(":")[0])"
                Write-Output "        Port: $($binding.bindingInformation.split(":")[1])"
                Write-Output "        Hostname: $($binding.hostHeader)"
            }
            Write-Output ""
        }
    }

    # If CA, list certificates?
    
    #Get Installed Applications 
    Write-Output "----------- Installed Applications -----------"
    # Get 32-bit and 64-bit installed applications
    $installedApps32Bit = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
    $installedApps64Bit = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*
    $installedAppsUser = Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*
    # Combine the results and select relevant properties including the file path
    $installedApps = $installedApps32Bit + $installedApps64Bit + $installedAppsUser | Where-Object { $_.DisplayName -ne $null } | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation

    # Output the list of installed applications with file paths
    $installedApps

    Write-Output "----------- Installed Roles and Features -----------"
    Get-WindowsFeature | Where-Object {$_.InstallState -eq "Installed"} | Format-Table Name,Path
}

Get-Inventory | Tee-Object -FilePath "results\inventory.txt"



