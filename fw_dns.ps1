# Delete all rules
netsh advfirewall set allprofiles state off | Out-Null
netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound | Out-Null
netsh advfirewall firewall delete rule name=all | Out-Null
Write-Host "[INFO] All firewall rules deleted"

# Configure logging
netsh advfirewall set allprofiles logging filename C:\Windows\fw.log | Out-Null
netsh advfirewall set allprofiles logging maxfilesize 32676 | Out-Null
netsh advfirewall set allprofiles logging droppedconnections enable | Out-Null
netsh advfirewall set allprofiles logging allowedconnections enable | Out-Null
Write-Host "[INFO] Firewall logging enabled"

# if key doesn't already exist, install WFC
if (!(Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Windows Firewall Control")) {
    $combinedPath = Join-Path -Path (Get-Item -Path '..').FullName -ChildPath "\tools\WFC"
    ..\installers\wfcsetup.exe -i -r -noshortcuts -norules $combinedPath
}

# Rules!
# DNS client
netsh adv f a r n=DNS-Client dir=out act=allow prof=any prot=udp remoteport=53 | Out-Null
Write-Host "[INFO] DNS Client firewall rule set"

# LSASS (needed for authentication and NLA)
# is this a bad idea? probably. keep an eye on network connections made by this program
netsh adv f a r n=LSASS-Out dir=out act=allow prof=any prog="C:\Windows\System32\lsass.exe" | Out-Null
Write-Host "[INFO] LSASS firewall rule set"

netsh adv f a r n=DC-TCP-In dir=in act=allow prof=any prot=tcp localport=88,135,389,445,636,3268 | Out-Null
netsh adv f a r n=DC-UDP-In dir=in act=allow prof=any prot=udp localport=88,123,135,389,445,636 | Out-Null
netsh adv f a r n=RPC-In dir=in act=allow prof=any prot=tcp localport=rpc | Out-Null
netsh adv f a r n=EPMAP-In dir=in act=allow prof=any prot=tcp localport=rpc-epmap | Out-Null

netsh adv f a r n=DNS-Server dir=in act=allow prof=any prot=udp localport=53 | Out-Null

Write-Host "[INFO] Domain Controller firewall rules set" 

# HTTP server rule (for CA)
netsh adv f a r n=HTTP-Server dir=in act=allow prof=any prot=tcp localport=80,443 | Out-Null
netsh adv f a r n=CA-Server dir=in act=allow prof=any prot=tcp localport=135 | Out-Null
Write-Host "[INFO] CA rules set"
# HTTP Client rule (disable if not needed)
# netsh adv f a r n=HTTP-Client dir=out act=allow prof=any prot=tcp remoteport=80,443 | Out-Null

## RDP
netsh adv f a r n=RDP-TCP-Server dir=in act=allow prof=any prot=tcp localport=3389 | Out-Null
netsh adv f a r n=RDP-UDP-Server dir=in act=allow prof=any prot=udp localport=3389 | Out-Null
Write-Host "[INFO] RDP inbound rules set"

## WinRM
netsh adv f a r n=WinRM-Server dir=in act=allow prof=any prot=tcp localport=5985,5986 | Out-Null
# netsh adv f a r n=WinRM-Client dir=in act=allow prof=any prot=tcp remoteport=5985,5986 | Out-Null
Write-Host "[INFO] WinRM inbound rule set"

## SSH
# netsh adv f a r n=SSH-Client dir=out act=allow prof=any prot=tcp remoteport=22 | Out-Null
netsh adv f a r n=SSH-Server dir=in act=allow prof=any prot=tcp localport=22 | Out-Null
Write-Host "[INFO] SSH inbound rule set"

## VNC
netsh adv f a r n=VNC-Server-TCP dir=in act=allow prof=any prot=tcp localport=5900 | Out-Null
netsh adv f a r n=VNC-Server-UDP dir=in act=allow prof=any prot=udp localport=5900 | Out-Null
Write-Host "[INFO] VNC inbound rules set"

## Wazuh 
netsh adv f a r n=Wazuh-Client dir=out act=allow prof=any prot=tcp remoteport=1514 | Out-Null
### Temporary rule to allow enrollment of an agent
netsh adv f a r n=Wazuh-Agent-Enrollment act=allow dir=out prof=any prot=tcp remoteport=1515 | Out-Null
Write-Host "[INFO] Wazuh rules set"

# Logic to add all fw rules to group for WFC
Get-NetFirewallRule -All | ForEach-Object {$_.Group = 'bingus'; $_ | Set-NetFirewallRule}

# Turn on firewall and default block
netsh advfirewall set allprofiles state on | Out-Null 
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound | Out-Null
Write-Host "[INFO] Firewall on, default block for all inbound and outbound"

# Lockout prevention
timeout 60
netsh advfirewall set allprofiles state off