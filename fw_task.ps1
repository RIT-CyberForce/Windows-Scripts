# Delete all rules
netsh advfirewall set allprofiles state off
netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound
netsh advfirewall firewall delete rule name=all

# Configure logging
netsh advfirewall set allprofiles logging filename C:\Windows\fw.log
netsh advfirewall set allprofiles logging maxfilesize 32676
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable

# Rules!
# DNS client
netsh adv f a r n=DNS-Client dir=out act=allow prof=any prot=udp remoteport=53
Write-Host "[INFO] DNS Client firewall rule set"

# LSASS (needed for authentication and NLA)
# is this a bad idea? probably. keep an eye on network connections made by this program
netsh adv f a r n=LSASS-Out dir=out act=allow prof=any prog="C:\Windows\System32\lsass.exe"
Write-Host "[INFO] LSASS firewall rule set"

## domain-joined so add client rules
netsh adv f a r n=DC-TCP-Out dir=out act=allow prof=any prot=tcp remoteport=88,135,389,445,636,3268
netsh adv f a r n=DC-UDP-Out dir=out act=allow prof=any prot=udp remoteport=88,123,135,389,445,636
Write-Host "[INFO] Domain client rules set"

netsh adv f a r n=HTTP-Server dir=in act=allow prof=any prot=tcp localport=80,443
netsh adv f a r n=HTTP-Client dir=out act=allow prof=any prot=tcp remoteport=80,443
Write-Host "[INFO] Web server and client rules set"

# Remoting Protocols
## RDP
netsh adv f a r n=RDP-TCP-Server dir=in act=allow prof=any prot=tcp localport=3389 
netsh adv f a r n=RDP-UDP-Server dir=in act=allow prof=any prot=udp localport=3389 
Write-Host "[INFO] RDP inbound rules set"

## WinRM
netsh adv f a r n=WinRM-Server dir=in act=allow prof=any prot=tcp localport=5985,5986
Write-Host "[INFO] WinRM inbound rule set"

## FTP
netsh adv f a r n=FTP-Server dir=in act=allow prof=any prot=tcp localport=20,21
Write-Host "[INFO] FTP server rule set"

## SMB 
netsh adv f a r n=SMB-Server dir=in act=allow prof=any prot=tcp localport=445
Write-Host "[INFO] SMB server rule set"

# Logging Protocols
## Wazuh 
netsh adv f a r n=Wazuh-Client dir=out act=allow prof=any prot=tcp remoteport=1514
### Temporary rule to allow enrollment of an agent
netsh adv f a r n=Wazuh-Agent-Enrollment dir=out prof=any prot=tcp remoteport=1515
Write-Host "[INFO] Wazuh rules set"

# Logic to add all fw rules to group for WFC
Get-NetFirewallRule -All | ForEach-Object {$_.Group = 'bingus'; $_ | Set-NetFirewallRule}

# Turn on firewall and default block
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

# Lockout prevention
timeout 60
netsh advfirewall set allprofiles state off