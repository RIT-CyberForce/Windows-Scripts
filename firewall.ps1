# Delete all rules
netsh advfirewall set allprofiles state off
netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound
netsh advfirewall firewall delete rule name=all

# Configure logging
netsh advfirewall set allprofiles logging filename C:\Windows\fw.log
netsh advfirewall set allprofiles logging maxfilesize 32676
netsh advfirewall set allprofiles logging droppedconnections enable
netsh advfirewall set allprofiles logging allowedconnections enable

# Logics
$DC = $false
if (Get-WmiObject -Query 'select * from Win32_OperatingSystem where (ProductType = "2")') {
    $DC = $true
    Write-Host "[INFO] Domain Controller detected"
}

# Rules!
# DNS client
netsh adv f a r n=DNS-Client dir=out act=allow prof=any prot=udp remoteport=53
Write-Host "[INFO] DNS Client firewall rule set"

# LSASS (needed for authentication and NLA)
# is this a bad idea? probably. keep an eye on network connections made by this program
netsh adv f a r n=LSASS-Out dir=out act=allow prof=any prog="C:\Windows\System32\lsass.exe"
Write-Host "[INFO] LSASS firewall rule set"

# Common Scored Services
## Domain Controller Rules (includes DNS server)
if ($DC) {
    ## add TCP/UDP port 464 (kerberos password change)?
    netsh adv f a r n=DC-TCP-In dir=in act=allow prof=any prot=tcp localport=88,135,389,445,636,3268
    netsh adv f a r n=DC-UDP-In dir=in act=allow prof=any prot=udp localport=88,123,135,389,445,636
    netsh adv f a r n=RPC-In dir=in act=allow prof=any prot=tcp localport=rpc
    netsh adv f a r n=EPMAP-In dir=in act=allow prof=any prot=tcp localport=rpc-epmap

    netsh adv f a r n=DNS-Server dir=in act=allow prof=any prot=udp localport=53

    Write-Host "[INFO] Domain Controller firewall rules set" 
} else {
    ## If not a DC it's probably domain-joined so add client rules
    netsh adv f a r n=DC-TCP-Out dir=out act=allow prof=any prot=tcp remoteport=88,135,389,445,636,3268
    netsh adv f a r n=DC-UDP-Out dir=out act=allow prof=any prot=udp remoteport=88,123,135,389,445,636
}

## ICMP/Ping
# netsh adv f a r n=ICMP-In dir=in act=allow prof=any prot=icmpv4:8,any 
# netsh adv f a r n=ICMP-Out dir=out act=allow prof=any prot=icmpv4:8,any 

## Certificate Authority
# netsh adv f a r n=CA-Server dir=in act=allow prof=any prot=tcp localport=135
# netsh adv f a r n=CA-Client dir=out act=allow prof=any prot=tcp remoteport=135

## HTTP(S) (open server for CA)
# netsh adv f a r n=HTTP-Server dir=in act=allow prof=any prot=tcp localport=80,443
# netsh adv f a r n=HTTP-Client dir=out act=allow prof=any prot=tcp remoteport=80,443

# Remoting Protocols

## RDP
# netsh adv f a r n=RDP-TCP-Client dir=out act=allow prof=any prot=tcp remoteport=3389 
# netsh adv f a r n=RDP-UDP-Client dir=out act=allow prof=any prot=udp remoteport=3389 
# netsh adv f a r n=RDP-TCP-Server dir=in act=allow prof=any prot=tcp localport=3389 
# netsh adv f a r n=RDP-UDP-Server dir=in act=allow prof=any prot=udp localport=3389 

## WinRM
# netsh adv f a r n=WinRM-Client dir=out act=allow prof=any prot=tcp remoteport=5985,5986
# netsh adv f a r n=WinRM-Server dir=in act=allow prof=any prot=tcp localport=5985,5986

## SSH 
# netsh adv f a r n=SSH-Client dir=out act=allow prof=any prot=tcp remoteport=22
# netsh adv f a r n=SSH-Server dir=in act=allow prof=any prot=tcp localport=22

# Uncommon Services

## LDAP
# netsh adv f a r n=LDAP-Client dir=out act=allow prof=any prot=tcp remoteport=389
# netsh adv f a r n=LDAP-Server dir=in act=allow prof=any prot=tcp localport=389

## SMB
# netsh adv f a r n=SMB-Client dir=out act=allow prof=any prot=tcp remoteport=445
# netsh adv f a r n=SMB-Server dir=in act=allow prof=any prot=tcp localport=445

## DHCP 
# netsh adv f a r n=DHCP-Client dir=out act=allow prof=any prot=udp remoteport=67,68
# netsh adv f a r n=DHCP-Server dir=in act=allow prof=any prot=udp localport=67,68

## S(FTP)
# netsh adv f a r n=FTP-Client dir=out act=allow prof=any prot=tcp remoteport=20,21
# netsh adv f a r n=SFTP-Client dir=out act=allow prof=any prot=tcp remoteport=22

# netsh adv f a r n=FTP-Server dir=in act=allow prof=any prot=tcp localport=20,21
# netsh adv f a r n=SFTP-Server dir=in act=allow prof=any prot=tcp localport=22

## OpenVPN
# netsh adv f a r n=OpenVPN-Client-UDP dir=out act=allow prof=any prot=udp remoteport=1194
# netsh adv f a r n=OpenVPN-Client-TCP dir=out act=allow prof=any prot=tcp remoteport=443
# netsh adv f a r n=OpenVPN-Server-UDP dir=in act=allow prof=any prot=udp localport=1194
# netsh adv f a r n=OpenVPN-Server-TCP dir=in act=allow prof=any prot=tcp localport=443

## Hyper-V VM Console
# netsh adv f a r n=Hyper-V-Client dir=out act=allow prof=any prot=tcp remoteport=2179
# netsh adv f a r n=Hyper-V-Server dir=in act=allow prof=any prot=tcp localport=2179

## SMTP(S)
# netsh adv f a r n=SMTP-Client dir=out act=allow prof=any prot=tcp remoteport=25
# netsh adv f a r n=SMTPS-Client dir=out act=allow prof=any prot=tcp remoteport=465,587
# netsh adv f a r n=SMTP-Server dir=out act=allow prof=any prot=tcp localport=25
# netsh adv f a r n=SMTPS-Server dir=out act=allow prof=any prot=tcp localport=465,587

## IMAP
# netsh adv f a r n=IMAP-Client dir=out act=allow prof=any prot=tcp remoteport=143
# netsh adv f a r n=IMAPS-Client dir=out act=allow prof=any prot=tcp remoteport=993
# netsh adv f a r n=IMAP-Server dir=in act=allow prof=any prot=tcp localport=143
# netsh adv f a r n=IMAPS-Server dir=in act=allow prof=any prot=tcp localport=993

## POP3
# netsh adv f a r n=POP3-Client dir=out act=allow prof=any prot=tcp remoteport=110
# netsh adv f a r n=POP3S-Client dir=out act=allow prof=any prot=tcp remoteport=995
# netsh adv f a r n=POP3-Server dir=in act=allow prof=any prot=tcp localport=110
# netsh adv f a r n=POP3S-Server dir=in act=allow prof=any prot=tcp localport=995

# Logging Protocols
## Wazuh 
netsh adv f a r n=Wazuh-Client dir=out act=allow prof=any prot=tcp remoteport=1514
### Temporary rule to allow enrollment of an agent
netsh adv f a r n=Wazuh-Agent-Enrollment dir=out prof=any prot=tcp remoteport=1515

## Pandora 
# netsh adv f a r n=Pandora-Client dir=out act=allow prof=any prot=tcp remoteport=41121
# netsh adv f a r n=Pandora-Server dir=in act=allow prof=any prot=tcp localport=41121

## Syslog
# netsh adv f a r n=Syslog-Client dir=out act=allow prof=any prot=udp remoteport=514
# netsh adv f a r n=Syslog-Server dir=in act=allow prof=any prot=udp localport=514

# Logic to add all fw rules to group for WFC
Get-NetFirewallRule -All | ForEach-Object {$_.Group = 'bingus'; $_ | Set-NetFirewallRule}

# Turn on firewall and default block
netsh advfirewall set allprofiles state on
netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound

# Lockout prevention
timeout 60
netsh advfirewall set allprofiles state off

# TODO: come up with a way to set fw rules for windows services that can be detected on the system