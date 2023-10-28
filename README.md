# General Folder Structure

```
├── scripts
│   ├── conf
│   │   ├── wc-member-client-v_.inf (or wc-dc-v_.inf)
│   │   ├── (GUID of client GPO or GUID of dc GPO)
│   │   ├── def-eg-settings.xml
│   │   └── wc-auditpol-v_.csv
│   ├── results
│   │   ├── artifacts
│   │   │   └── (old GPO and sec template)
│   │   └── (outputs of scripts here)
│   ├── audit.ps1
│   ├── firewall.ps1
│   ├── Get-InjectedThread.ps1
│   ├── inventory.ps1
│   ├── logging.ps1
│   ├── sbaseline.ps1
│   └── usermgmt.ps1
├── installers
│   ├── MBSetup.exe
│   ├── wazuhagent.msi
│   ├── wfcsetup.exe
│   └── wsinstall.exe
├── tools 
│   ├── PatchMyPC.exe
│   ├── LGPO_30
│   │   └── LGPO.exe
│   └── sys
│       ├── ar
│       │   └── (autoruns)
│       ├── dll
│       │   └── (listdlls)
│       ├── pe
│       │   └── (proc explorer)
│       ├── pm
│       │   └── (proc mon)
│       ├── sc
│       │   └── (sigcheck)
│       ├── sm
│       │   └── (sysmon)
│       ├── st
│       │   └── (streams)
│       └── tv
│           └── (tcpview)
│        
├── lg.zip (LGPO)
├── ar.zip
├── dll.zip
├── pe.zip
├── pm.zip
├── sc.zip
└── tv.zip
```
