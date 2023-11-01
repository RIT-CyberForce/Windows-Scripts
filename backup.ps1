if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $backup = Join-Path -Path (Get-Item -Path '..').FullName -ChildPath "\dns_backup"
    xcopy /E /I C:\Windows\System32\dns $backup
}


# Wazuh agent backup 
$dateTime = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$bkpFolder = Join-Path -Path (Get-Item -Path '..').FullName -ChildPath "\wazuh_files_backup\$dateTime"
New-Item -ItemType Directory -Path $bkpFolder | Out-Null

xcopy "C:\Program Files (x86)\ossec-agent\client.keys" $bkpFolder /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\ossec.conf" $bkpFolder /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\internal_options.conf" $bkpFolder /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\local_internal_options.conf" $bkpFolder /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\*.pem" $bkpFolder /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\ossec.log" $bkpFolder /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\logs\*"  $bkpFolder\logs\ /H /I /K /S /X
xcopy "C:\Program Files (x86)\ossec-agent\rids\*"  $bkpFolder\rids\ /H /I /K /S /X