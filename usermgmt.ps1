param(
    [Parameter()]
    [String]$filepath 
)

try {
    [string[]]$AllowUsers = Get-Content $filepath
} catch {
    Write-Host "[ERROR] Unable to get list of users"
    exit 1
}

$DC = $false
if (Get-CimInstance -Class Win32_OperatingSystem -Filter 'ProductType = "2"') {
    $DC = $true
    Write-Host "[INFO] Domain Controller Detected"
}

Function Set-Password([string]$UserName, [bool]$IsDC) {
    Clear-Host
    $Password = Read-Host -AsSecureString "Password: "
    $Password2 = Read-Host -AsSecureString "Confirm Password: "
    if ($Password -ne $Password2) {
        Write-Host "[ERROR] Passwords don't match" 
        exit
    } else {
        if ($IsDC) {
            Set-ADUser -Identity $UserName -Password $Password
            Write-Host "[INFO] Password set for" $UserName
        } else {
            Set-LocalUser -Name $UserName -Password $Password
            Write-Host "[INFO] Password set for" $UserName
        }
    }
}

Function Set-UserProperties([string[]]$UserList, [bool]$IsDC) {
    if ($IsDC) {
        $DomainUsers = Get-ADUser -filter *
        foreach ($DomainUser in $DomainUsers) {
            if ($DomainUser.Name -in $UserList) {
                Enable-ADAccount -Name $DomainUser.Name
                Write-Host "[INFO]" $DomainUser.Name "enabled"
                $DomainUser | Set-ADUser -AllowReversiblePasswordEncryption $false -ChangePasswordAtLogon $false -KerberosEncryptionType AES128,AES256 -PasswordNeverExpires $false -UserMayChangePassword $false -PasswordNotRequired $false -AccountNotDelegated $true
                $DomainUser | Set-ADAccountControl -DoesNotRequirePreAuth $false
            } else {
                Disable-ADAccount -Name $DomainUser.Name
                Write-Host "[INFO]" $DomainUser.Name "disabled"
            }
        }
    } else {
        $LocalUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True' and name!='$Env:Username'"
        foreach ($LocalUser in $LocalUsers) {
            if ($LocalUser.Name -in $UserList) {
                Enable-LocalUser -Name $LocalUser.Name
                Write-Host "[INFO]" $LocalUser.Name "enabled"
                $LocalUser | Set-LocalUser -PasswordNeverExpires $false -UserMayChangePassword $true -AccountNeverExpires
            } else {
                Disable-LocalUser -Name $LocalUser.Name
                Write-Host "[INFO]" $LocalUser.Name "disabled"
            }
        }
    }
}

while ($true) {
    Write-Host "Options:"
    Write-Host "1. Change passwords for all users in list"
    Write-Host "2. Change password for current user"
    Write-Host "3. Enable all users in list and apply proper user properties, disable users not in list"
    Write-Host "4. Exit"
    $option = Read-Host "Enter an option"
    
    if ($option -eq '1') {
        foreach ($user in $AllowUsers) {
            Set-Password -UserName $user -IsDC $DC
        }
    } elseif ($option -eq '2') {
        Set-Password -UserName $Env:UserName -IsDC $DC
    } elseif ($option -eq '3') {
        Set-UserProperties -UserList $AllowUsers -IsDC $DC
    } elseif ($option -eq '4') {
        exit 0
    } else {
        Write-Host "Invalid option, try again"
    }
}
