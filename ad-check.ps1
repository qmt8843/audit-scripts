$failtext = Write-Host "failure" -ForegroundColor Red -NoNewline

try {
    $ldapsigningpath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $ldapsigningname = "LDAPServerIntegrity"
    if (Test-Path $ldapsigningpath) {
        $ldapsigningoutcome = Get-ItemProperty -Path $ldapsigningpath -Name $ldapsigningname | Select-Object -ExpandProperty $ldapsigningname
        Write-Output "LDAP Signing output: $ldapsigningoutcome`r`n"
        #1 means none
        #2 means require signing
    } else {
        Write-Output "$failtext LDAP Signing Path does not exist!`r`n"
    }
}
catch {
    Write-Output "$failtext Error auditing LDAP Signing`r`n"
}


try {
    $auditkerbauthsrv = auditpol /get /subcategory:"Kerberos Authentication Service" | FindStr "Kerberos"
    Write-Output "Audit Kerberos Authentication Service output: $auditkerbauthsrv`r`n"
    #Default is success
    #Should be set to success & failure
} catch {
    Write-Output "$failtext Error auditing Audit Kerberos Authentication Service`r`n"
}

try {
    $auditkerbsrtvticket = auditpol /get /subcategory:"Kerberos Service Ticket Operations" | FindStr "Kerberos"
    Write-Output "Audit Kerberos Service Ticket Operations output: $auditkerbsrtvticket`r`n"
    #Default is success
    #Should be set to success & failure
} catch {
    Write-Output "$failtext Error auditing Audit Kerberos Service Ticket Operations`r`n"
}

try {
    $kerbencryptionpath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    $kerbencryptionname = "SupportedEncryptionTypes"
    if (Test-Path $kerbencryptionpath){
        $kerbencryptionoutput = Get-ItemProperty -Path $kerbencryptionpath -Name $kerbencryptionname | Select-Object -ExpandProperty $kerbencryptionname
        Write-Output "Kerberos Encryption Support: $kerbencryptionoutput`r`n"
        #Should be 2147483640
    } else {
        Write-Output "$failtext Kerberos Encryption Support does not exist!`r`n"
    }
    
} catch {
    Write-Output "$failtext Error auditing Kerberos Encryption Support`r`n"
}

try {
    $opscheduletaskpath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $opscheduletaskname = "SubmitControl"
    if (Test-Path $opscheduletaskpath) {
        $opscheduletaskoutcome = Get-ItemProperty -Path $opscheduletaskpath -Name $opscheduletaskname -ErrorAction Stop | Select-Object -ExpandProperty $opscheduletaskname
        Write-Output "Allow server operators to schedule tasks output: $opscheduletaskoutcome`r`n"
        #Should be 0 (disabled)
        #Path doesn't exist or error means it is disabled
    } else {
        Write-Output "$failtext Allow server operators to schedule tasks does not exist!`r`n"
    }
}
catch {
    Write-Output "$failtext Error auditing Allow server operators to schedule tasks`r`n"
}

try {
    $encryptsecurechannelpath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $encryptsecurechannelname = "RequireSignOrSeal"
    if (Test-Path $encryptsecurechannelpath) {
        $encryptsecurechanneloutcome = Get-ItemProperty -Path $encryptsecurechannelpath -Name $encryptsecurechannelname | Select-Object -ExpandProperty $encryptsecurechannelame
        $encryptsecurechanneloutcomepart = $encryptsecurechanneloutcome.RequireSignOrSeal
        Write-Output "Digitally encrypt or sign secure channel data (always) output: $encryptsecurechanneloutcomepart`r`n"
        #Should be 1 (enabled)
        #Path doesn't exist or error means it is disabled
    } else {
        Write-Output "$failtext Digitally encrypt or sign secure channel data (always) does not exist!`r`n"
    }
}
catch {
    Write-Output "$failtext Error auditing Digitally encrypt or sign secure channel data (always)`r`n"
}

try {
    $encryptwhenpath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $encryptwhenname = "SealSecureChannel"
    if (Test-Path $encryptwhenpath) {
        $encryptwhenoutcome = Get-ItemProperty -Path $encryptwhenpath -Name $encryptwhenname | Select-Object -ExpandProperty $encryptwhenname
        Write-Output "Digitally encrypt or sign secure channel data (when possible) output: $encryptwhenoutcome`r`n"
        #Should be 1 (enabled)
        #Path doesn't exist or error means it is disabled
    } else {
        Write-Output "$failtext Digitally encrypt or sign secure channel data (when possible) does not exist!`r`n"
    }
}
catch {
    Write-Output "$failtext Error auditing Digitally encrypt or sign secure channel data (when possible)`r`n"
}

try {
    $30dayspath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $30daysname = "MaximumPasswordAge"
    if (Test-Path $30dayspath) {
        $30daysoutcome = Get-ItemProperty -Path $30dayspath -Name $30daysname | Select-Object -ExpandProperty $30daysname
        Write-Output "Maximum machine account password set to 30 or fewer output: $30daysoutcome`r`n"
        #Should be 30 or less (but not 0)
        #Default is 30
    } else {
        Write-Output "$failtext Maximum machine account password set to 30 or fewer does not exist!`r`n"
    }
}
catch {
    Write-Output "$failtext Error auditing Maximum machine account password set to 30 or fewer`r`n"
}

try {
    $unlockpath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $unlockname = "ForceUnlockLogon"
    if (Test-Path $unlockpath) {
        $unlockoutcome = Get-ItemProperty -Path $unlockpath -Name $unlockname | Select-Object -ExpandProperty $unlockname
        Write-Output "Require Domain Controller Authentication to unlock workstation output: $unlockoutcome`r`n"
        #Should be 1 (Enabled)
    } else {
        Write-Output "$failtext Require Domain Controller Authentication to unlock workstation does not exist!`r`n"
    }
}
catch {
    Write-Output "$failtext Error auditing Require Domain Controller Authentication to unlock workstation`r`n"
}

try {
    $prohibitpath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
    $prohibitname = "fBlockNonDomain"
    if (Test-Path $prohibitpath) {
        $prohibitoutcome = Get-ItemProperty -Path $prohibitpath -Name $prohibitname -ErrorAction Stop | Select-Object -ExpandProperty $prohibitname
        Write-Output "Prohibit connection to non-domain networks when connected to domain authenticated network output: $prohibitoutcome`r`n"
        #Should be 1 (Enabled)
        #Error means it isnt applied
    } else {
        Write-Output "$failtext Prohibit connection to non-domain networks when connected to domain authenticated network does not exist!`r`n"
    }
}
catch {
    Write-Output "$failtext Error auditing Prohibit connection to non-domain networks when connected to domain authenticated network`r`n"
}

try {
    $enumeratepath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $enumeratename = "DontEnumerateConnectedUsers"
    if (Test-Path $enumeratepath) {
        $enumerateoutcome = Get-ItemProperty -Path $enumeratepath -Name $enumeratename -ErrorAction Stop | Select-Object -ExpandProperty $enumeratename
        Write-Output "Do not enumerate connected users on domain-joined computers output: $enumerateoutcome`r`n"
        #Should be 1 (Enabled)
        #Error means it isnt applied
    } else {
        Write-Output "$failtext Do not enumerate connected users on domain-joined computers does not exist!`r`n"
    }
}
catch {
    Write-Output "$failtext Error auditing Do not enumerate connected users on domain-joined computers`r`n"
}

try {
    $enumeratepath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    $enumeratename = "BackupDirectory"
    if (Test-Path $enumeratepath) {
        $enumerateoutcome = Get-ItemProperty -Path $enumeratepath -Name $enumeratename -ErrorAction Stop | Select-Object -ExpandProperty $enumeratename
        Write-Output "Configure password backup directory output: $enumerateoutcome`r`n"
        #Should be 1 (Active Directory) or 2 (Azure AD)
        #Error means it isnt applied
    } else {
        Write-Output "$failtext Configure password backup directory`r`n"
    }
}
catch {
    Write-Output "$failtext Error auditing Configure password backup directory`r`n"
}