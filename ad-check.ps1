try {
    $ldapsigningpath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $ldapsigningname = "LDAPServerIntegrity"
    if (Test-Path $ldapsigningpath) {
        $ldapsigningoutcome = Get-ItemProperty -Path $ldapsigningpath -Name $ldapsigningname | Select-Object -ExpandProperty $ldapsigningname
        Write-Output "LDAP Signing output: $ldapsigningoutcome`r`n"
        #1 means none
        #2 means require signing
    } else {
        Write-Output "LDAP Signing Path does not exist!`r`n"
    }
}
catch {
    Write-Output "Error auditing LDAP Signing`r`n"
}


try {
    $auditkerbauthsrv = auditpol /get /subcategory:"Kerberos Authentication Service" | FindStr "Kerberos"
    Write-Output "Audit Kerberos Authentication Service output: $auditkerbauthsrv`r`n"
    #Default is success
    #Should be set to success & failure
} catch {
    Write-Output "Error auditing Audit Kerberos Authentication Service`r`n"
}

try {
    $auditkerbsrtvticket = auditpol /get /subcategory:"Kerberos Service Ticket Operations" | FindStr "Kerberos"
    Write-Output "Audit Kerberos Service Ticket Operations output: $auditkerbsrtvticket`r`n"
    #Default is success
    #Should be set to success & failure
} catch {
    Write-Output "Error auditing Audit Kerberos Service Ticket Operations`r`n"
}

try {
    $kerbencryptionpath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    $kerbencryptionname = "SupportedEncryptionTypes"
    if (Test-Path $kerbencryptionpath){
        $kerbencryptionoutput = Get-ItemProperty -Path $kerbencryptionpath -Name $kerbencryptionname | Select-Object -ExpandProperty $kerbencryptionname
        Write-Output "Kerberos Encryption Support: $kerbencryptionoutput`r`n"
        #Should be 2147483640
    } else {
        Write-Output "Kerberos Encryption Support does not exist!`r`n"
    }
    
} catch {
    Write-Output "Error auditing Kerberos Encryption Support`r`n"
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
        Write-Output "Allow server operators to schedule tasks does not exist!`r`n"
    }
}
catch {
    Write-Output "Error auditing Allow server operators to schedule tasks`r`n"
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
        Write-Output "Digitally encrypt or sign secure channel data (always) does not exist!`r`n"
    }
}
catch {
    Write-Output "Error auditing Digitally encrypt or sign secure channel data (always)`r`n"
}

try {
    $encryptwhenpath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $encryptwhenname = "SealSecureChannel"
    if (Test-Path $encryptwhenpath) {
        $encryptwhenoutcome = Get-ItemProperty -Path $encryptwhenpath -Name $encryptwhenname | Select-Object -ExpandProperty $encryptwhenname
        $encryptwhenoutcomepart = $encryptwhenoutcome.SealSecureChannel
        Write-Output "Digitally encrypt or sign secure channel data (when possible) output: $encryptwhenoutcomepart`r`n"
        #Should be 1 (enabled)
        #Path doesn't exist or error means it is disabled
    } else {
        Write-Output "Digitally encrypt or sign secure channel data (when possible) does not exist!`r`n"
    }
}
catch {
    Write-Output "Error auditing Digitally encrypt or sign secure channel data (when possible)`r`n"
}