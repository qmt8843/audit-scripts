try {
    $ldapsigningpath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $ldapsigningname = "LDAPServerIntegrity"
    if (Test-Path $ldapsigningpath) {
        $ldapsigningoutcome = Get-ItemProperty -Path $ldapsigningpath -Name $ldapsigningname | Select-Object -ExpandProperty $ldapsigningname
        if ($ldapsigningoutcome ) {
            Write-Output "LDAP Signing output: $ldapsigningoutcome`r`n"
        }
        #1 means none
        #2 means require signing
    } else {
        Write-Output "LDAP Signing Path does not exist!"
    }
}
catch {
    Write-Output "Error auditing LDAP Signing"
}


try {
    $auditkerbauthsrv = auditpol /get /subcategory:"Kerberos Authentication Service" | FindStr "Kerberos"
    if ($auditkerbauthsrv) {
        Write-Output "Audit Kerberos Authentication Service output: $auditkerbauthsrv`r`n"
    }
    #Default is success
    #Should be set to success & failure
} catch {
    Write-Output "Error auditing Audit Kerberos Authentication Service"
}

try {
    $auditkerbsrtvticket = auditpol /get /subcategory:"Kerberos Service Ticket Operations" | FindStr "Kerberos"
    if ($auditkerbsrtvticket) {
        Write-Output "Audit Kerberos Service Ticket Operations output: $auditkerbsrtvticket`r`n"
    }
    #Default is success
    #Should be set to success & failure
} catch {
    Write-Output "Error auditing Audit Kerberos Service Ticket Operations"
}

try {
    $kerbencryptionpath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    $kerbencryptionname = "SupportedEncryptionTypes"
    if (Test-Path $kerbencryptionpath){
        $kerbencryptionoutput = Get-ItemProperty -Path $kerbencryptionpath -Name $kerbencryptionname | Select-Object -ExpandProperty $kerbencryptionname
        if ($kerbencryptionoutput) {
            Write-Output "Kerberos Encryption Support: $kerbencryptionoutput`r`n"
        }
        #Should be 2147483640
    } else {
        Write-Output "Kerberos Encryption Support does not exist!"
    }
    
} catch {
    Write-Output "Error auditing Kerberos Encryption Support"
}