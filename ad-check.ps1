function Write-Red {
    param (
        [Parameter(Mandatory)]
        [string]$Text
    )
    Write-Host $Text -ForegroundColor Red -NoNewline
}

function Write-Green {
    param (
        [Parameter(Mandatory)]
        [string]$Text
    )
    Write-Host $Text -ForegroundColor Green -NoNewline
}

try {
    $ldapsigningpath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
    $ldapsigningname = "LDAPServerIntegrity"
    if (Test-Path $ldapsigningpath) {
        $ldapsigningoutcome = Get-ItemProperty -Path $ldapsigningpath -Name $ldapsigningname | Select-Object -ExpandProperty $ldapsigningname
        
        #1 means none
        #2 means require signing
        if ($ldapsigningoutcome -eq 1) {
            Write-Green("SUCCESS: ")
            Write-Output "$LDAP Signing output: $ldapsigningoutcome`r`n"
        } elseif ($ldapsigningoutcome -eq 2) {
            Write-Red("FAILURE: ")
            Write-Output "LDAP Signing output: $ldapsigningoutcome`r`n"
        }
    } else {
        Write-Red("FAILURE: ")
        Write-Output "LDAP Signing Path does not exist!`r`n"
    }
}
catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing LDAP Signing`r`n"
}


try {
    $auditkerbauthsrv = auditpol /get /subcategory:"Kerberos Authentication Service" | FindStr "Kerberos"
    if ("SUCCESS" -in $auditkerbauthsrv -and "Failure" -in $auditkerbauthsrv){
        Write-Green("SUCCESS: ")
        Write-Output "Audit Kerberos Authentication Service output: $auditkerbauthsrv`r`n"
    } else {
        Write-Red("FAILURE: ")
        Write-Output "Audit Kerberos Authentication Service output: $auditkerbauthsrv`r`n"
    }
    #Default is SUCCESS
    #Should be set to SUCCESS & failure
} catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing Audit Kerberos Authentication Service`r`n"
}

try {
    $auditkerbsrtvticket = auditpol /get /subcategory:"Kerberos Service Ticket Operations" | FindStr "Kerberos"
    if ("SUCCESS" -in $auditkerbauthsrv -and "Failure" -in $auditkerbauthsrv){
        Write-Green("SUCCESS: ")
        Write-Output "Audit Kerberos Service Ticket Operations output: $auditkerbsrtvticket`r`n"
    } else {
        Write-Red("FAILURE: ")
        Write-Output "Audit Kerberos Service Ticket Operations output: $auditkerbsrtvticket`r`n"
    }
    #Default is SUCCESS
    #Should be set to SUCCESS & failure
} catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing Audit Kerberos Service Ticket Operations`r`n"
}

try {
    $kerbencryptionpath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    $kerbencryptionname = "SupportedEncryptionTypes"
    if (Test-Path $kerbencryptionpath){
        $kerbencryptionoutput = Get-ItemProperty -Path $kerbencryptionpath -Name $kerbencryptionname | Select-Object -ExpandProperty $kerbencryptionname
        if ($kerbencryptionoutput -eq 2147483640) {
            Write-Green("SUCCESS: ")
            Write-Output "Kerberos Encryption Support: $kerbencryptionoutput`r`n"
        } else {
            Write-Red("FAILURE: ")
            Write-Output "Kerberos Encryption Support: $kerbencryptionoutput`r`n"
        }
        #Should be 2147483640
    } else {
        Write-Red("FAILURE: ")
        Write-Output "Kerberos Encryption Support does not exist!`r`n"
    }
    
} catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing Kerberos Encryption Support`r`n"
}

try {
    $opscheduletaskpath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
    $opscheduletaskname = "SubmitControl"
    if (Test-Path $opscheduletaskpath) {
        $opscheduletaskoutcome = Get-ItemProperty -Path $opscheduletaskpath -Name $opscheduletaskname -ErrorAction Stop | Select-Object -ExpandProperty $opscheduletaskname
        if ($opscheduletaskoutcome -eq 0) {
            Write-Green("SUCCESS: ")
            Write-Output "Allow server operators to schedule tasks output: $opscheduletaskoutcome`r`n"
        } else {
            Write-Red("FAILURE: ")
            Write-Output "Allow server operators to schedule tasks output: $opscheduletaskoutcome`r`n"
        }
        #Should be 0 (disabled)
        #Path doesn't exist or error means it is disabled
    } else {
        Write-Red("FAILURE: ")
        Write-Output "Allow server operators to schedule tasks does not exist!`r`n"
    }
}
catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing Allow server operators to schedule tasks`r`n"
}

try {
    $encryptsecurechannelpath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $encryptsecurechannelname = "RequireSignOrSeal"
    if (Test-Path $encryptsecurechannelpath) {
        $encryptsecurechanneloutcome = Get-ItemProperty -Path $encryptsecurechannelpath -Name $encryptsecurechannelname | Select-Object -ExpandProperty $encryptsecurechannelame
        $encryptsecurechanneloutcomepart = $encryptsecurechanneloutcome.RequireSignOrSeal
        if ($encryptsecurechanneloutcomepart -eq 1) {
            Write-Green("SUCCESS: ")
            Write-Output "Digitally encrypt or sign secure channel data (always) output: $encryptsecurechanneloutcomepart`r`n"
        } else {
            Write-Red("FAILURE: ")
            Write-Output "Digitally encrypt or sign secure channel data (always) output: $encryptsecurechanneloutcomepart`r`n"
        }
        #Should be 1 (enabled)
        #Path doesn't exist or error means it is disabled
    } else {
        Write-Red("FAILURE: ")
        Write-Output "Digitally encrypt or sign secure channel data (always) does not exist!`r`n"
    }
}
catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing Digitally encrypt or sign secure channel data (always)`r`n"
}

try {
    $encryptwhenpath = "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    $encryptwhenname = "SealSecureChannel"
    if (Test-Path $encryptwhenpath) {
        $encryptwhenoutcome = Get-ItemProperty -Path $encryptwhenpath -Name $encryptwhenname | Select-Object -ExpandProperty $encryptwhenname
        if (encryptwhenoutcome -eq 1) {
            Write-Green("SUCCESS: ")
            rite-Output "Digitally encrypt or sign secure channel data (when possible) output: $encryptwhenoutcome`r`n"
        } else {
            Write-Red("FAILURE: ")
            Write-Output "Digitally encrypt or sign secure channel data (when possible) output: $encryptwhenoutcome`r`n"
        }
        #Should be 1 (enabled)
        #Path doesn't exist or error means it is disabled
    } else {
        Write-Red("FAILURE: ")
        Write-Output "Digitally encrypt or sign secure channel data (when possible) does not exist!`r`n"
    }
}
catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing Digitally encrypt or sign secure channel data (when possible)`r`n"
}

try {
    $30dayspath = "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters"
    $30daysname = "MaximumPasswordAge"
    if (Test-Path $30dayspath) {
        $30daysoutcome = Get-ItemProperty -Path $30dayspath -Name $30daysname | Select-Object -ExpandProperty $30daysname
        if ($30daysoutcome -lt 31 -and $30daysoutcome -gt 0){
            Write-Green("SUCCESS: ")
            Write-Output "Maximum machine account password set to 30 or fewer output: $30daysoutcome`r`n"
        } else {
            Write-Red("FAILURE: ")
            Write-Output "Maximum machine account password set to 30 or fewer output: $30daysoutcome`r`n"
        }
        #Should be 30 or less (but not 0)
        #Default is 30
    } else {
        Write-Red("FAILURE: ")
        Write-Output "Maximum machine account password set to 30 or fewer does not exist!`r`n"
    }
}
catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing Maximum machine account password set to 30 or fewer`r`n"
}

try {
    $unlockpath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $unlockname = "ForceUnlockLogon"
    if (Test-Path $unlockpath) {
        $unlockoutcome = Get-ItemProperty -Path $unlockpath -Name $unlockname | Select-Object -ExpandProperty $unlockname
        if ($unlockoutcome -eq 1) {
            Write-Green("SUCCESS: ")
            Write-Output "Require Domain Controller Authentication to unlock workstation output: $unlockoutcome`r`n"
        } else {
            Write-Red("FAILURE: ")
            Write-Output "Require Domain Controller Authentication to unlock workstation output: $unlockoutcome`r`n"
        }
        #Should be 1 (Enabled)
    } else {
        Write-Red("FAILURE: ")
        Write-Output "Require Domain Controller Authentication to unlock workstation does not exist!`r`n"
    }
}
catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing Require Domain Controller Authentication to unlock workstation`r`n"
}

try {
    $prohibitpath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WcmSvc\GroupPolicy"
    $prohibitname = "fBlockNonDomain"
    if (Test-Path $prohibitpath) {
        $prohibitoutcome = Get-ItemProperty -Path $prohibitpath -Name $prohibitname -ErrorAction Stop | Select-Object -ExpandProperty $prohibitname
        if ($prohibitoutcome -eq 1) {
            Write-Green("SUCCESS: ")
            Write-Output "Prohibit connection to non-domain networks when connected to domain authenticated network output: $prohibitoutcome`r`n"
        } else {
            Write-Red("FAILURE: ")
            Write-Output "Prohibit connection to non-domain networks when connected to domain authenticated network output: $prohibitoutcome`r`n"
        }
        #Should be 1 (Enabled)
        #Error means it isnt applied
    } else {
        Write-Red("FAILURE: ")
        Write-Output "Prohibit connection to non-domain networks when connected to domain authenticated network does not exist!`r`n"
    }
}
catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing Prohibit connection to non-domain networks when connected to domain authenticated network`r`n"
}

try {
    $enumeratepath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System"
    $enumeratename = "DontEnumerateConnectedUsers"
    if (Test-Path $enumeratepath) {
        $enumerateoutcome = Get-ItemProperty -Path $enumeratepath -Name $enumeratename -ErrorAction Stop | Select-Object -ExpandProperty $enumeratename
        if ($enumerateoutcome -eq 1) {
            Write-Green("SUCCESS: ")
            Write-Output "Do not enumerate connected users on domain-joined computers output: $enumerateoutcome`r`n"
        } else {
            Write-Red("FAILURE: ")
            Write-Output "Do not enumerate connected users on domain-joined computers output: $enumerateoutcome`r`n"
        }
        #Should be 1 (Enabled)
        #Error means it isnt applied
    } else {
        Write-Red("FAILURE: ")
        Write-Output "Do not enumerate connected users on domain-joined computers does not exist!`r`n"
    }
}
catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing Do not enumerate connected users on domain-joined computers`r`n"
}

try {
    $enumeratepath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\LAPS"
    $enumeratename = "BackupDirectory"
    if (Test-Path $enumeratepath) {
        $enumerateoutcome = Get-ItemProperty -Path $enumeratepath -Name $enumeratename -ErrorAction Stop | Select-Object -ExpandProperty $enumeratename
        if ($enumerateoutcome -eq 1 -or $enumerateoutcome -eq 2) {
            Write-Green("SUCCESS: ")
            Write-Output "Configure password backup directory output: $enumerateoutcome`r`n"
        } else {
            Write-Red("FAILURE: ")
            Write-Output "Configure password backup directory output: $enumerateoutcome`r`n"
        }
        #Should be 1 (Active Directory) or 2 (Azure AD)
        #Error means it isnt applied
    } else {
        Write-Red("FAILURE: ")
        Write-Output "Configure password backup directory`r`n"
    }
}
catch {
    Write-Red("FAILURE: ")
    Write-Output "Error auditing Configure password backup directory`r`n"
}