$ldapsigningpath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$ldapsigningname = "LDAPServerIntegrity"
$ldapsigningoutcome = Get-ItemProperty -Path $ldapsigningpath -Name $ldapsigningname | Select-Object -ExpandProperty $ldapsigningname
Write-Output "LDAP Signing output: $ldapsigningoutcome"
#1 means none
#2 means require signing

$auditkerbauthsrv = auditpol /get /subcategory:"Kerberos Authentication Service" | FindStr "Kerberos"
Write-Output "Audit Kerberos Authentication Service output: $auditkerbauthsrv"
#Default is success
#Should be set to success & failure

$auditkerbsrtvticket = auditpol /get /subcategory:"Kerberos Service Ticket Operations"
Write-Output "Kerberos Service Ticket Operations output: $auditkerbsrtvticket"
#Default is success
#Should be set to success & failure

$kerbencryptionpath = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$kerbencryptionname = "SupportedEncryptionTypes"
$kerbencryptionoutput = Get-ItemProperty -Path $kerbencryptionpath -Name $kerbencryptionname | Select-Object -ExpandProperty $kerbencryptionname
Write-Output "Kerberos Encryption Support: $kerbencryptionoutput"
#Should be 2147483640