$ldapsigningpath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$ldapsigningname = "LDAPServerIntegrity"
$ldapsigningoutcome = Get-ItemProperty -Path $ldapsigningpath -Name $ldapsigningname | Select-Object -ExpandProperty $ldapsigningname
if (%ldapsigningoutcome){
    Write-Output "LDAP Signing output: $ldapsigningoutcome`r`n"
}
#1 means none
#2 means require signing

$auditkerbauthsrv = auditpol /get /subcategory:"Kerberos Authentication Service" | FindStr "Kerberos"
if (%auditkerbauthsrv){
    Write-Output "Audit Kerberos Authentication Service output: $auditkerbauthsrv`r`n"
}
#Default is success
#Should be set to success & failure

$auditkerbsrtvticket = auditpol /get /subcategory:"Kerberos Service Ticket Operations"
if (%auditkerbsrtvticket){
    Write-Output "Kerberos Service Ticket Operations output: $auditkerbsrtvticket`r`n"
}
#Default is success
#Should be set to success & failure

$kerbencryptionpath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
$kerbencryptionname = "SupportedEncryptionTypes"
$kerbencryptionoutput = Get-ItemProperty -Path $kerbencryptionpath -Name $kerbencryptionname | Select-Object -ExpandProperty $kerbencryptionname
if (%kerbencryptionoutput){
    Write-Output "Kerberos Encryption Support: $kerbencryptionoutput`r`n"
}
#Should be 2147483640