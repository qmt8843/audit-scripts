$ldapsigningpath = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
$ldapsigningname = "LDAPServerIntegrity"

$ldapsigningoutcome = Get-ItemProperty -Path $ldapsigningpath -Name $ldapsigningname | Select-Object -ExpandProperty $ldapsigningname
Write-Output "LDAP Signing is set to $ldapsigningoutcome"
#1 means none
#2 means require signing