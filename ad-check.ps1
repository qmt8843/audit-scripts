$examplepath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Power"
$examplename = "Firmware-Final"

$test = Get-ItemProperty -Path $examplepath -Name $examplename | Select-Object -ExpandProperty $examplename
$test