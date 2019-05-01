# // Renew DirectAccess Self-Signed Certificates

# // Clone and install IP-HTTPS certificate

$iphttpscert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object Thumbprint -eq ((Get-RemoteAccess).SslCertificate | Select-Object -ExpandProperty Thumbprint))
$newcert = New-SelfSignedCertificate -CloneCert $iphttpscert -FriendlyName "DirectAccess-IPHTTPS" | Select-Object -ExpandProperty Thumbprint
$cert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object Thumbprint -eq $newcert)
Set-RemoteAccess -SslCertificate $cert -PassThru

# // Clone and install NLS certificate

$nlscert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object Thumbprint -eq ((Get-RemoteAccess).NlsCertificate | Select-Object -ExpandProperty Thumbprint))
$newcert = New-SelfSignedCertificate -CloneCert $nlscert -FriendlyName "DirectAccess-NLS" | Select-Object -ExpandProperty Thumbprint
$cert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object Thumbprint -eq $newcert)
Set-DANetworkLocationServer -NLSOnDAServer -Certificate $cert

# // Clone RADIUS encryption certificate

$cert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object Subject -like "*radius-encrypt*")
New-SelfSignedCertificate -CloneCert $cert -FriendlyName "Certificate issued by Remote Access for RADIUS shared secrets"