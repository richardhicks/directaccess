<#

.SYNOPSIS
    PowerShell script to renew DirectAccess self-signed certificates.

.PARAMETER Iphttps
    Renew the DirectAccess IP-HTTPS self-signed certificate.

.PARAMETER Nls
    Renew the DirectAccess NLS self-signed certificate.

.PARAMETER Radius
    Renew the DirectAccess RADIUS encryption self-signed certificate.

.PARAMETER All
    Renew all DirectAccess self-signed certificates.

.EXAMPLE
    .\Renew-DaSelfSignedCertificates.ps1 -Iphttps

    Running this command with the -Iphttps parameter will renew the DirectAccess IP-HTTPS self-signed certificate.

.EXAMPLE
    .\Renew-DaSelfSignedCertificates.ps1 -Nls

    Running this command with the -Nls parameter will renew the DirectAccess NLS self-signed certificate.

.EXAMPLE
    .\Renew-DaSelfSignedCertificates.ps1 -Radius

    Running this command with the -Radius parameter will renew the DirectAccess RADIUS encryption self-signed certificate.

.EXAMPLE
    .\Renew-DaSelfSignedCertificates.ps1 -All

    Running this command with the -All parameter will renew all DirectAccess self-signed certificates.

.DESCRIPTION
    DirectAccess uses self-signed certificates when configured using the Getting Started Wizard, sometimes referred to as the "simplified deployment" method. Self-signed certificates are also an option when using the standard deployment wizard. These certificates expire 5 years from the date of installation.
    
    Microsoft currently provides no documentation or method for renewing these certificates. However, this script will renew these certificates and update the DirectAccess configuration automatically.

    WARNING! This PowerShell script will make changes to the DirectAccess configuration that may break connectivity for remote clients. See the "Related Links" section below for more information.

.LINK
    https://directaccess.richardhicks.com/2019/05/02/renew-directaccess-self-signed-certificates/

.LINK
    https://directaccess.richardhicks.com/2012/11/28/windows-server-2012-directaccess-simplified-deployment-limitations/

.NOTES
    Version:        1.11
    Creation Date:  July 14, 2019
    Last Updated:   February 3, 2020
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Web Site:       www.richardhicks.com

#>

[CmdletBinding()]

Param(

    [switch]$Iphttps,
    [switch]$Nls,
    [switch]$Radius,
    [switch]$All = [switch]::Present

)

# If an individual certificate is selected set the value of the $All parameter to $false.
If ($Iphttps -or $Nls -or $Radius) {

    $All = $false

}

If ($Iphttps -or $All) {

    # Identify current IP-HTTPS certificate.
    Write-Verbose 'Cloning DirectAccess IP-HTTPS certificate...'
    $IphttpsCert = (Get-ChildItem -Path 'Cert:\LocalMachine\My\' | Where-Object 'Thumbprint' -eq ((Get-RemoteAccess).SslCertificate | Select-Object -ExpandProperty 'Thumbprint'))

    # Windows Server 2012/2012R2 does not support the -FriendlyName switch. Omit if either OS is detected.
    If ((Get-CimInstance 'Win32_OperatingSystem' | Select-Object -ExpandProperty 'Caption') -like '*2012*') {

        # Clone current IP-HTTPS certificate. 
        $newcert = New-SelfSignedCertificate -CloneCert $IphttpsCert -CertStoreLocation 'Cert:\LocalMachine\My'

    }

    Else {

        # Clone current IP-HTTPS certificate using -FriendlyName switch if running Windows Server 2016 or later.
        $newcert = New-SelfSignedCertificate -CloneCert $IphttpsCert -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'DirectAccess-IPHTTPS'

    }

    # Update DirectAccess configuration with new IP-HTTPS certificate.
    Write-Verbose 'Updating DirectAccess configuration with new IP-HTTPS certificate...'
    $cert = (Get-ChildItem -Path 'Cert:\LocalMachine\My\' | Where-Object Thumbprint -eq $newcert.Thumbprint)
    Set-RemoteAccess -SslCertificate $cert -PassThru

} # iphttpscert

If ($Nls -or $All) {

    # Identify current NLS certificate.
    Write-Verbose 'Cloning DirectAccess NLS certificate...'
    $NlsCert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object Thumbprint -eq ((Get-RemoteAccess).NlsCertificate | Select-Object -ExpandProperty Thumbprint))

    # Windows Server 2012/2012R2 does not support the -FriendlyName switch. Omit if either OS is detected.
    If ((Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -like '*2012*') {

        # Clone current NLS certificate.
        $newcert = New-SelfSignedCertificate -CloneCert $NlsCert -CertStoreLocation 'Cert:\LocalMachine\My'

    }

    Else {

        # Clone current NLS certificate using -FriendlyName switch if running Windows Server 2016 or later.
        $newcert = New-SelfSignedCertificate -CloneCert $NlsCert -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'DirectAccess-NLS'

    }

    # Update DirectAccess configuration with new NLS certificate.
    Write-Verbose 'Updating DirectAccess configuration with new NLS certificate...'
    $cert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object Thumbprint -eq $newcert.Thumbprint)
    Set-DANetworkLocationServer -NLSOnDAServer -Certificate $cert -PassThru

} # nlscert

If ($Radius -or $All) {

    # Identify current RADIUS encryption certificate.
    Write-Verbose 'Cloning DirectAccess RADIUS encryption certificate...'
    $RadiusCert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object Subject -like "*radius-encrypt*")

    # Windows Server 2012/2012R2 does not support the -FriendlyName switch. Omit if either OS is detected.
    If ((Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -like '*2012*') {

        # Clone current RADIUS encryption certificate.
        New-SelfSignedCertificate -CloneCert $RadiusCert -CertStoreLocation 'Cert:\LocalMachine\My'
    }
    Else {

        # Clone current RADIUS encryption certificate using -FriendlyName switch if running Windows Server 2016 or later.
        New-SelfSignedCertificate -CloneCert $RadiusCert -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName "Certificate issued by Remote Access for RADIUS shared secrets"

    }

} # radiuscert

Write-Output 'Script complete.'

# SIG # Begin signature block
# MIINbAYJKoZIhvcNAQcCoIINXTCCDVkCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUtq0I8t+u4VCa67pzldxcuZGh
# VkWgggquMIIFMDCCBBigAwIBAgIQBAkYG1/Vu2Z1U0O1b5VQCDANBgkqhkiG9w0B
# AQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMTMxMDIyMTIwMDAwWhcNMjgxMDIyMTIwMDAwWjByMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQg
# Q29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# +NOzHH8OEa9ndwfTCzFJGc/Q+0WZsTrbRPV/5aid2zLXcep2nQUut4/6kkPApfmJ
# 1DcZ17aq8JyGpdglrA55KDp+6dFn08b7KSfH03sjlOSRI5aQd4L5oYQjZhJUM1B0
# sSgmuyRpwsJS8hRniolF1C2ho+mILCCVrhxKhwjfDPXiTWAYvqrEsq5wMWYzcT6s
# cKKrzn/pfMuSoeU7MRzP6vIK5Fe7SrXpdOYr/mzLfnQ5Ng2Q7+S1TqSp6moKq4Tz
# rGdOtcT3jNEgJSPrCGQ+UpbB8g8S9MWOD8Gi6CxR93O8vYWxYoNzQYIH5DiLanMg
# 0A9kczyen6Yzqf0Z3yWT0QIDAQABo4IBzTCCAckwEgYDVR0TAQH/BAgwBgEB/wIB
# ADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMweQYIKwYBBQUH
# AQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYI
# KwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaG
# NGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcmwwTwYDVR0gBEgwRjA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0
# dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCgYIYIZIAYb9bAMwHQYDVR0OBBYE
# FFrEuXsqCqOl6nEDwGD5LfZldQ5YMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6en
# IZ3zbcgPMA0GCSqGSIb3DQEBCwUAA4IBAQA+7A1aJLPzItEVyCx8JSl2qB1dHC06
# GsTvMGHXfgtg/cM9D8Svi/3vKt8gVTew4fbRknUPUbRupY5a4l4kgU4QpO4/cY5j
# DhNLrddfRHnzNhQGivecRk5c/5CxGwcOkRX7uq+1UcKNJK4kxscnKqEpKBo6cSgC
# PC6Ro8AlEeKcFEehemhor5unXCBc2XGxDI+7qPjFEmifz0DLQESlE/DmZAwlCEIy
# sjaKJAL+L3J+HNdJRZboWR3p+nRka7LrZkPas7CM1ekN3fYBIM6ZMWM9CBoYs4Gb
# T8aTEAb8B4H6i9r5gkn3Ym6hU/oSlBiFLpKR6mhsRDKyZqHnGKSaZFHvMIIFdjCC
# BF6gAwIBAgIQDOTKENcaCUe5Ct81Y25diDANBgkqhkiG9w0BAQsFADByMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29k
# ZSBTaWduaW5nIENBMB4XDTE5MTIxNjAwMDAwMFoXDTIxMTIyMDEyMDAwMFowgbIx
# CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1NaXNz
# aW9uIFZpZWpvMSowKAYDVQQKEyFSaWNoYXJkIE0uIEhpY2tzIENvbnN1bHRpbmcs
# IEluYy4xHjAcBgNVBAsTFVByb2Zlc3Npb25hbCBTZXJ2aWNlczEqMCgGA1UEAxMh
# UmljaGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nLCBJbmMuMIIBIjANBgkqhkiG9w0B
# AQEFAAOCAQ8AMIIBCgKCAQEAr+wmqY7Bpvs6EmNV227JD5tee0m+ltuYmleTJ1TG
# TCfibcWU+2HOHICHoUdSF4M8L0LoonkIWKoMCUaGFzrvMFjlt/J8juH7kazf3mEd
# Z9lzxOt6GLn5ILpq+8i2xb4cGqLd1k8FEJaFcq66Xvi2xknQ3r8cDJWBXi4+CoLY
# 0/VPNNPho2RTlpN8QL/Xz//hE+KB7YzaF+7wYCVCkR/Qn4D8AfiUBCAw8fNbjNGo
# Q/v7xh+f6TidtC7Y5B8D8AR4IJSok8Zbivz+HJj5wZNWsS70D8HnWQ7hM/7nAwQh
# teh0/kj0m6TMVtsv4b9KCDEyPT71cp5g4JxMO+x3UZh0CQIDAQABo4IBxTCCAcEw
# HwYDVR0jBBgwFoAUWsS5eyoKo6XqcQPAYPkt9mV1DlgwHQYDVR0OBBYEFB6Bcy+o
# ShXw68ntqleXMwE4Lj1jMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEF
# BQcDAzB3BgNVHR8EcDBuMDWgM6Axhi9odHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# c2hhMi1hc3N1cmVkLWNzLWcxLmNybDA1oDOgMYYvaHR0cDovL2NybDQuZGlnaWNl
# cnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwTAYDVR0gBEUwQzA3BglghkgB
# hv1sAwEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQ
# UzAIBgZngQwBBAEwgYQGCCsGAQUFBwEBBHgwdjAkBggrBgEFBQcwAYYYaHR0cDov
# L29jc3AuZGlnaWNlcnQuY29tME4GCCsGAQUFBzAChkJodHRwOi8vY2FjZXJ0cy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNzdXJlZElEQ29kZVNpZ25pbmdDQS5j
# cnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAcJWSNtlE7Ml9VLf/
# 96z8tVbF05wZ/EkC4O9ouEdg5AmMx/5LdW2Tz4OrwAUCrRWgIRsC2ea4ZzsZli1i
# 7TdwaYmb2LGKMpq0z1g88iyjIdX6jCoUqMQq1jZAFaJ9iMk7Gn2kHrlcHvVjxwYE
# nf3XxMeGkvvBl8CBkV/fPQ2rrSyKeGSdumWdGGx6Dv/OH5log+x6Qdr6tkFC7byK
# oCBsiETUHs63z53QeVjVxH0zXGa9/G57XphUx18UTYkgIobMN4+dRizxA5sU1WCB
# pstchAVbAsM8OhGoxCJlQGjaXxSk6uis2XretUDhNzCodqdz9ul8CVKem9uJTYjo
# V6CBYjGCAigwggIkAgEBMIGGMHIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xMTAvBgNVBAMTKERp
# Z2lDZXJ0IFNIQTIgQXNzdXJlZCBJRCBDb2RlIFNpZ25pbmcgQ0ECEAzkyhDXGglH
# uQrfNWNuXYgwCQYFKw4DAhoFAKB4MBgGCisGAQQBgjcCAQwxCjAIoAKAAKECgAAw
# GQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisG
# AQQBgjcCARUwIwYJKoZIhvcNAQkEMRYEFJuzMwqYX7IEjeRoQ12t1elavb3kMA0G
# CSqGSIb3DQEBAQUABIIBACId5ap5ADcAv/8yx4m7enAFwZhgl5NosNmpEfNGc9Jr
# WyWKY0BsCqbIsFe4rBoYnbzHZ/TE9uCF/51A/Pm1zNDKE3gpaLsqw6zmb92Pf/xB
# ct5uX00xzehgt9KyqMZPWXu5m4c+4C9pVfd0xjPtrLK0Y3rkpi3xXHIgub9JpDti
# gnODmEWJRN3ZR8x5WlZlnAaxbRMqGdHObuUpJYDAvOgp5RVUr9cxqq1qETDWnbPh
# f0ZXa3tocVFo1ycal1xvzF8Jwq6mdLUsKxD6FzdHvKdzA+yjzOOYCJCSvwdNWBdB
# FBDEK80x4ELZgSauFNS9thCU8VO2EVHO3cV57E2itVA=
# SIG # End signature block
