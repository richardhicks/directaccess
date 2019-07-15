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
    Renew-DaSelfSignedCertificates.ps1 -Iphttps

    Running the command with the -Iphttps parameter will renew the DirectAccess IP-HTTPS self-signed certificate.

.EXAMPLE
    Renew-DaSelfSignedCertificates.ps1 -Nls

    Running the command with the -Nls parameter will renew the DirectAccess NLS self-signed certificate.

.EXAMPLE
    Renew-DaSelfSignedCertificates.ps1 -Radius

    Running the command with the -Radius parameter will renew the DirectAccess RADIUS encryption self-signed certificate.

.EXAMPLE
    Renew-DaSelfSignedCertificates.ps1 -All

    Running the command with the -All parameter will renew all DirectAccess self-signed certificates.

.DESCRIPTION
    DirectAccess uses self-signed certificates when configured using the Getting Started Wizard, sometimes referred to as the "simplified deployment" method. Self-signed certificates are also an option when using the standard deployment wizard. These certificates expire 5 years from the date of installation.
    
    Microsoft currently provides no documentation or method for renewing these certificates. However, this script will renew these certificates and update the DirectAccess configuration automatically.

    WARNING! This PowerShell script will make changes to the DirectAccess configuration that may break connectivity for remote clients. See the "Related Links" section below for more information.

.LINK
    https://directaccess.richardhicks.com/2019/05/02/renew-directaccess-self-signed-certificates/

.LINK
    https://directaccess.richardhicks.com/2012/11/28/windows-server-2012-directaccess-simplified-deployment-limitations/

.NOTES
    Version:        1.1
    Creation Date:  July 14, 2019
    Last Updated:   July 15, 2019
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
# MIINRAYJKoZIhvcNAQcCoIINNTCCDTECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU7XigvVh+AJzRfTKZGeWfU8T9
# e3CgggqGMIIFMDCCBBigAwIBAgIQBAkYG1/Vu2Z1U0O1b5VQCDANBgkqhkiG9w0B
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
# T8aTEAb8B4H6i9r5gkn3Ym6hU/oSlBiFLpKR6mhsRDKyZqHnGKSaZFHvMIIFTjCC
# BDagAwIBAgIQDRySYKw7OlG2XJ5gdgi+ETANBgkqhkiG9w0BAQsFADByMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29k
# ZSBTaWduaW5nIENBMB4XDTE4MTIxOTAwMDAwMFoXDTE5MTIyMzEyMDAwMFowgYox
# CzAJBgNVBAYTAlVTMQswCQYDVQQIEwJDQTEWMBQGA1UEBxMNTWlzc2lvbiBWaWVq
# bzEqMCgGA1UEChMhUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nLCBJbmMuMSow
# KAYDVQQDEyFSaWNoYXJkIE0uIEhpY2tzIENvbnN1bHRpbmcsIEluYy4wggEiMA0G
# CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDUHjzuLxgClv+gWiUDH0+9f5AOxNlM
# P1NukiHgYChzeuSTWsHEkx+PsdMqUJCpRtzxYupKrSVLiTp0NDcgbsrenVDR3iXa
# dKrhjaOHovAjmg+KMPkCCj7qkiBsrBHAZD0ooTwVLXKOhgbJk4Cdar6ttgPUVmZy
# 3rMuk9EjOKcd+Gbc9T0kBId3ZRCQUV7Wd/V4yzCxIcm4Vn/2KpZ2abuTeRJ6nYGE
# fKZoTpH3XCus95DypF36Bvg8virD5O8e07cOXk/8qpRetjNhCWc4y5vHWQC+k6Yj
# Coqk6TopQ59a+M/fNcqicbPMnvqNNPTDNJ3zEJLH1n01AVdA16+1CospAgMBAAGj
# ggHFMIIBwTAfBgNVHSMEGDAWgBRaxLl7KgqjpepxA8Bg+S32ZXUOWDAdBgNVHQ4E
# FgQUC8RAAtkGb09tnKvrEQH4/M39pzAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQM
# MAoGCCsGAQUFBwMDMHcGA1UdHwRwMG4wNaAzoDGGL2h0dHA6Ly9jcmwzLmRpZ2lj
# ZXJ0LmNvbS9zaGEyLWFzc3VyZWQtY3MtZzEuY3JsMDWgM6Axhi9odHRwOi8vY3Js
# NC5kaWdpY2VydC5jb20vc2hhMi1hc3N1cmVkLWNzLWcxLmNybDBMBgNVHSAERTBD
# MDcGCWCGSAGG/WwDATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2Vy
# dC5jb20vQ1BTMAgGBmeBDAEEATCBhAYIKwYBBQUHAQEEeDB2MCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wTgYIKwYBBQUHMAKGQmh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJBc3N1cmVkSURDb2RlU2ln
# bmluZ0NBLmNydDAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQDwrBWt
# OLyXkZ5jW/Y1GjxZlpNzBfswqNObyvwrg1xyNSAjVzo8lrswcqMfg/mMMr/Rx4C/
# 5y+JEJLCuR6+nuLNY8qQ5V57MtLm5/QhuwWsqMOjA7msIK67HZz8JB5QiVRaBKOg
# j6Tse+lZMkzFDGo5muwEXUKCkFBl8bXYOPne8Sd9m3mgQ+XhCbGy/f5yabKFHb9o
# JgwwaScbNAYBE0VpWLIuO8uLGmSJdezW1uGYgs1PmErPd4VBR6i4q9gJD9bnAyud
# RGwP8bLsJdP24eqXJRE+ulm+TyG9r/jL78161wXb5f0Cva1wFz808xUeagzOybS/
# qPK28b1JAJ4jpGCTMYICKDCCAiQCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8G
# A1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIENvZGUgU2lnbmluZyBDQQIQ
# DRySYKw7OlG2XJ5gdgi+ETAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAig
# AoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgEL
# MQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUTxU2gSQKHp6aKQWdUeoK
# 1NlPxQcwDQYJKoZIhvcNAQEBBQAEggEApNq+yyswlEQ3AdchbUZMRIjArEXOOieh
# 6rdg1IvOUBUhPtiy7BM7PBG9fcPKDLsd7vuBxtivMicI8tsliF0bDf0cUtBOsuhn
# WxmrsWUC8GUGDHQgrmA3urVm4vWYWz9cydzYA9QSJT/QQZz2emp624zcV3xkvug1
# GIcNjx84yxOlkjlkYy5m5T7/MSQG2uAvQBMM54WqdbjkWQDKlG3tChTbnYTzUwYZ
# Kih6zWv35mIxyTRDk5MYnTVM7v3790kBsrCXfGxSt2jdmsWBGcNxbFz6HBdWAprY
# gSfRDJJBNkLcnK/HxkEZkeE9xdW4bOBhU3d7u1gLsVK+oQgAIpMFZw==
# SIG # End signature block
