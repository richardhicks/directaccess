<#

.SYNOPSIS
    PowerShell script to renew DirectAccess self-signed certificates.

.PARAMETER Iphttps
    Renew the DirectAccess IP-HTTPS self-signed certificate.

.PARAMETER Nls
    Renew the DirectAccess NLS self-signed certificate.

.PARAMETER Radius
    Renew the DirectAccess RADIUS encryption self-signed certificate. Only required when OTP authentication is configured for DirectAccess clients.

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
    Note: Renewing the RADIUS encryption certificate is only required when OTP authentication is configured for DirectAccess clients.

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
    Version:        2.01
    Creation Date:  July 14, 2019
    Last Updated:   December 28, 2021
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Web Site:       https://directaccess.richardhicks.com/

#>

[CmdletBinding()]

Param(

    [switch]$Iphttps,
    [switch]$Nls,
    [switch]$Radius,
    [switch]$All = [switch]::Present

)

# // If an individual certificate is selected set the value of the $All parameter to $false.
If ($Iphttps -or $Nls -or $Radius) {

    $All = $false

}

If ($Iphttps -or $All) {

    # //Identify current IP-HTTPS certificate.
    Write-Verbose 'Cloning DirectAccess IP-HTTPS certificate...'
    $IphttpsCert = (Get-ChildItem -Path 'Cert:\LocalMachine\My\' | Where-Object 'Thumbprint' -eq ((Get-RemoteAccess).SslCertificate | Select-Object -ExpandProperty 'Thumbprint'))

    # // Windows Server 2012/2012R2 does not support the -FriendlyName switch. Omit if either OS is detected.
    If ((Get-CimInstance 'Win32_OperatingSystem' | Select-Object -ExpandProperty 'Caption') -like '*2012*') {

        # // Clone current IP-HTTPS certificate. 
        $NewCert = New-SelfSignedCertificate -CloneCert $IphttpsCert -CertStoreLocation 'Cert:\LocalMachine\My'

    }

    Else {

        # // Clone current IP-HTTPS certificate using -FriendlyName switch if running Windows Server 2016 or later.
        $NewCert = New-SelfSignedCertificate -CloneCert $IphttpsCert -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'DirectAccess-IPHTTPS'

    }

    # // Update DirectAccess configuration with new IP-HTTPS certificate.
    Write-Verbose 'Updating DirectAccess configuration with new IP-HTTPS certificate...'
    $Cert = (Get-ChildItem -Path 'Cert:\LocalMachine\My\' | Where-Object Thumbprint -eq $NewCert.Thumbprint)
    Set-RemoteAccess -SslCertificate $Cert -PassThru
    Write-Warning 'DirectAccess clients will not be able to connect remotely until they have updated group policy.'

} # iphttpscert

If ($Nls -or $All) {

    # // Identify current NLS certificate.
    Write-Verbose 'Cloning DirectAccess NLS certificate...'
    $NlsCert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object Thumbprint -eq ((Get-RemoteAccess).NlsCertificate | Select-Object -ExpandProperty Thumbprint))

    # // Windows Server 2012/2012R2 does not support the -FriendlyName switch. Omit if either OS is detected.
    If ((Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -like '*2012*') {

        # // Clone current NLS certificate.
        $NewCert = New-SelfSignedCertificate -CloneCert $NlsCert -CertStoreLocation 'Cert:\LocalMachine\My'

    }

    Else {

        # // Clone current NLS certificate using -FriendlyName switch if running Windows Server 2016 or later.
        $NewCert = New-SelfSignedCertificate -CloneCert $NlsCert -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'DirectAccess-NLS'

    }

    # // Update DirectAccess configuration with new NLS certificate.
    Write-Verbose 'Updating DirectAccess configuration with new NLS certificate...'
    $Cert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object Thumbprint -eq $NewCert.Thumbprint)
    Set-DANetworkLocationServer -NLSOnDAServer -Certificate $Cert -PassThru

} # nlscert

If ($Radius -or $All) {

    # // Identify current RADIUS encryption certificate.
    Write-Verbose 'Cloning DirectAccess RADIUS encryption certificate...'
    $RadiusCert = (Get-ChildItem -Path Cert:\LocalMachine\My\ | Where-Object Subject -like "*radius-encrypt*")

    # // Windows Server 2012/2012R2 does not support the -FriendlyName switch. Omit if either OS is detected.
    If ((Get-CimInstance Win32_OperatingSystem | Select-Object -ExpandProperty Caption) -like '*2012*') {

        # // Clone current RADIUS encryption certificate.
        $NewCert = New-SelfSignedCertificate -CloneCert $RadiusCert -CertStoreLocation 'Cert:\LocalMachine\My'
    }

    Else {

        # // Clone current RADIUS encryption certificate using -FriendlyName switch if running Windows Server 2016 or later.
        $NewCert = New-SelfSignedCertificate -CloneCert $RadiusCert -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName "Certificate issued by Remote Access for RADIUS shared secrets"

    }

    # // Identify machine SID and create registry path.
    $ComputerName = $env:computername + '$'
    $Id = New-Object System.Security.Principal.NTAccount($ComputerName)
    $MachineSid = $Id.Translate([System.Security.Principal.SecurityIdentifier]).ToString()
    $RegPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\RemoteAccess\Config\MachineSIDs\$MachineSid\"
    $CertBinary = $NewCert.GetRawCertData()

    # // Get DirectAccess server settings GPO name
    $Gpo = (Get-RemoteAccess).ServerGpoName
    $Gpo = $Gpo.Split('\')[1]

    # // Define registry settings.
    $Parameters = @{

        Name      = $Gpo
        Key       = $RegPath
        ValueName = 'ServerCertForRadius'
        Type      = 'BINARY'
        Value     = $CertBinary
    
    }

    Write-Verbose "Publishing new RADIUS encryption certificate to the ""$Gpo"" group policy object..."
    Set-GpRegistryValue @Parameters
    Write-Warning 'You must update group policy on this machine for changes to take effect.'

} # radiuscert

# SIG # Begin signature block
# MIIdWQYJKoZIhvcNAQcCoIIdSjCCHUYCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUUMSsmD+gad9eQoIY9TXtgLdf
# s9igghfxMIIE/jCCA+agAwIBAgIQDUJK4L46iP9gQCHOFADw3TANBgkqhkiG9w0B
# AQsFADByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFz
# c3VyZWQgSUQgVGltZXN0YW1waW5nIENBMB4XDTIxMDEwMTAwMDAwMFoXDTMxMDEw
# NjAwMDAwMFowSDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MSAwHgYDVQQDExdEaWdpQ2VydCBUaW1lc3RhbXAgMjAyMTCCASIwDQYJKoZIhvcN
# AQEBBQADggEPADCCAQoCggEBAMLmYYRnxYr1DQikRcpja1HXOhFCvQp1dU2UtAxQ
# tSYQ/h3Ib5FrDJbnGlxI70Tlv5thzRWRYlq4/2cLnGP9NmqB+in43Stwhd4CGPN4
# bbx9+cdtCT2+anaH6Yq9+IRdHnbJ5MZ2djpT0dHTWjaPxqPhLxs6t2HWc+xObTOK
# fF1FLUuxUOZBOjdWhtyTI433UCXoZObd048vV7WHIOsOjizVI9r0TXhG4wODMSlK
# XAwxikqMiMX3MFr5FK8VX2xDSQn9JiNT9o1j6BqrW7EdMMKbaYK02/xWVLwfoYer
# vnpbCiAvSwnJlaeNsvrWY4tOpXIc7p96AXP4Gdb+DUmEvQECAwEAAaOCAbgwggG0
# MA4GA1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMEEGA1UdIAQ6MDgwNgYJYIZIAYb9bAcBMCkwJwYIKwYBBQUHAgEWG2h0
# dHA6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAfBgNVHSMEGDAWgBT0tuEgHf4prtLk
# YaWyoiWyyBc1bjAdBgNVHQ4EFgQUNkSGjqS6sGa+vCgtHUQ23eNqerwwcQYDVR0f
# BGowaDAyoDCgLoYsaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItYXNzdXJl
# ZC10cy5jcmwwMqAwoC6GLGh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWFz
# c3VyZWQtdHMuY3JsMIGFBggrBgEFBQcBAQR5MHcwJAYIKwYBBQUHMAGGGGh0dHA6
# Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBPBggrBgEFBQcwAoZDaHR0cDovL2NhY2VydHMu
# ZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkFzc3VyZWRJRFRpbWVzdGFtcGluZ0NB
# LmNydDANBgkqhkiG9w0BAQsFAAOCAQEASBzctemaI7znGucgDo5nRv1CclF0CiNH
# o6uS0iXEcFm+FKDlJ4GlTRQVGQd58NEEw4bZO73+RAJmTe1ppA/2uHDPYuj1UUp4
# eTZ6J7fz51Kfk6ftQ55757TdQSKJ+4eiRgNO/PT+t2R3Y18jUmmDgvoaU+2QzI2h
# F3MN9PNlOXBL85zWenvaDLw9MtAby/Vh/HUIAHa8gQ74wOFcz8QRcucbZEnYIpp1
# FUL1LTI4gdr0YKK6tFL7XOBhJCVPst/JKahzQ1HavWPWH1ub9y4bTxMd90oNcX6X
# t/Q/hOvB46NJofrOp79Wz7pZdmGJX36ntI5nePk2mOHLKNpbh6aKLzCCBTEwggQZ
# oAMCAQICEAqhJdbWMht+QeQF2jaXwhUwDQYJKoZIhvcNAQELBQAwZTELMAkGA1UE
# BhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2lj
# ZXJ0LmNvbTEkMCIGA1UEAxMbRGlnaUNlcnQgQXNzdXJlZCBJRCBSb290IENBMB4X
# DTE2MDEwNzEyMDAwMFoXDTMxMDEwNzEyMDAwMFowcjELMAkGA1UEBhMCVVMxFTAT
# BgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEx
# MC8GA1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBD
# QTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAL3QMu5LzY9/3am6gpnF
# OVQoV7YjSsQOB0UzURB90Pl9TWh+57ag9I2ziOSXv2MhkJi/E7xX08PhfgjWahQA
# OPcuHjvuzKb2Mln+X2U/4Jvr40ZHBhpVfgsnfsCi9aDg3iI/Dv9+lfvzo7oiPhis
# EeTwmQNtO4V8CdPuXciaC1TjqAlxa+DPIhAPdc9xck4Krd9AOly3UeGheRTGTSQj
# MF287DxgaqwvB8z98OpH2YhQXv1mblZhJymJhFHmgudGUP2UKiyn5HU+upgPhH+f
# MRTWrdXyZMt7HgXQhBlyF/EXBu89zdZN7wZC/aJTKk+FHcQdPK/P2qwQ9d2srOlW
# /5MCAwEAAaOCAc4wggHKMB0GA1UdDgQWBBT0tuEgHf4prtLkYaWyoiWyyBc1bjAf
# BgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzASBgNVHRMBAf8ECDAGAQH/
# AgEAMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB5BggrBgEF
# BQcBAQRtMGswJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBD
# BggrBgEFBQcwAoY3aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNydDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2Ny
# bDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDig
# NoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9v
# dENBLmNybDBQBgNVHSAESTBHMDgGCmCGSAGG/WwAAgQwKjAoBggrBgEFBQcCARYc
# aHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggEBAHGVEulRh1Zpze/d2nyqY3qzeM8GN0CE70uEv8rPAwL9xafD
# DiBCLK938ysfDCFaKrcFNB1qrpn4J6JmvwmqYN92pDqTD/iy0dh8GWLoXoIlHsS6
# HHssIeLWWywUNUMEaLLbdQLgcseY1jxk5R9IEBhfiThhTWJGJIdjjJFSLK8pieV4
# H9YLFKWA1xJHcLN11ZOFk362kmf7U2GJqPVrlsD0WGkNfMgBsbkodbeZY4UijGHK
# eZR+WfyMD+NvtQEmtmyl7odRIeRYYJu6DC0rbaLEfrvEJStHAgh8Sa4TtuF8QkIo
# xhhWz0E0tmZdtnR79VYzIi8iNrJLokqV2PWmjlIwggawMIIEmKADAgECAhAIrUCy
# YNKcTJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVTMRUwEwYD
# VQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAf
# BgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0MjkwMDAwMDBa
# Fw0zNjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4IC
# DwAwggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYwn6SOaNhc
# 9es0JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43iCH00fUyA
# VxJrQ5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1hz1RGeiQ
# IXhFLqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd6BgTZcV/
# sk+FLEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObarYBLj6Na5
# 9zHh3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18ebMlrC/2pg
# VItJwZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYoX7Bzzosm
# JQayg9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDzd5Ea/ttQ
# okbIYViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8SkXbev1jL
# chApQfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZYIpkVMHM
# IRroOBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxWEQIDAQAB
# o4IBWTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg67Y7+F8R
# hvv+YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYD
# VR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUFBwEBBGsw
# aTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUF
# BzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVk
# Um9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTATMAcGBWeB
# DAEDMAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6PvDqZ01bg
# Ahql+Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V1T9J9Ce7
# FoFFUP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+3NiAGhEZ
# GM1hmYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcnP/2Q0XaG
# 3RywYFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgUkpn13c5U
# bdldAhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6QB7BDf5WI
# IIJw8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3kuZOX956
# rEnPLqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKLQcBIhEuW
# TatEQOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47vtevLt/B3
# E+bnKD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0qFEgu60b
# hQjiWQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0YW6/aOIm
# YIbqyK+p/pQd52MbOoZWeE4wggcCMIIE6qADAgECAhABZnISBJVCuLLqeeLTB6xE
# MA0GCSqGSIb3DQEBCwUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2Vy
# dCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25p
# bmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjExMjAyMDAwMDAwWhcNMjQx
# MjIwMjM1OTU5WjCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEx
# FjAUBgNVBAcTDU1pc3Npb24gVmllam8xJDAiBgNVBAoTG1JpY2hhcmQgTS4gSGlj
# a3MgQ29uc3VsdGluZzEkMCIGA1UEAxMbUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0
# aW5nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA6svrVqBRBbazEkrm
# htz7h05LEBIHp8fGlV19nY2gpBLnkDR8Mz/E9i1cu0sdjieC4D4/WtI4/NeiR5id
# tBgtdek5eieRjPcn8g9Zpl89KIl8NNy1UlOWNV70jzzqZ2CYiP/P5YGZwPy8Lx5r
# IAOYTJM6EFDBvZNti7aRizE7lqVXBDNzyeHhfXYPBxaQV2It+sWqK0saTj0oNA2I
# u9qSYaFQLFH45VpletKp7ded2FFJv2PKmYrzYtax48xzUQq2rRC5BN2/n7771NDf
# J0t8udRhUBqTEI5Z1qzMz4RUVfgmGPT+CaE55NyBnyY6/A2/7KSIsOYOcTgzQhO4
# jLmjTBZ2kZqLCOaqPbSmq/SutMEGHY1MU7xrWUEQinczjUzmbGGw7V87XI9sn8Ec
# WX71PEvI2Gtr1TJfnT9betXDJnt21mukioLsUUpdlRmMbn23or/VHzE6Nv7Kzx+t
# A1sBdWdC3Mkzaw/Mm3X8Wc7ythtXGBcLmBagpMGCCUOk6OJZAgMBAAGjggIGMIIC
# AjAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG+/5hewiIZfROQjAdBgNVHQ4EFgQUxF7d
# o+eIG9wnEUVjckZ9MsbZ+4kwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsG
# AQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIw
# MjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEzODQyMDIxQ0ExLmNybDA+
# BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUFBwIBFhtodHRwOi8vd3d3LmRp
# Z2ljZXJ0LmNvbS9DUFMwgZQGCCsGAQUFBwEBBIGHMIGEMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXAYIKwYBBQUHMAKGUGh0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5nUlNB
# NDA5NlNIQTM4NDIwMjFDQTEuY3J0MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQEL
# BQADggIBAEvHt/OKalRysHQdx4CXSOcgoayuFXWNwi/VFcFr2EK37Gq71G4AtdVc
# WNLu+whhYzfCVANBnbTa9vsk515rTM06exz0QuMwyg09mo+VxZ8rqOBHz33xZyCo
# Ttw/+D/SQxiO8uQR0Oisfb1MUHPqDQ69FTNqIQF/RzC2zzUn5agHFULhby8wbjQf
# Ut2FXCRlFULPzvp7/+JS4QAJnKXq5mYLvopWsdkbBn52Kq+ll8efrj1K4iMRhp3a
# 0n2eRLetqKJjOqT335EapydB4AnphH2WMQBHHroh5n/fv37dCCaYaqo9JlFnRIrH
# U7pHBBEpUGfyecFkcKFwsPiHXE1HqQJCPmMbvPdV9ZgtWmuaRD0EQW13JzDyoQdJ
# xQZSXJhDDL+VSFS8SRNPtQFPisZa2IO58d1Cvf5G8iK1RJHN/Qx413lj2JSS1o3w
# gNM3Q5ePFYXcQ0iPxjFYlRYPAaDx8t3olg/tVK8sSpYqFYF99IRqBNixhkyxAyVC
# k6uLBLgwE9egJg1AFoHEdAeabGgT2C0hOyz55PNoDZutZB67G+WN8kGtFYULBloR
# KHJJiFn42bvXfa0Jg1jZ41AAsMc5LUNlqLhIj/RFLinDH9l4Yb0ddD4wQVsIFDVl
# JgDPXA9E1Sn8VKrWE4I0sX4xXUFgjfuVfdcNk9Q+4sJJ1YHYGmwLMYIE0jCCBM4C
# AQEwfTBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/
# BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYg
# U0hBMzg0IDIwMjEgQ0ExAhABZnISBJVCuLLqeeLTB6xEMAkGBSsOAwIaBQCgeDAY
# BgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3
# AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMGCSqGSIb3DQEJBDEW
# BBT+kSEg5JvHI3zF/vx1Z4oySOHQEjANBgkqhkiG9w0BAQEFAASCAYBUm/DceTGH
# Mo+uF4fO2R/B3l7FK532nCpOQ9qFaXC0IMEBSyxt2hEWlrjWZlYRA5dnH2NMWWRz
# 7iE7knTVVcyUFMGECEbXOnH1CRXsz8FjbNrV4mfD9lg+Sokd6TWNcegXxKh0ygMo
# 9z2fdLcrmnNsfvJfYfpk+YE6U6K1IWGRipodDOLMAybaYUZ1lOR7+VHbhegd8mlM
# YdqLNyUzvAxtXNOPWfodIjlZEMjIkT4jXNVthJcVd2iqyk4BKMiwC0lIFqiqKBta
# xEPrTFn3aZJqQ6MZnrPQflYbZotgqF+oXxGm64ixv/iSaA8FiWsZQOOgEEyTZAqf
# N/7Aj7EV+kuMUrB0k8P3daACJKuQY7TlKse3sGOpmU/vcMghieCvhPyA3jdFsxOl
# oa6bVWMzLwUgk3YQsEd/pwFUZnY0C6rhn/30qEpdBi7BJqp4pPZq5FmQCc51Nnn/
# HSZOubtgwqKmXPlP+C5r1/eLmMkSoIAETOAxY3ze9LCwY0eKvvbJsOahggIwMIIC
# LAYJKoZIhvcNAQkGMYICHTCCAhkCAQEwgYYwcjELMAkGA1UEBhMCVVMxFTATBgNV
# BAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTExMC8G
# A1UEAxMoRGlnaUNlcnQgU0hBMiBBc3N1cmVkIElEIFRpbWVzdGFtcGluZyBDQQIQ
# DUJK4L46iP9gQCHOFADw3TANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJAzEL
# BgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTIxMTIyODIwNTYwNFowLwYJKoZI
# hvcNAQkEMSIEIBoZbfCyeTisB1iuytvqMOs26LQk0Vfteg5AmxuadxMcMA0GCSqG
# SIb3DQEBAQUABIIBAI+1NX5L/20W0L74TufjXF5kI7nJZuNdXVpSgYgd4/4dpBEq
# 36fy0067ktD/5F4K6I9ov1bRkuhx8Lin31/ft0jSuxAALss3pbgd3GlhpiaMlFKq
# X0ucLiWlD7jMSB9Inx+eAjNorYwgYCBpTs32sYw632l5OGgBiGfuyHBzkL0n+b0K
# pz3cDt4DcULXMmsfNYSybPOS8DXWLkEF8OK7tiedlF8s0hfFMKlo+qzd6Qwf2J4G
# DY2iJ/CpjxPZu3odcKABIG5ppCWM+n8tNOxmYWWb4pXIlJLI5rjBVv33BjDVVwXb
# Ozvze+NMrmnwZzJ09CjuD0ceSjr3Imy9e3/9a9Q=
# SIG # End signature block
