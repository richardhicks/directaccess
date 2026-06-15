<#PSScriptInfo

.VERSION 1.1.1

.GUID 4310a537-3e45-4f07-bbd9-be8bd0e0c6eb

.AUTHOR Richard Hicks

.COMPANYNAME Richard M. Hicks Consulting, Inc.

.COPYRIGHT Copyright (C) 2026 Richard M. Hicks Consulting, Inc. All Rights Reserved.

.LICENSE Licensed under the MIT License. See LICENSE file in the project root for full license information.

.LICENSEURI https://github.com/richardhicks/directaccess/blob/master/LICENSE

.PROJECTURI https://github.com/richardhicks/directaccess/blob/master/Enable-DACertKit.ps1

.TAGS Microsoft, DirectAccess, CertKit, Certificate, TLS, SSL, IPHTTPS, IPv6

.EXTERNALMODULEDEPENDENCIES ActiveDirectory, GroupPolicy, RemoteAccess

#>

<#

.SYNOPSIS
    Configures a service account for the certkit-agent service on a DirectAccess server for IP-HTTPS TLS certificate automation.

.DESCRIPTION
    DirectAccess requires a public TLS certificate for the IP-HTTPS IPv6 transition technology. When using the CertKit.io agent to manage this certificate, the certkit-agent service must run in the context of a service account (gMSA or standard domain account) with delegated permissions on the DirectAccess Client Settings and DirectAccess Server Settings GPOs in Active Directory.

    The following actions are performed:

    - Validates that the specified account exists in Active Directory and determines whether it is a gMSA or a standard domain user account.
    - Grants 'Edit settings, delete, modify security' permissions on the DirectAccess client and server GPOs in Active Directory. Existing permissions are checked first; each GPO is skipped if the correct permission level is already assigned.
    - Adds the service account to the local Administrators group on the DirectAccess server, if it is not already a member.
    - Grants the 'Log on as a service' user right (standard domain user accounts only; not required for gMSA accounts).
    - Stops the certkit-agent service, reconfigures it to run under the specified account, validates that the service StartName was updated correctly, and restarts the service.

    For gMSA accounts, no password is required. For standard domain user accounts, the script prompts for the account password to configure the service.

    This script requires Administrator privileges and the GroupPolicy and RemoteAccess PowerShell modules.

.PARAMETER AccountName
    The name of the service account to configure. Must be in 'domain\samAccountName' or 'domain\gmsa$' format.

.PARAMETER Force
    Suppresses confirmation prompts for high-impact operations such as modifying GPO permissions.

.INPUTS
    None.

.OUTPUTS
    None.

.EXAMPLE
    .\Enable-DACertKit.ps1 -AccountName "corp\svc-certkit"

    Configures the standard domain user account 'corp\svc-certkit' for the certkit-agent service. Prompts for confirmation before modifying GPO permissions and prompts for the account password before updating the service.

.EXAMPLE
    .\Enable-DACertKit.ps1 -AccountName "corp\gmsa-certkit$" -Force

    Configures the gMSA 'corp\gmsa-certkit$' for the certkit-agent service without prompting for confirmation. No password prompt is issued because the OS manages gMSA credentials.

.EXAMPLE
    .\Enable-DACertKit.ps1 -AccountName "corp\svc-certkit" -Force

    Configures the standard domain user account 'corp\svc-certkit' for the certkit-agent service, suppressing GPO permission confirmation prompts. The account password is still required to configure the service.

.LINK
    https://github.com/richardhicks/directaccess/blob/master/Enable-DACertKit.ps1

.LINK
    https://directaccess.richardhicks.com/2026/03/10/certkit-agent-support-for-always-on-vpn-sstp-and-directaccess-ip-https-tls-certificates/

.LINK
    https://www.certkit.io/

.LINK
    https://www.richardhicks.com/

.NOTES
    Version:        1.1.1
    Creation Date:  March 7, 2026
    Last Updated:   June 15, 2026
    Author:         Richard Hicks
    Organization:   Richard M. Hicks Consulting, Inc.
    Contact:        rich@richardhicks.com
    Website:        https://www.richardhicks.com/

#>

#Requires -Modules GroupPolicy, RemoteAccess
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]

Param (

    [Parameter(Mandatory)]
    [ValidateScript({

        If ($_ -match '^[A-Za-z0-9._-]+\\[A-Za-z0-9._-]+\$?$') { $True }
        Else { Throw "AccountName must be in 'domain\user' or 'domain\gmsa$' format." }

    })]

    [string]$AccountName,
    [switch]$Force

)

# Ensure the certkit-agent service exists. Exit if it does not.
$CertKitService = Get-Service -Name certkit-agent -ErrorAction SilentlyContinue

If (-not $CertKitService) {

    Write-Warning "The certkit-agent service was not found on this system. Ensure the CertKit agent is installed before running this script."
    Return

}

# Validate the specified account exists in Active Directory and determine target type and gMSA status for downstream logic.
Write-Verbose "Resolving account '$AccountName' in Active Directory..."

# Extract domain and samAccountName
$Domain, $Sam = $AccountName.Split('\', 2)

# Validate account exists and retrieve objectClass attributes to determine target type and gMSA status
Try {

    $Root = "LDAP://$Domain"
    $Searcher = New-Object DirectoryServices.DirectorySearcher
    $Searcher.SearchRoot = $Root
    $Searcher.Filter = "(sAMAccountName=$Sam)"
    $Searcher.PropertiesToLoad.AddRange([string[]]@('objectClass', 'sAMAccountName'))

    $Result = $Searcher.FindOne()

    If ($null -eq $Result) {

        Write-Error "Account '$AccountName' does not exist in domain '$Domain'. Cannot continue."
        Return

    }

    $ObjectClasses = @($Result.Properties['objectClass'])

}

Catch {

    Write-Error "Failed to query Active Directory for account '$AccountName'. $($_.Exception.Message)"
    Return

}

# Determine GPO target type from the objectClass hierarchy.
$TargetType = If ($ObjectClasses -contains 'computer') { 'Computer' } Else { 'User' }

# Flag gMSA accounts so downstream logic can skip password prompts
$IsGmsa = $ObjectClasses -contains 'msDS-GroupManagedServiceAccount'

Write-Verbose "Account resolved. Name: '$Sam', ObjectClasses: '$($ObjectClasses -join ', ')', GPO TargetType: '$TargetType', gMSA: $IsGmsa."

# Get RemoteAccess configuration to identify associated GPOs
Try {

    Write-Verbose "Retrieving DirectAccess configuration..."
    $RemoteAccess = Get-RemoteAccess -ErrorAction Stop

}

Catch {

    Write-Warning "Failed to retrieve DirectAccess configuration. Ensure this is a DirectAccess server."
    Write-Warning $_.Exception.Message
    Return

}

# Collect GPO names
$GpoList = @($RemoteAccess.ClientGpoName, $RemoteAccess.ServerGpoName) | Where-Object { $_ }

If ($GpoList.Count -eq 0) {

    Write-Warning "No DirectAccess GPOs found. Nothing to process."
    Return

}

Write-Verbose "Found $($GpoList.Count) DirectAccess GPO(s): $($GpoList -join ', ')."

# Process each GPO to set permissions for the service account
ForEach ($GpoEntry in $GpoList) {

    # Expect "domain\GPO Name"
    $DomainPart, $GpoName = $GpoEntry.Split('\', 2)

    If (-not $GpoName) {

        Write-Warning "Unexpected GPO entry format: '$GpoEntry'. Skipping."
        Continue

    }

    Write-Verbose "Processing GPO '$GpoName' in domain '$DomainPart'..."

    Try {

        $Gpo = Get-GPO -Name $GpoName -Domain $DomainPart -ErrorAction Stop
        Write-Verbose "GPO found. GUID: $($Gpo.Id)"

    }

    Catch {

        Write-Warning "GPO '$GpoName' not found in domain '$DomainPart'. Skipping."
        Write-Warning $_.Exception.Message
        Continue

    }

    # Check existing permissions to avoid unnecessary writes
    Try {

        $Existing = Get-GPPermission -Guid $Gpo.Id -Domain $DomainPart -TargetName $Sam -TargetType $TargetType -ErrorAction Stop

    }

    Catch {

        $Existing = $null

    }

    If ($Existing -and $Existing.Permission -eq 'GpoEditDeleteModifySecurity') {

        Write-Verbose "Permissions already set for '$Sam' on '$GpoName'. Skipping."
        Continue

    }

    # Confirm high impact change
    $ActionDesc = "Grant 'Edit settings, delete, modify security' to '$Sam' on GPO '$GpoName'"
    $TargetDesc = "GPO '$GpoName' in domain '$DomainPart'"

    If ($PSCmdlet.ShouldProcess($TargetDesc, $ActionDesc)) {

        If ($Force -or $PSCmdlet.ShouldContinue("Modify GPO permissions?", $ActionDesc)) {

            Try {

                [void](Set-GPPermission -Guid $Gpo.Id -Domain $DomainPart -TargetName $Sam -TargetType $TargetType -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction Stop)
                Write-Verbose "Granted 'Edit settings, delete, modify security' to '$Sam' on GPO '$GpoName'."

            }

            Catch {

                Write-Warning "Failed to set permissions on GPO '$GpoName'."
                Write-Warning $_.Exception.Message

            }

        }

    }

}

# Check local administrators for service account
$Admins = Get-LocalGroupMember -Group Administrators -Member $AccountName -ErrorAction SilentlyContinue

# Add service account to local Administrators group if required
If ($null -eq $Admins) {

    Write-Verbose "Adding '$AccountName' to the local Administrators group..."

    Try {

        Add-LocalGroupMember -Group Administrators -Member $AccountName -ErrorAction Stop

    }

    Catch {

        Write-Warning "Failed to add '$AccountName' to the local Administrators group. $($_.Exception.Message)"

    }

}

Else {

    Write-Verbose "'$AccountName' is already a member of the local Administrators group."

}

# Grant 'Log on as a service' right to standard domain user accounts only
If (-not $IsGmsa) {

    If (-not ([System.Management.Automation.PSTypeName]'LsaApi').Type) {

        $lsaCode = @'
using System;
using System.Runtime.InteropServices;

public class LsaApi

{

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaOpenPolicy(

        ref LSA_UNICODE_STRING SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccess,
        out IntPtr PolicyHandle

    );

    [DllImport("advapi32.dll", SetLastError = true, PreserveSig = true)]
    public static extern uint LsaAddAccountRights(

        IntPtr PolicyHandle,
        IntPtr AccountSid,
        LSA_UNICODE_STRING[] UserRights,
        long CountOfRights

    );

    [DllImport("advapi32.dll")]
    public static extern uint LsaClose(IntPtr ObjectHandle);

    [DllImport("advapi32.dll")]
    public static extern uint LsaNtStatusToWinError(uint Status);

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_UNICODE_STRING

    {

        public ushort Length;
        public ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string Buffer;

    }

    [StructLayout(LayoutKind.Sequential)]
    public struct LSA_OBJECT_ATTRIBUTES

    {

        public uint   Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint   Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;

    }

}

'@

        Add-Type -TypeDefinition $lsaCode -Language CSharp

    }

    Function Grant-LogOnAsService {

        Param (

        [string]$ServiceAccount

        )

        # Resolve account name to a SID
        Try {

            $ntAccount = New-Object System.Security.Principal.NTAccount($ServiceAccount)
            $sid = $ntAccount.Translate([System.Security.Principal.SecurityIdentifier])

        }

        Catch {

            Write-Error "Could not resolve account '$ServiceAccount' to a SID. Verify the account exists and the format is 'domain\user'. Error: $_"
            Return

        }

        # Marshal the SID to unmanaged memory
        $sidBytes = New-Object byte[] $sid.BinaryLength
        $sid.GetBinaryForm($sidBytes, 0)
        $sidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($sidBytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($sidBytes, 0, $sidPtr, $sidBytes.Length)

        Try {

            $objAttr         = New-Object LsaApi+LSA_OBJECT_ATTRIBUTES
            $objAttr.Length  = [System.Runtime.InteropServices.Marshal]::SizeOf($objAttr)
            $emptyName       = New-Object LsaApi+LSA_UNICODE_STRING
            $policyHandle    = [IntPtr]::Zero

            # POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES = 0x00000010 | 0x00000800
            $status = [LsaApi]::LsaOpenPolicy([ref]$emptyName, [ref]$objAttr, 0x00000810, [ref]$policyHandle)
            If ($status -ne 0) {

                $winErr = [LsaApi]::LsaNtStatusToWinError($status)
                Write-Error "LsaOpenPolicy failed. Win32 error: $winErr"
                Return

            }

            Try {

                $right               = New-Object LsaApi+LSA_UNICODE_STRING
                $right.Buffer        = 'SeServiceLogonRight'
                $right.Length        = [uint16]($right.Buffer.Length * 2)
                $right.MaximumLength = [uint16]($right.Buffer.Length * 2 + 2)

                $status = [LsaApi]::LsaAddAccountRights($policyHandle, $sidPtr, @($right), 1)
                If ($status -ne 0) {

                    $winErr = [LsaApi]::LsaNtStatusToWinError($status)
                    Write-Error "LsaAddAccountRights failed. Win32 error: $winErr"
                    Return

                }

                Write-Verbose "Successfully granted 'Log on as a service' to '$ServiceAccount' (SID: $($sid.Value))."

            }

            Finally {

                [void]([LsaApi]::LsaClose($policyHandle))

            }

        }

        Finally {

            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($sidPtr)

        }

    } # End function Grant-LogOnAsService

    Write-Verbose "Granting 'Log on as a service' right to '$AccountName'..."

    Try {

        Grant-LogOnAsService -ServiceAccount $AccountName

    }

    Catch {

        Write-Warning "Failed to grant 'Log on as a service' to '$AccountName'. $($_.Exception.Message)"

    }

}

# Check current service logon account before making changes
Write-Verbose "Checking current certkit-agent service logon account..."

Try {

    $CurrentSvc = Get-CimInstance Win32_Service -Filter "Name='certkit-agent'" -ErrorAction Stop

}

Catch {

    Write-Warning "Failed to query certkit-agent service configuration. $($_.Exception.Message)"
    $CurrentSvc = $null

}

If ($CurrentSvc -and $CurrentSvc.StartName -ieq $AccountName) {

    Write-Verbose "certkit-agent is already configured to run as '$AccountName'. Skipping service update."
    Write-Verbose "Configuration complete. '$AccountName' is already configured to run the certkit-agent service."

}

Else {

    # Update service credentials
    Write-Verbose "Stopping certkit-agent service..."

    Try {

        Stop-Service -Name certkit-agent -Force -ErrorAction Stop
        Write-Verbose 'certkit-agent service stopped successfully.'

    }

    Catch {

        Write-Warning "Failed to stop the certkit-agent service. $($_.Exception.Message)"

    }

    # Configure certkit-agent to run under the service account
    If ($IsGmsa) {

        Write-Verbose "Configuring certkit-agent to run as gMSA '$AccountName'..."
        [void](& sc.exe config certkit-agent obj= $AccountName)

    }

    Else {

        $Credentials = Get-Credential -UserName $AccountName -Message "Enter the service account password for certkit-agent."

        $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credentials.Password)
        $plainPw = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

        Write-Verbose "Configuring certkit-agent to run as '$AccountName'..."
        [void](& sc.exe config certkit-agent obj= $AccountName password= $plainPw)

        $plainPw = $null

    }

    If ($LASTEXITCODE -ne 0) {

        Write-Warning "sc.exe config returned exit code $LASTEXITCODE. Service credentials may not have been updated."

    }

    # Validate service configuration
    Try {

        $Svc = Get-CimInstance Win32_Service -Filter "Name='certkit-agent'"

        If ($Svc.StartName -ne $AccountName) {

            Write-Warning "Service StartName is '$($Svc.StartName)' but expected '$AccountName'. Credentials may not have applied."

        }

        Else {

            Write-Verbose "Service StartName successfully updated to '$AccountName'."

        }

    }

    Catch {

        Write-Warning "Failed to validate service configuration. $($_.Exception.Message)"

    }

    Write-Verbose "Starting certkit-agent service..."

    Try {

        Start-Service -Name certkit-agent -ErrorAction Stop
        Write-Verbose "certkit-agent service started successfully."

    }

    Catch {

        Write-Warning "Failed to start the certkit-agent service. $($_.Exception.Message)"

    }

    Write-Output "Configuration complete. '$AccountName' is configured to run the certkit-agent service."

}

# SIG # Begin signature block
# MIIk7AYJKoZIhvcNAQcCoIIk3TCCJNkCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCQzMzeuGy0N8/a
# RkvmX0s4gMCFzrIxDy+Fy7Ze2k7206CCH6YwggWNMIIEdaADAgECAhAOmxiO+dAt
# 5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNV
# BAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBa
# Fw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2Vy
# dCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lD
# ZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoC
# ggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3E
# MB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKy
# unWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsF
# xl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU1
# 5zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJB
# MtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObUR
# WBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6
# nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxB
# YKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5S
# UUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+x
# q4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIB
# NjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwP
# TzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMC
# AYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0
# aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENB
# LmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0Nc
# Vec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnov
# Lbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65Zy
# oUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFW
# juyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPF
# mCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9z
# twGpn1eqXijiuZQwggW0MIIDnKADAgECAhAOxitIKuZQm69NGxw+uiH/MA0GCSqG
# SIb3DQEBDAUAMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2RlIFNpZ25pbmcgUlNB
# NDA5NiBTSEEzODQgMjAyMSBDQTEwHhcNMjYwNTE2MDAwMDAwWhcNMjcwODE3MjM1
# OTU5WjCBhjELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNV
# BAcTDU1pc3Npb24gVmllam8xJDAiBgNVBAoTG1JpY2hhcmQgTS4gSGlja3MgQ29u
# c3VsdGluZzEkMCIGA1UEAxMbUmljaGFyZCBNLiBIaWNrcyBDb25zdWx0aW5nMFkw
# EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOooTPiege6mCA4AriPO+Xh3mymiiZ+3k
# kn31uJifB2ojzzfY7VkAVKhgj+rcVBnofnj2b8OhvAJ4YaQ2Iwuc6aOCAgMwggH/
# MB8GA1UdIwQYMBaAFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB0GA1UdDgQWBBQJvGhl
# Ahwi6UKROatrFKBmPLmd5TA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcGCCsGAQUF
# BwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwDgYDVR0PAQH/BAQDAgeA
# MBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BRoE+GTWh0dHA6
# Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENvZGVTaWduaW5n
# UlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8vY3JsNC5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JTQTQwOTZTSEEz
# ODQyMDIxQ0ExLmNybDCBlAYIKwYBBQUHAQEEgYcwgYQwJAYIKwYBBQUHMAGGGGh0
# dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBcBggrBgEFBQcwAoZQaHR0cDovL2NhY2Vy
# dHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZEc0Q29kZVNpZ25pbmdSU0E0
# MDk2U0hBMzg0MjAyMUNBMS5jcnQwCQYDVR0TBAIwADANBgkqhkiG9w0BAQwFAAOC
# AgEAbaKnnRcJAMHjuWSc2PG/QhJ0jj4hQVwJIbddYDJNxPmD0cxuuorSiR9gX2nl
# ajqNI9N7Kl+FB3oheRTGh/wp4JgZMpCq0qS0zGJ/N6Js+HmVtbkFaPyYxJMXbIWq
# p9zKkoXtSXkpR6nGZnzYkn3EBcRlu4R6hIJHzM/C2PUztH/Hd4fGIryyD69iHvKx
# zotYdlHHY6+X1ACaQnuCz3TLxs3/CDKhPUXesKcISnXHmm4uCwyVdtGyl7wPuZVk
# +rfCIOeWn+XG5J7L8xwhXCPSJ5fKJ5m8/H5cICLR0I7hI4SUiybE1nG5CZ1hKhbW
# abSfNer1dHH/vSYi80YGXCej/88vZeCGQ9/rrjugsg0yN7WCPqNKjEMTYGWkrt37
# lp4cJqULS+alUbL6x1HBdoBStDE2CFmPivL7cCCtnudqCA6b3XB416/FlRo8t4Lw
# Dc2ty+RDKirWM84Zj3ANTVs5fi43rxClBQwngGdqi5TjriKHGTkEKYRIFTViy6Ie
# JDIboOkCFJU5vM7Curvh4rQnw+aM4CyjwnDwnzwcKQVZC3Iy1T4h/FvmpSgu5ouM
# wjdzaR3cSh4OPDRrfBl1YIOoZEOHcshCaHDC46t8+UyAf70BMlrB7Nj84ORTuKTi
# IlU062VzGeREc1KHJqp/S3/NtArpVUVQEgibRxQ99KJCOV8wggawMIIEmKADAgEC
# AhAIrUCyYNKcTJ9ezam9k67ZMA0GCSqGSIb3DQEBDAUAMGIxCzAJBgNVBAYTAlVT
# MRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5j
# b20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yMTA0Mjkw
# MDAwMDBaFw0zNjA0MjgyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5E
# aWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBDb2Rl
# IFNpZ25pbmcgUlNBNDA5NiBTSEEzODQgMjAyMSBDQTEwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDVtC9C0CiteLdd1TlZG7GIQvUzjOs9gZdwxbvEhSYw
# n6SOaNhc9es0JAfhS0/TeEP0F9ce2vnS1WcaUk8OoVf8iJnBkcyBAz5NcCRks43i
# CH00fUyAVxJrQ5qZ8sU7H/Lvy0daE6ZMswEgJfMQ04uy+wjwiuCdCcBlp/qYgEk1
# hz1RGeiQIXhFLqGfLOEYwhrMxe6TSXBCMo/7xuoc82VokaJNTIIRSFJo3hC9FFdd
# 6BgTZcV/sk+FLEikVoQ11vkunKoAFdE3/hoGlMJ8yOobMubKwvSnowMOdKWvObar
# YBLj6Na59zHh3K3kGKDYwSNHR7OhD26jq22YBoMbt2pnLdK9RBqSEIGPsDsJ18eb
# MlrC/2pgVItJwZPt4bRc4G/rJvmM1bL5OBDm6s6R9b7T+2+TYTRcvJNFKIM2KmYo
# X7BzzosmJQayg9Rc9hUZTO1i4F4z8ujo7AqnsAMrkbI2eb73rQgedaZlzLvjSFDz
# d5Ea/ttQokbIYViY9XwCFjyDKK05huzUtw1T0PhH5nUwjewwk3YUpltLXXRhTT8S
# kXbev1jLchApQfDVxW0mdmgRQRNYmtwmKwH0iU1Z23jPgUo+QEdfyYFQc4UQIyFZ
# YIpkVMHMIRroOBl8ZhzNeDhFMJlP/2NPTLuqDQhTQXxYPUez+rbsjDIJAsxsPAxW
# EQIDAQABo4IBWTCCAVUwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUaDfg
# 67Y7+F8Rhvv+YXsIiGX0TkIwHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4c
# D08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMDMHcGCCsGAQUF
# BwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEG
# CCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5k
# aWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAcBgNVHSAEFTAT
# MAcGBWeBDAEDMAgGBmeBDAEEATANBgkqhkiG9w0BAQwFAAOCAgEAOiNEPY0Idu6P
# vDqZ01bgAhql+Eg08yy25nRm95RysQDKr2wwJxMSnpBEn0v9nqN8JtU3vDpdSG2V
# 1T9J9Ce7FoFFUP2cvbaF4HZ+N3HLIvdaqpDP9ZNq4+sg0dVQeYiaiorBtr2hSBh+
# 3NiAGhEZGM1hmYFW9snjdufE5BtfQ/g+lP92OT2e1JnPSt0o618moZVYSNUa/tcn
# P/2Q0XaG3RywYFzzDaju4ImhvTnhOE7abrs2nfvlIVNaw8rpavGiPttDuDPITzgU
# kpn13c5UbdldAhQfQDN8A+KVssIhdXNSy0bYxDQcoqVLjc1vdjcshT8azibpGL6Q
# B7BDf5WIIIJw8MzK7/0pNVwfiThV9zeKiwmhywvpMRr/LhlcOXHhvpynCgbWJme3
# kuZOX956rEnPLqR0kq3bPKSchh/jwVYbKyP/j7XqiHtwa+aguv06P0WmxOgWkVKL
# QcBIhEuWTatEQOON8BUozu3xGFYHKi8QxAwIZDwzj64ojDzLj4gLDb879M4ee47v
# tevLt/B3E+bnKD+sEq6lLyJsQfmCXBVmzGwOysWGw/YmMwwHS6DTBwJqakAwSEs0
# qFEgu60bhQjiWQ1tygVQK+pKHJ6l/aCnHwZ05/LWUpD9r4VIIflXO7ScA+2GRfS0
# YW6/aOImYIbqyK+p/pQd52MbOoZWeE4wgga0MIIEnKADAgECAhANx6xXBf8hmS5A
# QyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAx
# MTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5j
# LjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNB
# NDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK
# AoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcy
# bEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzT
# qpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftB
# dsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3
# mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6z
# MUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS
# 5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBB
# BnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqL
# XvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7ps
# NOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeE
# WvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCC
# AVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv
# 1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/
# BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggr
# BgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVo
# dHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0
# LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20v
# RGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjAL
# BglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvI
# tTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/m
# S83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgX
# f9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liy
# rukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+
# Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2
# ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipD
# oq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6Ax
# nJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAl
# Z66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1
# MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZs
# q8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDAN
# BgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
# IEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5n
# IFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkw
# MzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVz
# cG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBG
# rC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwB
# SOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/
# 4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3
# K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROU
# INDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3
# w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46Yce
# NA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d
# 2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8x
# ymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+
# AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2b
# Qhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNV
# HRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSME
# GDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0l
# AQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzAB
# hhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9j
# YWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGlu
# Z1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRw
# Oi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBp
# bmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIw
# CwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESe
# Y0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FU
# FqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7Y
# MTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0zi
# TN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/
# QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlq
# AcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3
# Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roan
# cJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/
# ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7
# IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdC
# vHlshtjdNXOCIUjsarfNZzGCBJwwggSYAgEBMH0waTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IENvZGUgU2lnbmluZyBSU0E0MDk2IFNIQTM4NCAyMDIxIENBMQIQDsYrSCrm
# UJuvTRscProh/zANBglghkgBZQMEAgEFAKCBhDAYBgorBgEEAYI3AgEMMQowCKAC
# gAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsx
# DjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCA+VZIc2aX06MZJPNmZhNPZ
# 85S+z/OFEYjm4plB+qcDDjALBgcqhkjOPQIBBQAERzBFAiEAq08Zmi44kNGMQ06c
# 178F4wJzmMnogVbXQIRdnnEh/rUCIFAYzuxvZQv9777KOheIol6Lx+g3WqEDa/nW
# LHYcYsqXoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEBMH0waTELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2Vy
# dCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENB
# MQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBpMBgGCSqGSIb3DQEJ
# AzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDYxNTIxNDgzOVowLwYJ
# KoZIhvcNAQkEMSIEIKy7gVs38Hq5CQFUEMrIh6iZc9ArwDe/K73/ia3DIbJUMA0G
# CSqGSIb3DQEBAQUABIICACF4OSilykZM0c0u3miQaorou7h6iWXnwYEwN0EcyKpB
# bC7QXuPARXTUYi+zmtUXTsmfJ41k5xrZBlcjiQcRjfj7MZ2zRlbwak3f2UHQTefb
# WJ27ZvA9VfdxJJjBFxu0gsbU14+9/dQHyVVblJLd0JldhsLYvQ8gFHRtvORccFX3
# 3GQXkP4B+CUht9i+IpF8afDzMR9VDYPZDkq1JBwwKeQzX3OLxk9cjZuzrYhdvwfs
# 7FfiNr2dier7Cnt+Lx1kaMnJR4Dz5nckBtVSMCEWl5qQfOpXkAajVJB5510otLI/
# buGqk33Cn9egjAlf1lJEMuv0hRzpDMhWd8sZJbkHIcU1qiNeo6EraLfQxCDQfID8
# VYL+ugi/k6nzIXB3F/8TNkGWNYnvPp7Ru9ushOvZlkofnySoHE6Dz5u7ioFVpXF6
# kYV4Xk8mNedJtj4710qBWioGNP/uRl/u1VP0ZFyY91ONsCj2QX7xdlSpL1UvbHdh
# brstnlcDrOPjcs4NorbEk4bUvJuWfvUrAJrSKRMoyBHZvBm16qGf3u+6KUC7pui/
# gwYdFou8eMHMdDNFypBmxn6JoniWq3YaDW7ykofrF+71MrTRMiri1vJ46r5wrdU0
# o1IljUHNnVmlpsvXUM2JPL/0hMkDsinHGZPZmPq/smwXUh5G8KkUEfqggOH32QD/
# SIG # End signature block
