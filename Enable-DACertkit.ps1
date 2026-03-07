<#PSScriptInfo

.VERSION 1.0

.GUID 4310a537-3e45-4f07-bbd9-be8bd0e0c6eb

.AUTHOR Richard Hicks

.COMPANYNAME Richard M. Hicks Consulting, Inc.

.COPYRIGHT Copyright (C) 2026 Richard M. Hicks Consulting, Inc. All Rights Reserved.

.LICENSE Licensed under the MIT License. See LICENSE file in the project root for full license information.

.LICENSEURI https://github.com/richardhicks/directaccess/blob/master/LICENSE

.PROJECTURI https://github.com/richardhicks/directaccess/blob/master/Enable-DACertKit.ps1

.TAGS Microsoft, DirectAccess, CertKit, Certificate, TLS, SSL, IPHTTPS, IPv6

.EXTERNALMODULEDEPENDENCIES GroupPolicy, RemoteAccess

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
    Version:        1.0
    Creation Date:  March 7, 2026
    Last Updated:   March 7, 2026
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

Write-Verbose "Retrieving DirectAccess configuration..."

# Get RemoteAccess configuration to identify associated GPOs
Try {

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

                Set-GPPermission -Guid $Gpo.Id -Domain $DomainPart -TargetName $Sam -TargetType $TargetType -PermissionLevel GpoEditDeleteModifySecurity -ErrorAction Stop | Out-Null
                Write-Information "Granted 'Edit settings, delete, modify security' to '$Sam' on GPO '$GpoName'." -InformationAction Continue

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

                [LsaApi]::LsaClose($policyHandle) | Out-Null

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
    & sc.exe config certkit-agent obj= $AccountName

}

Else {

    $Credentials = Get-Credential -UserName $AccountName -Message "Enter the service account password for certkit-agent."

    $BSTR = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credentials.Password)
    $plainPw = [Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($BSTR)

    Write-Verbose "Configuring certkit-agent to run as '$AccountName'..."
    & sc.exe config certkit-agent obj= $AccountName password= $plainPw

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

Write-Information "Configuration complete. '$AccountName' is configured to run the certkit-agent service." -InformationAction Continue

# SIG # Begin signature block
# MIIf2wYJKoZIhvcNAQcCoIIfzDCCH8gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCDnElcFVv6DMcsK
# e/ej3ajVSKeBEzn+uYcdEtA89B8SiaCCGpkwggNZMIIC36ADAgECAhAPuKdAuRWN
# A1FDvFnZ8EApMAoGCCqGSM49BAMDMGExCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xIDAeBgNVBAMT
# F0RpZ2lDZXJ0IEdsb2JhbCBSb290IEczMB4XDTIxMDQyOTAwMDAwMFoXDTM2MDQy
# ODIzNTk1OVowZDELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMu
# MTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9iYWwgRzMgQ29kZSBTaWduaW5nIEVDQyBT
# SEEzODQgMjAyMSBDQTEwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS7tKwnpUgNolNf
# jy6BPi9TdrgIlKKaqoqLmLWx8PwqFbu5s6UiL/1qwL3iVWhga5c0wWZTcSP8GtXK
# IA8CQKKjSlpGo5FTK5XyA+mrptOHdi/nZJ+eNVH8w2M1eHbk+HejggFXMIIBUzAS
# BgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSbX7A2up0GrhknvcCgIsCLizh3
# 7TAfBgNVHSMEGDAWgBSz20ik+aHF2K42QcwRY2liKbxLxjAOBgNVHQ8BAf8EBAMC
# AYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwdgYIKwYBBQUHAQEEajBoMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQAYIKwYBBQUHMAKGNGh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbFJvb3RHMy5jcnQw
# QgYDVR0fBDswOTA3oDWgM4YxaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0R2xvYmFsUm9vdEczLmNybDAcBgNVHSAEFTATMAcGBWeBDAEDMAgGBmeBDAEE
# ATAKBggqhkjOPQQDAwNoADBlAjB4vUmVZXEB0EZXaGUOaKncNgjB7v3UjttAZT8N
# /5Ovwq5jhqN+y7SRWnjsBwNnB3wCMQDnnx/xB1usNMY4vLWlUM7m6jh+PnmQ5KRb
# qwIN6Af8VqZait2zULLd8vpmdJ7QFmMwggP+MIIDhKADAgECAhANSjTahpCPwBMs
# vIE3k68kMAoGCCqGSM49BAMDMGQxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdp
# Q2VydCwgSW5jLjE8MDoGA1UEAxMzRGlnaUNlcnQgR2xvYmFsIEczIENvZGUgU2ln
# bmluZyBFQ0MgU0hBMzg0IDIwMjEgQ0ExMB4XDTI0MTIwNjAwMDAwMFoXDTI3MTIy
# NDIzNTk1OVowgYYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYw
# FAYDVQQHEw1NaXNzaW9uIFZpZWpvMSQwIgYDVQQKExtSaWNoYXJkIE0uIEhpY2tz
# IENvbnN1bHRpbmcxJDAiBgNVBAMTG1JpY2hhcmQgTS4gSGlja3MgQ29uc3VsdGlu
# ZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFCbtcqpc7vGGM4hVM79U+7f0tKz
# o8BAGMJ/0E7JUwKJfyMJj9jsCNpp61+mBNdTwirEm/K0Vz02vak0Ftcb/3yjggHz
# MIIB7zAfBgNVHSMEGDAWgBSbX7A2up0GrhknvcCgIsCLizh37TAdBgNVHQ4EFgQU
# KIMkVkfISNUyQJ7bwvLm9sCIkxgwPgYDVR0gBDcwNTAzBgZngQwBBAEwKTAnBggr
# BgEFBQcCARYbaHR0cDovL3d3dy5kaWdpY2VydC5jb20vQ1BTMA4GA1UdDwEB/wQE
# AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzCBqwYDVR0fBIGjMIGgME6gTKBKhkho
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWdu
# aW5nRUNDU0hBMzg0MjAyMUNBMS5jcmwwTqBMoEqGSGh0dHA6Ly9jcmw0LmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEdsb2JhbEczQ29kZVNpZ25pbmdFQ0NTSEEzODQyMDIx
# Q0ExLmNybDCBjgYIKwYBBQUHAQEEgYEwfzAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMFcGCCsGAQUFBzAChktodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRHbG9iYWxHM0NvZGVTaWduaW5nRUNDU0hBMzg0MjAy
# MUNBMS5jcnQwCQYDVR0TBAIwADAKBggqhkjOPQQDAwNoADBlAjBMOsBb80qx6E6S
# 2lnnHafuyY2paoDtPjcfddKaB1HKnAy7WLaEVc78xAC84iW3l6ECMQDhOPD5JHtw
# YxEH6DxVDle5pLKfuyQHiY1i0I9PrSn1plPUeZDTnYKmms1P66nBvCkwggWNMIIE
# daADAgECAhAOmxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNV
# BAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdp
# Y2VydC5jb20xJDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAe
# Fw0yMjA4MDEwMDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# ITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcN
# AQEBBQADggIPADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC
# 4SmnPVirdprNrnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWl
# fr6fqVcWWVVyr2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1j
# KS3O7F5OyJP4IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dP
# pzDZVu7Ke13jrclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3
# pC4FfYj1gj4QkXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJ
# pMLmqaBn3aQnvKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aa
# dMreSx7nDmOu5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXD
# j/chsrIRt7t/8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB
# 4Q+UDCEdslQpJYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ
# 33xMdT9j7CFfxCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amy
# HeUbAgMBAAGjggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC
# 0nFdZEzfLmc/57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823I
# DzAOBgNVHQ8BAf8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhho
# dHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNl
# cnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYD
# VR0fBD4wPDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0
# QXNzdXJlZElEUm9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcN
# AQEMBQADggEBAHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxpp
# VCLtpIh3bb0aFPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6
# mouyXtTP0UNEm0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPH
# h6jSTEAZNUZqaVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCN
# NWAcAgPLILCsWKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg6
# 2fC2h5b9W9FcrBjDTZ9ztwGpn1eqXijiuZQwgga0MIIEnKADAgECAhANx6xXBf8h
# mS5AQyIMOkmGMA0GCSqGSIb3DQEBCwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQK
# EwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNV
# BAMTGERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0z
# ODAxMTQyMzU5NTlaMGkxCzAJBgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwg
# SW5jLjFBMD8GA1UEAxM4RGlnaUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcg
# UlNBNDA5NiBTSEEyNTYgMjAyNSBDQTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAw
# ggIKAoICAQC0eDHTCphBcr48RsAcrHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGP
# NRcybEKq+RuwOnPhof6pvF4uGjwjqNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1I
# pYzTqpyFQ/4Bt0mAxAHeHYNnQxqXmRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5A
# vftBdsOECS1UkxBvMgEdgkFiDNYiOTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDRe
# b6e3mmdglTcaarps0wjUjsZvkgFkriK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBUR
# Jg6zMUjZa/zbCclF83bRVFLeGkuAhHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/ao
# fEnS5xLrfxnGpTXiUOeSLsJygoLPp66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQ
# skBBBnGy3tW/AMOMCZIVNSaz7BX8VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJ
# lIqLXvJWnY0v5ydPpOjL6s36czwzsucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev
# +7psNOdgJMoiwOrUG2ZdSoQbU2rMkpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6B
# aaeEWvjJSjNm2qA+sdFUeEY0qVjPKOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IB
# XTCCAVkwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQ
# VvYv1Ensy04wHwYDVR0jBBgwFoAU7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0P
# AQH/BAQDAgGGMBMGA1UdJQQMMAoGCCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAC
# hjVodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNydDBDBgNVHR8EPDA6MDigNqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEE
# AjALBglghkgBhv1sBwEwDQYJKoZIhvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9
# vgvItTSmf83Qh8WIGjB/T8ObXAZz8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwb
# SI/mS83afsl3YTj+IQhQE7jU/kXjjytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTL
# xLgXf9r5nWMQwr8Myb9rEVKChHyfpzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD
# 8liyrukZ2iA/wdG2th9y1IsA0QF8dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVk
# o43+Cdmu4y81hjajV/gxdEkMx1NKU4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRa
# Ps+2ykgcGV00TYr2Lr3ty9qIijanrUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8
# cipDoq7+qNNjqFzeGxcytL5TTLL4ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRz
# W6AxnJll38F0cuJG7uEBYTptMSbhdhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KC
# LPAlZ66RzIg9sC+NJpud/v4+7RWsWCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau
# 1j/1MIDpMPx0LckTetiSuEtQvLsNz3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPS
# xyZsq8WhbaM2tszWkPZPubdcMIIG7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0
# aDANBgkqhkiG9w0BAQsFADBpMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNl
# cnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1w
# aW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2
# MDkwMzIzNTk1OVowYzELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
# bmMuMTswOQYDVQQDEzJEaWdpQ2VydCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAg
# UmVzcG9uZGVyIDIwMjUgMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
# ANBGrC0Sxp7Q6q5gVrMrV7pvUf+GcAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdw
# bHwBSOeLpvPnZ8ZN+vo8dE2/pPvOx/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9
# RJt/4QhguSssp3qome7MrxVyfQO9sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrU
# cCV3K3E0zz09ldQ//nBZZREr4h/GI6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iU
# SROUINDT98oksouTMYFOnHoRh6+86Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw
# 2YD3w6ySSSu+3qU8DD+nigNJFmt6LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe4
# 6YceNA0LfNsnqcnpJeItK/DhKbPxTTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seA
# O+6d2sC26/PQPdP51ho1zBp+xUIZkpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSH
# lq8xymLnjCbSLZ49kPmk8iyyizNDIXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6
# EaJ+AliL7ojTdS5PWPsWeupWs7NpChUk555K096V1hE0yZIXe+giAwW00aHzrDch
# Ic2bQhpp0IoKRR7YufAkprxMiXAJQ1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAM
# BgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNV
# HSMEGDAWgBTvb1NK6eQGfHrK4pBW9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYD
# VR0lAQH/BAwwCgYIKwYBBQUHAwgwgZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUF
# BzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6
# Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFt
# cGluZ1JTQTQwOTZTSEEyNTYyMDI1Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5o
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3Rh
# bXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwB
# BAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezR
# CESeY0ByIfjk9iJP2zWLpQq1b4URGnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0
# k8FUFqNh+tshgb4O6Lgjg8K8elC4+oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFO
# tj7YMTmqPO9mzskgiC3QYIUP2S3HQvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLW
# U0ziTN6R3ygQBHMUBaB5bdrPbF6MRYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2n
# HkX/QqvXnNb+YkDFkxUGtMTaiLR9wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIF
# eRlqAcuEVT0cKsb+zJNEsuEB7O7/cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqR
# hoS3Y50OHgaY7T/lwd6UArb+BOVAkg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7
# roancJIFcbojBcxlRcGG0LIhp6GvReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47Cdx
# VRd/ndUlQ05oxYy2zRWVFjF7mcr4C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/r
# ptb7IRE2lskKPIJgbaP5t2nGj/ULLi49xTcBZU8atufk+EMF/cWuiC7POGT75qaL
# 6vdCvHlshtjdNXOCIUjsarfNZzGCBJgwggSUAgEBMHgwZDELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTwwOgYDVQQDEzNEaWdpQ2VydCBHbG9i
# YWwgRzMgQ29kZSBTaWduaW5nIEVDQyBTSEEzODQgMjAyMSBDQTECEA1KNNqGkI/A
# Eyy8gTeTryQwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGCNwIBDDEKMAigAoAA
# oQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4w
# DAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgfaUAPSjDSennxKnXa/oiOfJ0
# 68q33a6dFpF4TJAKDL0wCwYHKoZIzj0CAQUABEgwRgIhAKGdTFpT32dJYX/sSx1X
# 9W/fM4W4N9P82OMxSZABAaKtAiEA9k5IOIjwZ40MMM7b1609/IoeLK54Zx9Bc+Q5
# deQFp82hggMmMIIDIgYJKoZIhvcNAQkGMYIDEzCCAw8CAQEwfTBpMQswCQYDVQQG
# EwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0
# IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0Ex
# AhAKgO8YS43xBYLRxHanlXRoMA0GCWCGSAFlAwQCAQUAoGkwGAYJKoZIhvcNAQkD
# MQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMjYwMzA3MjE1NTA0WjAvBgkq
# hkiG9w0BCQQxIgQgqHS5bvi4iskC9TashcO06FDX6rJEgcPEGmPXL4esMGIwDQYJ
# KoZIhvcNAQEBBQAEggIAOwLu/LH/gP5n8wfo+quB8ZjKJt+nQADMf8TbccRYVtZO
# FxJz4Ok76C+GBZ023o2oXQWkezvAgpONY/KQuRlDF5TxMTG9u/65nhoH3d0NAaku
# O8lUC45rf7XrMFWATMnvyrkMAVkkfviiR9e+w9jnpbcWvCyZ0tqHS2/ypv1yO7Pq
# d1hUT1imYWmIEeoPFlt+Y9K6zGon689kgVlZRwo0bINddRUP3rHu3Qn2R/7bB8Vn
# iEpaTXkWwGuBY4Y7E6kOH/WW4SKqH7GF7V69viiuvckKcXFNc7xV2ME/YyqYWby3
# cnzaibGBjwFLIhHaGnWg9fZ1gfRwrgWp8Zx4oNMFaqOS3mMzeFgrdnxnj3FfkZst
# ttT3IfHcywdGrrilG8F3uswNOm7V+ToOf1JIusutHL0ZLN1Bvg35NfAKy23rVR46
# NT7QHh9M2ynCAg2C/QicFHbbi+WBuYTWyH9i10M2EppiNLnO2w2h/deMvwjjLkrt
# ZutSR1RHLC9J5lss/vPDLHtLVBHRCHT5al1uwJcPzMzA5JOzSYYS6/dFmyFANXPr
# 45ggk+7ifDgXz1CzqLlkjVxGHyAm5euWzPaDMZGCsRxh+tj58s59i0xB8LkwY6y1
# KXff/GSWhtQjbDZr0E61zE4x41RwZHoHXayiXyFt2pvQSr/jqI4JfXUccVI9ixo=
# SIG # End signature block
