[cmdletbinding(SupportsShouldProcess)]

Param(
    [Parameter(HelpMessage = "Enter the path to the Direct Access database folder relative to the remote computer")]
    [Alias("path")]
    [string]$SourcePath = "C:\Windows\DirectAccess\DB",
    [Parameter(Mandatory, HelpMessage = "Enter the target folder path to move the Direct Access database  relative to the remote computer")]
    [alias("destination")]
    [string]$TargetPath,
    [Parameter(HelpMessage = "Enter the name of the remote RRAS server.", ValueFromPipeline, ValueFromPipelineByPropertyName)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Computername = $env:computername,
    [switch]$Passthru,
    [Parameter(HelpMessage = "Enter an optional credential in the form domain\username or machine\username")]
    [PSCredential]$Credential,
    [ValidateSet('Default', 'Basic', 'Credssp', 'Digest', 'Kerberos', 'Negotiate', 'NegotiateWithImplicitCredential')]
    [ValidateNotNullorEmpty()]
    [string]$Authentication = "default",
    [switch]$UseSSL

)
Begin {
    Write-Verbose "Starting $($myinvocation.mycommand)"
    #display some meta information for troubleshooting
    Write-Verbose "PowerShell version: $($psversiontable.psversion)"
    Write-Verbose "Operating System: $((Get-Ciminstance -class win32_operatingsystem -property caption).caption)"

    $sb = {
        [cmdletbinding()]
        Param(
            [ValidateScript( {
                    #write a custom error message if the database file isn't in the source path
                    if (Test-Path "$_\RaAcctDb.mdf") {
                        return $True
                    }
                    else {
                        Throw "The path ($_) does not appear to contain the RaAcctDB.mdf database."
                    }
                })]
            [string]$SourcePath,
            [string]$TargetPath,
            [bool]$Passthru
        )

        $VerbosePreference = $using:verbosepreference
        $whatifpreference = $using:whatifpreference
        Write-Verbose "SourcePath = $SourcePath"
        Write-Verbose "TargetPath = $TargetPath"
        Write-Verbose "WhatIf = $whatifpreference"
        Write-verbose "Verbose = $VerbosePreference"

        If (-Not (Test-Path $TargetPath)) {
            Write-Verbose "Creating target $TargetPath"
            Try {
                New-Item -ItemType Directory -Force -Path $TargetPath -ErrorAction stop
            }
            Catch {
                Write-Verbose "Failed to create target folder $targetPath"
                Throw $_
                #this should terminate the command if the target folder can't be created.
                #we will force a bailout just in case this doesn't terminate.
                return
            }
        }
        Write-Verbose "Copying Access Control from $SourcePath to $TargetPath"
        if ($pscmdlet.ShouldProcess($TargetPath, "Copy Access Control")) {

            Try {
                Write-Verbose "Get ACL"
                $Acl = Get-Acl -Path $SourcePath -ErrorAction stop
                Write-Verbose "Set ACL"
                Set-Acl -Path $TargetPath -aclobject $Acl -ErrorAction stop
            }
            Catch {
                Write-Verbose "Failed to copy ACL from $SourcePath to $TargetPath"
                Throw $_
                #bail out if PowerShell doesn't terminate the pipeline
                return
            }
        } #WhatIf copying ACL

        Write-Verbose "Stopping the RamgmtSvc"
        Try {
            Get-Service RaMgmtSvc -ErrorAction Stop | Stop-Service -Force -ErrorAction Stop
        }
        Catch {
            Write-Verbose "Failed to stop the RaMgmtSvc"
            Throw $_
            #bail out if PowerShell doesn't terminate the pipeline
            return
        }

        Write-Verbose "Altering database"
        $sqlConn = 'server=\\.\pipe\Microsoft##WID\tsql\query;Database=RaAcctDb;Trusted_Connection=True;'
        $conn = New-Object System.Data.SQLClient.SQLConnection($sqlConn)
        Write-Verbose "Opening WID connection"
        if ($pscmdlet.ShouldProcess("RaAcctDB", "Open Connection")) {
            $conn.Open()
        }
        $cmd = $conn.CreateCommand()
        $cmdText = "USE master;ALTER DATABASE RaAcctDb SET SINGLE_USER WITH ROLLBACK IMMEDIATE;EXEC sp_detach_db @dbname = N'RaAcctDb';"
        Write-Verbose $cmdText
        $cmd.CommandText = $cmdText
        $cmd | Out-String | Write-Verbose
        if ($pscmdlet.ShouldProcess("RaAcctDB", "ALTER DATABASE")) {
            Write-Verbose "Executing"
            $rdrDetach = $cmd.ExecuteReader()
            Write-Verbose "Detached"
            $rdrDetach | Out-String | Write-Verbose
        }
        Write-Verbose "Closing WID connection"
        if ($conn.State -eq "Open") {
            $conn.Close()
        }

        Write-Verbose "Moving database files from $sourcePath to $TargetPath"
        $mdf = Join-Path -path $SourcePath -ChildPath "RaAcctDb.mdf"
        $ldf = Join-Path -path $SourcePath -ChildPath "RaAcctDb_log.ldf"
        Move-Item -Path $mdf -Destination $TargetPath
        Move-Item -Path $ldf -Destination $TargetPath

        Write-Verbose "Creating new database"
        $sqlConn = 'server=\\.\pipe\Microsoft##WID\tsql\query;Database=;Trusted_Connection=True;'
        $conn = New-Object System.Data.SQLClient.SQLConnection($sqlConn)
        Write-Verbose "Opening WID connection"
        if ($pscmdlet.ShouldProcess("New DB", "Open Connection")) {
            $conn.Open()
        }

        $cmd = $conn.CreateCommand()
        $targetmdf = Join-Path -Path $TargetPath -ChildPath RaAcctDb.mdf
        $targetldf = Join-Path -Path $TargetPath -ChildPath RaAcctDb_log.ldf
        $cmdText = "USE master CREATE DATABASE RaAcctDb ON (FILENAME = '$targetmdf'),(FILENAME = '$targetldf') FOR ATTACH;USE [master] ALTER DATABASE [RaAcctDb] SET READ_WRITE WITH NO_WAIT;"
        Write-Verbose $cmdText
        $cmd.CommandText = $cmdText
        if ($pscmdlet.ShouldProcess($targetmdf, "CREATE DATABASE")) {
            Write-Verbose "Executing"
            $rdrAttach = $cmd.ExecuteReader()
            Write-Verbose "Attached"
            $rdrAttach | Out-String | Write-Verbose
        }
        Write-Verbose "Closing WID connection"
        if ($conn.State -eq "Open") {
            $conn.Close()
        }
        Write-Verbose "Starting the RaMgmtSvc"
        Try {
            Get-Service RaMgmtSvc -ErrorAction stop | Start-Service -ErrorAction stop
        }
        Catch {
            Write-Verbose "Failed to start RaMgmtSvc"
            Throw $_
        }

        #manage README.txt file
        if ($SourcePath -eq "C:\Windows\DirectAccess\DB") {
            #create a readme.txt file in the default location if files are being moved.
            $txt = @"

The RaAcctDB database and log files have been relocated to $TargetPath

Moved by $env:USERDOMAIN\$env:USERNAME at $(Get-Date)

"@

            Set-Content -Path C:\Windows\DirectAccess\DB\Readme.txt -Value $txt

        }
        elseif ($TargetPath -eq "C:\Windows\DirectAccess\DB" -AND (Test-Path -path "C:\Windows\DirectAccess\DB\readme.txt") ) {
            #if the destination is the default location and the readme file exists, delete the file.
            Remove-Item -Path "C:\Windows\DirectAccess\DB\readme.txt"
        }

        if ($Passthru) {
            Get-ChildItem -Path $TargetPath
        }
    } #close scriptblock

    #define a set of parameter values to splat to Invoke-Command
    $icmParams = @{
        Computername     = ""
        Scriptblock      = $sb
        HideComputername = $True
        Authentication   = $Authentication
        ArgumentList     = @($SourcePath, $TargetPath, $Passthru)
        ErrorAction      = "Stop"
    }

    if ($pscredential.username) {
        Write-Verbose "Adding an alternate credential for $($pscredential.username)"
        $icmParams.Add("Credential", $PSCredential)
    }
    if ($UseSSL) {
        Write-Verbose "Using SSL"
        $icmParams.Add("UseSSL", $True)
    }
    Write-Verbose "Using $Authentication authentication."

} #begin

Process {

    foreach ($computer in $computername) {

        Write-Verbose "Querying $($computer.toUpper())"
        $icmParams.Computername = $computer
        $icmParams | Out-String | Write-verbose
        Try {
            #display result without the runspace ID
            Invoke-Command @icmParams
        }
        Catch {
            Throw $_
        }
    } #foreach computer

} #process

End {
    Write-Verbose "Ending $($myinvocation.MyCommand)"
} #end
