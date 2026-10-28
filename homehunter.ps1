<#
.SYNOPSIS
    Read-only scanner for hidden clues and reusable credentials in all local
    Windows user profiles. Windows PowerShell 5.1 compatible.
#>
#requires -Version 5.1
[CmdletBinding()]
param(
    [ValidateRange(1,512)]
    [int]$MaxFileSizeMB = 5,
    [string]$OutputFile,
    [Alias('Home')][string[]]$HomePath = @(),
    [switch]$OnlySpecifiedHomes,
    [switch]$Quiet,
    [switch]$NoColor,
    [Alias('h','?')][switch]$Help
)

$script:Version = '1.0.0'
$script:ExitCode = 0
$script:MaxBytes = [int64]$MaxFileSizeMB * 1MB
$script:LogPath = $null
$script:SeenHomes = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$script:Reported = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$script:SeenFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
$script:ReportAdded = $false
$script:Homes = New-Object 'System.Collections.Generic.List[string]'
$script:Counts = @{
    HomesDiscovered=0; HomesScanned=0; Files=0; Text=0; Hidden=0
    High=0; Key=0; Large=0; Binary=0; Denied=0
}

function Show-Usage {
@"
homehunter.ps1 v$($script:Version)

Usage: .\homehunter.ps1 [options]

  -MaxFileSizeMB N       Maximum text file size (default 5, maximum 512)
  -OutputFile FILE       Append findings to a restricted text log
  -Home PATH             Add explicit profile/home paths
  -OnlySpecifiedHomes    Scan only paths supplied with -Home
  -Quiet                 Suppress progress; findings and summary remain
  -NoColor               Reserved for output parity
  -Help                   Show help

No options are required. Run elevated for the widest coverage.
"@
}
if ($Help) { Show-Usage; exit 0 }
if ($OnlySpecifiedHomes -and $HomePath.Count -eq 0) { Write-Error '-OnlySpecifiedHomes requires -Home PATH'; exit 2 }

function Initialize-Output {
    if (-not $OutputFile) { return }
    try {
        New-Item -ItemType File -Path $OutputFile -Force -ErrorAction Stop | Out-Null
        $script:LogPath = (Resolve-Path -LiteralPath $OutputFile -ErrorAction Stop).Path
        try {
            $me = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            $acl = Get-Acl -LiteralPath $script:LogPath
            $acl.SetAccessRuleProtection($true,$false)
            @($acl.Access) | ForEach-Object { [void]$acl.RemoveAccessRule($_) }
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($me,'FullControl','Allow')
            $acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $script:LogPath -AclObject $acl
        } catch {}
    } catch {
        Write-Error "Cannot create output file: $OutputFile"
        exit 2
    }
}

function Write-Line([string]$Line) {
    Write-Host $Line
    if ($script:LogPath) { Add-Content -LiteralPath $script:LogPath -Value $Line -Encoding UTF8 }
}
function Write-ProgressLine([string]$Line) { if (-not $Quiet) { Write-Host "[*] $Line" } }
function Clean-Path([string]$Path) { return ($Path -replace "[`r`n`t]",' ') }
function Report-Once([string]$Tag,[string]$Path,[string]$Detail='') {
    $script:ReportAdded = $false
    $clean = Clean-Path $Path
    $key = "$Tag|$clean|$Detail"
    if (-not $script:Reported.Add($key)) { return }
    $script:ReportAdded = $true
    if ($Detail) { Write-Line "[$Tag] $clean  $Detail" } else { Write-Line "[$Tag] $clean" }
}

function Add-Home([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    $expanded = [Environment]::ExpandEnvironmentVariables($Path.Trim('"'))
    try {
        if (-not [IO.Path]::IsPathRooted($expanded)) { return }
        if (-not (Test-Path -LiteralPath $expanded -PathType Container)) { return }
        $full = [IO.Path]::GetFullPath($expanded).TrimEnd('\','/')
        if ($script:SeenHomes.Add($full)) { $script:Homes.Add($full) }
    } catch {}
}

function Discover-Homes {
    if (-not $OnlySpecifiedHomes) {
        try {
            Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' -ErrorAction Stop | ForEach-Object {
                try { Add-Home (Get-ItemProperty -LiteralPath $_.PSPath -Name ProfileImagePath -ErrorAction Stop).ProfileImagePath } catch {}
            }
        } catch {}
        if ($env:SystemDrive) {
            $usersRoot = Join-Path $env:SystemDrive 'Users'
            try { Get-ChildItem -LiteralPath $usersRoot -Force -Directory -ErrorAction Stop | ForEach-Object { Add-Home $_.FullName } } catch {}
        }
        if ($env:USERPROFILE) { Add-Home $env:USERPROFILE }
        if ($env:HOME) { Add-Home $env:HOME }
    }
    foreach ($h in $HomePath) { Add-Home $h }
    $script:Counts.HomesDiscovered = $script:Homes.Count
}

$script:OfficeExt = New-Object 'System.Collections.Generic.HashSet[string]' ([string[]]@(
    '.doc','.docx','.docm','.dot','.dotx','.dotm','.xls','.xlsx','.xlsm','.xlsb','.xlt','.xltx','.xltm',
    '.ppt','.pptx','.pptm','.pot','.potx','.potm','.pps','.ppsx','.ppsm','.vsd','.vsdx','.pub','.mdb','.accdb'
),[System.StringComparer]::OrdinalIgnoreCase)
$script:SqlExt = New-Object 'System.Collections.Generic.HashSet[string]' ([string[]]@(
    '.sql','.ddl','.dump','.psql','.pgsql','.plsql','.tsql','.mdf','.ndf','.ldf','.db','.sqlite','.sqlite3'
),[System.StringComparer]::OrdinalIgnoreCase)
$script:ArchiveExt = New-Object 'System.Collections.Generic.HashSet[string]' ([string[]]@(
    '.zip','.7z','.rar','.tar','.tgz','.gz','.bz2','.xz','.cab'
),[System.StringComparer]::OrdinalIgnoreCase)
$script:InterestExt = New-Object 'System.Collections.Generic.HashSet[string]' ([string[]]@(
    '.kdbx','.kdb','.psafe3','.opvault','.1pif','.1pux','.pfx','.p12','.jks','.keystore','.keytab','.ppk',
    '.pcap','.pcapng','.pem','.key','.priv','.pvk'
),[System.StringComparer]::OrdinalIgnoreCase)

function Get-TypeTag([string]$Extension) {
    if ($script:OfficeExt.Contains($Extension)) { return 'OFFICE' }
    if ($script:SqlExt.Contains($Extension)) { return 'SQL' }
    if ($script:ArchiveExt.Contains($Extension)) { return 'ARCHIVE' }
    if ($script:InterestExt.Contains($Extension)) { return 'INTEREST' }
    return ''
}

$script:Patterns = @(
    @{Label='password_assign'; Regex=[regex]::new('(?i)(password|passwd|passphrase|pwd|secret)["'']?\s*[:=]\s*["'']?[^\s"''#<>{}]{3,}')},
    @{Label='prefixed_password'; Regex=[regex]::new('(?i)(db|database|mysql|postgres|mssql|sql|sa|oracle|redis|ldap|smtp|smb|ftp|admin|root|svc|service)[_-]?(password|passwd|passphrase|pwd|pass)["'']?\s*[:=]')},
    @{Label='connection_string'; Regex=[regex]::new('(?i)(server|host|data[ _-]?source)\s*=.{1,200}(password|pwd)\s*=')},
    @{Label='jdbc_password'; Regex=[regex]::new('(?i)jdbc:[a-z]+://.*(password|pwd)=')},
    @{Label='uri_credentials'; Regex=[regex]::new('(?i)[a-z][a-z0-9+.-]*://[^\s/:@]+:[^\s/@]+@')},
    @{Label='gpp_cpassword'; Regex=[regex]::new('(?i)cpassword\s*=\s*"[A-Za-z0-9+/=]{20,}"')},
    @{Label='autologon_password'; Regex=[regex]::new('(?i)(DefaultPassword|AltDefaultPassword)["'']?\s*[:=]')},
    @{Label='command_password'; Regex=[regex]::new('(?i)(sshpass|sqlcmd|mysql|psql|mongosh|smbclient|xfreerdp|rdesktop|plink|curl|wget|7z|zip).*(-p|-P|-pw|--password|/p:)\s*[= ]\s*\S{2,}')},
    @{Label='powershell_password'; Regex=[regex]::new('(?i)-(Password|Pass|AccountPassword|NewPassword|DefaultPassword)\s+["''][^"'']{3,}["'']')},
    @{Label='pgpassword'; Regex=[regex]::new('(?i)PGPASSWORD\s*=\s*[^\s#]{3,}')},
    @{Label='mysql_pwd'; Regex=[regex]::new('(?i)MYSQL_PWD\s*=\s*[^\s#]{3,}')},
    @{Label='netrc_password'; Regex=[regex]::new('(?i)(machine\s+\S+\s+)?(login|user)\s+\S+\s+password\s+\S{2,}')},
    @{Label='ntlm_hash'; Regex=[regex]::new('(?i)[\w.@$-]+:\d+:[A-Fa-f0-9]{32}:[A-Fa-f0-9]{32}:')},
    @{Label='password_hash'; Regex=[regex]::new('\$(1|2a|2b|2y|5|6|y|argon2(?:id|i|d))\$\S{10,}')},
    @{Label='kerberos_hash'; Regex=[regex]::new('\$krb5(?:tgs|asrep)\$\S{10,}')},
    @{Label='wifi_psk'; Regex=[regex]::new('(?i)(psk|pre-shared-key|wpa-passphrase)\s*[:=]\s*[^\s#]{8,}')}
)
$script:Placeholder = [regex]::new('(?i)(example|sample|dummy|changeme|replace[_-]?me|your[_-]?(password|secret)|password[_-]?here|redacted|masked|\*\*\*|integrated\s*security\s*=\s*(true|sspi)|trusted_connection\s*=\s*(yes|true))')
$script:KeyMarker = [regex]::new('-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----|PuTTY-User-Key-File-')

function Read-TextSmart([string]$Path,[byte[]]$Bytes) {
    try {
        if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) { return [Text.Encoding]::Unicode.GetString($Bytes,2,$Bytes.Length-2) }
        if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) { return [Text.Encoding]::BigEndianUnicode.GetString($Bytes,2,$Bytes.Length-2) }
        if ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) { return [Text.Encoding]::UTF8.GetString($Bytes,3,$Bytes.Length-3) }
        $sample = [Math]::Min($Bytes.Length,8192)
        for ($i=0;$i -lt $sample;$i++) { if ($Bytes[$i] -eq 0) { return $null } }
        $strict = New-Object Text.UTF8Encoding($false,$true)
        try { return $strict.GetString($Bytes) } catch { return [Text.Encoding]::Default.GetString($Bytes) }
    } catch { return $null }
}

function Scan-Text([string]$Path,[string]$Content) {
    $lines = $Content -split "`r?`n"
    for ($i=0;$i -lt $lines.Count;$i++) {
        $line = $lines[$i]
        if ($line.Length -gt 16384) { continue }
        if ($script:KeyMarker.IsMatch($line)) {
            $preview = $line.Substring(0,[Math]::Min(180,$line.Length))
            Report-Once 'KEY' "${Path}:$($i+1)" "private_key  $preview"
            $script:Counts.Key++; $script:ExitCode=1
        }
        if ($script:Placeholder.IsMatch($line)) { continue }
        foreach ($p in $script:Patterns) {
            if ($p.Regex.IsMatch($line)) {
                $preview = $line.Substring(0,[Math]::Min(180,$line.Length))
                $before = $script:Reported.Count
                Report-Once 'HIGH' "${Path}:$($i+1)" "$($p.Label)  $preview"
                if ($script:Reported.Count -gt $before) { $script:Counts.High++; $script:ExitCode=1 }
                break
            }
        }
    }
}

function Handle-File([IO.FileInfo]$File) {
    if (-not $script:SeenFiles.Add($File.FullName)) { return }
    $script:Counts.Files++
    $path = $File.FullName
    if ($script:LogPath -and $path.Equals($script:LogPath,[StringComparison]::OrdinalIgnoreCase)) { return }
    if (($File.Attributes -band [IO.FileAttributes]::Hidden) -ne 0 -or ($File.Attributes -band [IO.FileAttributes]::System) -ne 0) {
        Report-Once 'HIDDEN' $path; if ($script:ReportAdded) { $script:Counts.Hidden++ }
    }
    $tag = Get-TypeTag $File.Extension
    if ($tag) { Report-Once $tag $path }
    try { $size=$File.Length } catch { Report-Once 'DENIED' $path 'cannot stat'; if ($script:ReportAdded) { $script:Counts.Denied++ }; return }
    if ($size -gt $script:MaxBytes) {
        Report-Once "SKIP:size>${MaxFileSizeMB}MB" $path (('{0:N1} MB' -f ($size/1MB)))
        if ($script:ReportAdded) { $script:Counts.Large++ }; return
    }
    if ($size -eq 0) { return }
    try { $bytes=[IO.File]::ReadAllBytes($path) } catch { Report-Once 'DENIED' $path; if ($script:ReportAdded) { $script:Counts.Denied++ }; return }
    $text=Read-TextSmart $path $bytes
    if ($null -eq $text) { Report-Once 'SKIP:binary' $path; if ($script:ReportAdded) { $script:Counts.Binary++ }; return }
    $script:Counts.Text++
    Scan-Text $path $text
}

function Scan-Home([string]$Root) {
    Write-ProgressLine "Scanning $Root"
    try { $rootItem=Get-Item -LiteralPath $Root -Force -ErrorAction Stop } catch { Report-Once 'DENIED' $Root; if ($script:ReportAdded) { $script:Counts.Denied++ }; return }
    $script:Counts.HomesScanned++
    $stack=New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($rootItem.FullName)
    while ($stack.Count -gt 0) {
        $dir=$stack.Pop()
        try { $items=@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop) } catch { Report-Once 'DENIED' $dir; if ($script:ReportAdded) { $script:Counts.Denied++ }; continue }
        foreach ($item in $items) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            $hidden=(($item.Attributes -band [IO.FileAttributes]::Hidden) -ne 0 -or ($item.Attributes -band [IO.FileAttributes]::System) -ne 0)
            if ($item.PSIsContainer) {
                if ($hidden) { Report-Once 'HIDDEN' $item.FullName; if ($script:ReportAdded) { $script:Counts.Hidden++ } }
                $stack.Push($item.FullName)
            } else { Handle-File $item }
        }
    }
}

function Write-Summary {
    Write-Line ''
    Write-Line '=== HomeHunter Summary ==='
    Write-Line ("Homes discovered:       {0}" -f $script:Counts.HomesDiscovered)
    Write-Line ("Homes scanned:          {0}" -f $script:Counts.HomesScanned)
    Write-Line ("Files enumerated:       {0}" -f $script:Counts.Files)
    Write-Line ("Text files scanned:     {0}" -f $script:Counts.Text)
    Write-Line ("Hidden items:           {0}" -f $script:Counts.Hidden)
    Write-Line ("Credential findings:    {0}" -f $script:Counts.High)
    Write-Line ("Private-key findings:   {0}" -f $script:Counts.Key)
    Write-Line ("Large files skipped:    {0}" -f $script:Counts.Large)
    Write-Line ("Binary files skipped:   {0}" -f $script:Counts.Binary)
    Write-Line ("Permission denied:      {0}" -f $script:Counts.Denied)
}

Initialize-Output
Discover-Homes
if ($script:Homes.Count -eq 0) { Write-Error 'No home directories discovered'; exit 2 }
Write-ProgressLine "Discovered $($script:Homes.Count) home directories; text limit $MaxFileSizeMB MiB"
foreach ($h in $script:Homes) { Scan-Home $h }
Write-Summary
exit $script:ExitCode
