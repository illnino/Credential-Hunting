@echo off
setlocal DisableDelayedExpansion

:: ============================================================================
::  credshunter.bat  v2.4.0-bat
::  CMD port of credshunter.ps1 for hosts without PowerShell.
::  Read-only. Never modifies the system.
::
::  LIMITATIONS vs the PowerShell version:
::    - No .NET regex: content scan uses findstr (basic wildcards only).
::    - No capture-group extraction: findings show the whole line, not just
::      the secret value.
::    - No encoding detection: UTF-16 files are usually skipped/garbled.
::    - No hash-set dedup: duplicate hits across stages may appear.
::    - No progress bar; verbose output is throttled with echo.
::
::  Usage:
::    credshunter.bat -Path C:\Users -OutputFile loot.txt
::    credshunter.bat -Path C:\ -SkipSystem -MaxFileSizeMB 10
:: ============================================================================

set "VERSION=2.4.0-bat"

set "PATHS="
set "EXCLUDEPATHS="
set "OUTPUTFILE="
set /a MAXSIZEMB=5
set "ALL="
set "QUIET="
set "NOCOLOR="
set "SKIPSYSTEM="
set "NOSTAGE1="
set "NOSTAGE2="
set "NOSTAGE3="
set "NOSTAGE4="
set "NOSTAGE5="
set "NOSTAGE6="
set "INCLUDEDATA="
set "NODEFAULTEXCLUDE="
set "NOSIZELIMIT="

:ParseArgs
if "%~1"=="" goto ArgsDone
set "arg=%~1"
set "val=%~2"
if /I "%arg%"=="-Path"        set "PATHS=%PATHS%;%val%" & shift & shift & goto ParseArgs
if /I "%arg%"=="/Path"        set "PATHS=%PATHS%;%val%" & shift & shift & goto ParseArgs
if /I "%arg%"=="-ExcludePath" set "EXCLUDEPATHS=%EXCLUDEPATHS%;%val%" & shift & shift & goto ParseArgs
if /I "%arg%"=="/ExcludePath" set "EXCLUDEPATHS=%EXCLUDEPATHS%;%val%" & shift & shift & goto ParseArgs
if /I "%arg%"=="-OutputFile"  set "OUTPUTFILE=%val%" & shift & shift & goto ParseArgs
if /I "%arg%"=="/OutputFile"  set "OUTPUTFILE=%val%" & shift & shift & goto ParseArgs
if /I "%arg%"=="-MaxFileSizeMB" set /a MAXSIZEMB=%val% & shift & shift & goto ParseArgs
if /I "%arg%"=="/MaxFileSizeMB" set /a MAXSIZEMB=%val% & shift & shift & goto ParseArgs
if /I "%arg%"=="-All"          set "ALL=1" & shift & goto ParseArgs
if /I "%arg%"=="/All"          set "ALL=1" & shift & goto ParseArgs
if /I "%arg%"=="-Quiet"        set "QUIET=1" & shift & goto ParseArgs
if /I "%arg%"=="/Quiet"        set "QUIET=1" & shift & goto ParseArgs
if /I "%arg%"=="-NoColor"      set "NOCOLOR=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoColor"      set "NOCOLOR=1" & shift & goto ParseArgs
if /I "%arg%"=="-SkipSystem"   set "SKIPSYSTEM=1" & set "NOSTAGE1=1" & shift & goto ParseArgs
if /I "%arg%"=="/SkipSystem"   set "SKIPSYSTEM=1" & set "NOSTAGE1=1" & shift & goto ParseArgs
if /I "%arg%"=="-NoStage1"    set "NOSTAGE1=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoStage1"    set "NOSTAGE1=1" & shift & goto ParseArgs
if /I "%arg%"=="-NoStage2"    set "NOSTAGE2=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoStage2"    set "NOSTAGE2=1" & shift & goto ParseArgs
if /I "%arg%"=="-NoStage3"    set "NOSTAGE3=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoStage3"    set "NOSTAGE3=1" & shift & goto ParseArgs
if /I "%arg%"=="-NoStage4"    set "NOSTAGE4=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoStage4"    set "NOSTAGE4=1" & shift & goto ParseArgs
if /I "%arg%"=="-NoStage5"    set "NOSTAGE5=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoStage5"    set "NOSTAGE5=1" & shift & goto ParseArgs
if /I "%arg%"=="-NoStage6"    set "NOSTAGE6=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoStage6"    set "NOSTAGE6=1" & shift & goto ParseArgs
if /I "%arg%"=="-NoGit"       set "NOSTAGE6=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoGit"       set "NOSTAGE6=1" & shift & goto ParseArgs
if /I "%arg%"=="-IncludeData" set "INCLUDEDATA=1" & shift & goto ParseArgs
if /I "%arg%"=="/IncludeData" set "INCLUDEDATA=1" & shift & goto ParseArgs
if /I "%arg%"=="-NoDefaultExclude" set "NODEFAULTEXCLUDE=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoDefaultExclude" set "NODEFAULTEXCLUDE=1" & shift & goto ParseArgs
if /I "%arg%"=="-NoSizeLimit" set "NOSIZELIMIT=1" & shift & goto ParseArgs
if /I "%arg%"=="/NoSizeLimit" set "NOSIZELIMIT=1" & shift & goto ParseArgs
if /I "%arg%"=="-Help"        goto ShowUsage
if /I "%arg%"=="/Help"        goto ShowUsage
if /I "%arg%"=="-h"           goto ShowUsage
if /I "%arg%"=="/h"           goto ShowUsage
if /I "%arg%"=="-?"           goto ShowUsage
if /I "%arg%"=="/?"           goto ShowUsage
shift
goto ParseArgs

:ShowUsage
echo credshunter v%VERSION% - reusable-credential discovery (read-only, CMD)
echo.
echo Usage: credshunter.bat -Path ^<dir^> [options]
echo.
echo   -Path ^<dir^>          Directories to scan (stages 2-6)
echo   -ExcludePath ^<dir^>   Directories to skip (stages 2-6)
echo   -NoDefaultExclude    Don't skip built-in system/vendor dirs
echo   -All                 Stage 5 scans every readable file
echo   -IncludeData         Also scan large SQL/CSV/data files
echo   -MaxFileSizeMB ^<n^>   Skip files larger than n MB (default 5)
echo   -NoSizeLimit         Disable the file-size cap
echo   -OutputFile ^<file^>   Append a findings log
echo   -SkipSystem          Skip stage 1 (OS checks)
echo   -NoStage1..6         Skip an individual stage
echo   -NoGit               Same as -NoStage6 ^(alias^)
echo   -Quiet               Reduce status noise
echo   -NoColor             Strip colour codes
echo   -Help                Show this help
echo.
echo Examples:
echo   credshunter.bat -Path C:\ -OutputFile loot.txt
echo   credshunter.bat -Path C:\Users,C:\inetpub -SkipSystem
goto :EOF

:ArgsDone
if not defined PATHS goto ShowUsage
setlocal EnableDelayedExpansion

set "CR="
set "CG="
set "CY="
set "CB="
set "CM="
set "CC="
set "CW="
set "CD="
set "CNC="
if not defined NOCOLOR (
    for /F %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"
    set "CR=!ESC![1;31m"
    set "CG=!ESC![1;32m"
    set "CY=!ESC![1;33m"
    set "CB=!ESC![1;34m"
    set "CM=!ESC![1;35m"
    set "CC=!ESC![1;36m"
    set "CW=!ESC![1;37m"
    set "CD=!ESC![2m"
    set "CNC=!ESC![0m"
)

set "TMPDIR=%TEMP%\credshunter_%RANDOM%"
mkdir "%TMPDIR%" 2>nul
set "FILELIST=%TMPDIR%\allfiles.txt"
set "PATTERNS=%TMPDIR%\patterns.txt"
set "KEYPATTERNS=%TMPDIR%\keypatterns.txt"
set "DEDUP=%TMPDIR%\dedup.txt"
set "HIGH=%TMPDIR%\high.txt"
set "KEY=%TMPDIR%\key.txt"
set "INTEREST=%TMPDIR%\interest.txt"
set "NAME=%TMPDIR%\name.txt"
set "GIT=%TMPDIR%\git.txt"
set "CHECKED=%TMPDIR%\checked.txt"
set "SKIPPED=%TMPDIR%\skipped.txt"
set "GUAR=%TMPDIR%\guaranteed.txt"

echo. > "%DEDUP%"

set /a MAXBYTES=%MAXSIZEMB% * 1048576
if defined NOSIZELIMIT set /a MAXBYTES=536870912

(
echo password
echo passwd
echo passphrase
echo pwd
echo cpassword
echo DefaultPassword
echo AltDefaultPassword
echo auth_pass
echo requirepass
echo rootpw
echo bindpw
echo PSK
echo rocommunity
echo rwcommunity
echo com2sec
echo ProxyPassword
echo Password=
echo Passwd=
echo Pwd=
echo PGPASSWORD
echo MYSQL_PWD
echo sshpass
echo --password
echo -password
echo /password:
echo /pass:
echo /p:
echo -pw
echo -pass
echo -a 
echo --pw
echo db_password
echo db_pass
echo db_pwd
echo connection string
echo jdbc:
echo ://
echo -----BEGIN RSA PRIVATE KEY-----
echo -----BEGIN DSA PRIVATE KEY-----
echo -----BEGIN EC PRIVATE KEY-----
echo -----BEGIN OPENSSH PRIVATE KEY-----
echo -----BEGIN PRIVATE KEY-----
echo -----BEGIN ENCRYPTED PRIVATE KEY-----
echo -----BEGIN PGP PRIVATE KEY BLOCK-----
echo PuTTY-User-Key-File-
echo net use
echo net user
echo runas /savecred
echo cmdkey /add
echo psexec
echo ConvertTo-SecureString
echo PSCredential
echo NetworkCredential
echo define^('DB_PASSWORD'
echo define^('DB_PASS'
echo define^('DB_PWD'
echo $password
echo $passwd
echo $pwd
echo $secret
echo htpasswd
echo .netrc
echo smb.conf
echo id_rsa
echo id_dsa
echo id_ecdsa
echo id_ed25519
echo .ppk
echo .pem
echo .pfx
echo .p12
echo .keytab
echo .kdbx
echo .kdb
echo NTLM
echo $krb5tgs$
echo $krb5asrep$
echo $DCC2$
echo $1$
echo $2a$
echo $2b$
echo $2y$
echo $5$
echo $6$
echo $y$
echo $argon2
echo M$
echo NOPASSWD
echo snmpwalk
echo mosquitto_pub
echo mosquitto_sub
echo redis-cli
echo psql 
echo mysql 
echo mongo 
echo lftp
echo nmcli
echo openssl
echo curl --user
echo wget --password
echo 7z -P
echo zip -P
echo gpg --passphrase
echo sqlcmd -P
echo schtasks /rp
echo evil-winrm
echo impacket
echo secretsdump
echo wmiexec
echo smbexec
echo psexec.py
echo freerdp
echo xfreerdp
echo rdesktop
echo plink
echo putty
echo winscp
echo filezilla
echo sitemanager.xml
echo recentservers.xml
echo tomcat-users.xml
echo credentials.xml
echo secrets.json
echo appsettings
echo web.config
echo machine.config
echo applicationHost.config
echo unattend.xml
echo autounattend.xml
echo sysprep.xml
echo sysprep.inf
echo SiteList.xml
echo SiteMgr.xml
echo administrators_authorized_keys
echo sshd_config
echo MobaXterm.ini
echo WinSCP.ini
echo rclone.conf
echo .aws\credentials
echo .kube\config
echo .docker\config.json
echo .git-credentials
echo .npmrc
echo .pypirc
echo .s3cfg
echo .pgpass
echo .my.cnf
echo my.cnf
echo krb5.conf
echo krb5cc_
) > "%PATTERNS%"

(
echo -----BEGIN RSA PRIVATE KEY-----
echo -----BEGIN DSA PRIVATE KEY-----
echo -----BEGIN EC PRIVATE KEY-----
echo -----BEGIN OPENSSH PRIVATE KEY-----
echo -----BEGIN PRIVATE KEY-----
echo -----BEGIN ENCRYPTED PRIVATE KEY-----
echo -----BEGIN PGP PRIVATE KEY BLOCK-----
echo PuTTY-User-Key-File-
) > "%KEYPATTERNS%"

set /a nGuar=0
set /a nHigh=0
set /a nKey=0
set /a nInt=0
set /a nName=0
set /a nGit=0
set /a nCheck=0
set /a nSkip=0
set /a EXITCODE=0

if not defined QUIET (
    echo.
    echo   !CC!+----------------------------------------------------------------!CNC!
    echo    !CW!reusable-credential discovery . v%VERSION% . Windows ^(CMD^)!CNC!
    echo    !CD!authorized testing only . read-only!CNC!
    echo   !CC!+----------------------------------------------------------------!CNC!
    echo.
)

if defined NOSIZELIMIT (
    if not defined QUIET echo !CY![!] Size cap disabled - every readable file will be inspected.!CNC!
) else (
    if not defined QUIET echo !CB![*] Size cap: skipping files larger than %MAXSIZEMB% MB!CNC!
)

if not defined NOSTAGE1 (
    if not defined QUIET (
        echo.
        echo   !CC!==== STAGE 1 -- OS-level credential checks ======================!CNC!
    )
    call :Stage1_AutoLogon
    call :Stage1_GPP
    call :Stage1_Unattend
    call :Stage1_PSHistory
    call :Stage1_Cmdkey
    call :Stage1_PuTTY
    call :Stage1_WinSCP
    call :Stage1_VNC
    call :Stage1_SNMP
    call :Stage1_SAM
    call :Stage1_IIS
    call :Stage1_Tasks
    call :Stage1_WiFi
    call :Stage1_McAfee
    call :Stage1_Browser
    call :Stage1_CloudCLI
    call :Stage1_SSH
    call :Stage1_RDP
    call :Stage1_RemoteMgr
    call :Stage1_WlanSvc
    call :Stage1_Autopilot
    call :Stage1_StickyNotes
    call :Stage1_IISHistory
    call :Stage1_FileZilla
    call :Stage1_OpenSSH
    call :Stage1_MobaXterm
    call :Stage1_DBClients
    call :Stage1_AppServers
    call :Stage1_DotNetSecrets
)

if not defined PATHS goto SkipFileStages
if defined NOSTAGE2 if defined NOSTAGE3 if defined NOSTAGE4 if defined NOSTAGE5 if defined NOSTAGE6 goto SkipFileStages

call :BuildExclusions

if defined NOSTAGE2 if defined NOSTAGE3 if defined NOSTAGE4 if defined NOSTAGE5 goto RunStage6
if not defined QUIET (
    echo.
    echo   !CC!==== STAGE 2-5 -- File scanning ==================================!CNC!
    echo !CB![*] Enumerating files...!CNC!
)

echo. > "%FILELIST%"
for %%P in (%PATHS%) do (
    set "thisPath=%%~P"
    if exist "!thisPath!\" (
        call :WalkDir "!thisPath!"
    ) else if exist "!thisPath!" (
        echo !thisPath! >> "%FILELIST%"
    ) else (
        if not defined QUIET echo !CY![!] Path does not exist: !thisPath!!CNC!
    )
)

if not defined NOSTAGE2 call :DoStage2
if not defined NOSTAGE3 call :DoStage3
if not defined NOSTAGE4 call :DoStage4
if not defined NOSTAGE5 call :DoStage5

:RunStage6
if not defined NOSTAGE6 (
    call :DoStage6
) else if not defined QUIET (
    echo.
    echo   !CC!==== STAGE 6 -- Git repository discovery [SKIPPED] ==============!CNC!
)

:SkipFileStages
call :WriteSummary

if exist "%TMPDIR%\" rmdir /S /Q "%TMPDIR%" 2>nul
exit /b %EXITCODE%

:Stage1_AutoLogon
if not defined QUIET echo !CB![*] Stage 1.1 - AutoLogon registry!CNC!
for %%K in ("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Winlogon") do (
    reg query %%K /v DefaultPassword 2>nul ^| findstr /I "DefaultPassword" >nul
    if !errorlevel!==0 (
        for /f "tokens=2,*" %%a in ('reg query %%K /v DefaultPassword 2^>nul ^| findstr /I "DefaultPassword"') do (
            call :IsFP "%%b"
            if errorlevel 1 call :AddHigh "registry/autologon_defaultpassword" "%%~K" "0" "DefaultPassword = %%b"
        )
    )
    reg query %%K /v AltDefaultPassword 2>nul ^| findstr /I "AltDefaultPassword" >nul
    if !errorlevel!==0 (
        for /f "tokens=2,*" %%a in ('reg query %%K /v AltDefaultPassword 2^>nul ^| findstr /I "AltDefaultPassword"') do (
            call :IsFP "%%b"
            if errorlevel 1 call :AddHigh "registry/autologon_altdefaultpassword" "%%~K" "0" "AltDefaultPassword = %%b"
        )
    )
)
call :AddChecked "autologon_registry" "HKLM\Winlogon"
goto :EOF

:Stage1_GPP
if not defined QUIET echo !CB![*] Stage 1.2 - Group Policy Preferences cpassword!CNC!
for %%R in ("%SystemRoot%\SYSVOL" "%ProgramData%\Microsoft\Group Policy\History" "%SystemRoot%\System32\GroupPolicy") do (
    if exist "%%~R\" (
        call :AddChecked "gpp_root" "%%~R"
        for %%X in (Groups Services ScheduledTasks DataSources Drives Printers) do (
            if exist "%%~R\%%X.xml" (
                call :AddChecked "gpp_xml" "%%~R\%%X.xml"
                findstr /I /M /C:"cpassword=" "%%~R\%%X.xml" >nul 2>&1
                if !errorlevel!==0 (
                    call :AddHigh "gpp/cpassword" "%%~R\%%X.xml" "0" "cpassword found"
                )
            )
            for /r "%%~R" %%F in (%%X.xml) do (
                call :AddChecked "gpp_xml" "%%~F"
                findstr /I /M /C:"cpassword=" "%%~F" >nul 2>&1
                if !errorlevel!==0 (
                    call :AddHigh "gpp/cpassword" "%%~F" "0" "cpassword found"
                )
            )
        )
    )
)
goto :EOF

:Stage1_Unattend
if not defined QUIET echo !CB![*] Stage 1.3 - Unattended install / sysprep files!CNC!
for %%F in (
    "%SystemRoot%\Panther\Unattend.xml"
    "%SystemRoot%\Panther\Unattended.xml"
    "%SystemRoot%\Panther\Unattend\Unattend.xml"
    "%SystemRoot%\System32\Sysprep\unattend.xml"
    "%SystemRoot%\System32\Sysprep\sysprep.xml"
    "%SystemDrive%\unattend.xml"
    "%SystemDrive%\autounattend.xml"
    "%SystemDrive%\sysprep.inf"
    "%SystemRoot%\debug\NetSetup.log"
) do (
    if exist "%%~F" (
        call :AddChecked "unattend" "%%~F"
        findstr /I /M /C:"Password" "%%~F" >nul 2>&1
        if !errorlevel!==0 call :AddHigh "unattend/password" "%%~F" "0" "Password tag found"
    )
)
goto :EOF

:Stage1_PSHistory
if not defined QUIET echo !CB![*] Stage 1.4 - PowerShell history!CNC!
for %%H in (
    "%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
) do (
    if exist "%%~H" call :ScanFile "%%~H" "powershell_history"
)
for /d %%U in ("%SystemDrive%\Users\*") do (
    if exist "%%~U\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" (
        call :ScanFile "%%~U\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" "powershell_history"
    )
)
goto :EOF

:Stage1_Cmdkey
if not defined QUIET echo !CB![*] Stage 1.5 - Windows credential vault / cmdkey!CNC!
cmdkey /list > "%TMPDIR%\cmdkey.txt" 2>nul
if exist "%TMPDIR%\cmdkey.txt" (
    findstr /I /M /C:"Target:" "%TMPDIR%\cmdkey.txt" >nul 2>&1
    if !errorlevel!==0 (
        call :AddHigh "cmdkey/saved_credential" "cmdkey:list" "0" "Saved credentials exist"
    )
)
for %%D in (
    "%USERPROFILE%\AppData\Roaming\Microsoft\Credentials"
    "%USERPROFILE%\AppData\Local\Microsoft\Credentials"
    "%USERPROFILE%\AppData\Local\Microsoft\Vault"
    "%USERPROFILE%\AppData\Roaming\Microsoft\Vault"
) do (
    if exist "%%~D\" (
        call :AddChecked "vault_dir" "%%~D"
        for /f %%F in ('dir /B /A:-D "%%~D" 2^>nul') do (
            call :AddInterest "windows_vault_file" "%%~D\%%F"
        )
    )
)
goto :EOF

:Stage1_PuTTY
if not defined QUIET echo !CB![*] Stage 1.6 - PuTTY / KiTTY saved sessions!CNC!
for %%R in ("HKCU\Software\SimonTatham\PuTTY\Sessions" "HKCU\Software\9bis.com\KiTTY\Sessions") do (
    reg query %%R 2>nul ^| findstr /I /V "HKEY_" ^| findstr /R "." >nul
    if !errorlevel!==0 (
        call :AddChecked "putty_sessions" "%%~R"
        call :AddInterest "putty_session_review" "%%~R"
    )
)
goto :EOF

:Stage1_WinSCP
if not defined QUIET echo !CB![*] Stage 1.7 - WinSCP saved sessions!CNC!
reg query "HKCU\Software\Martin Prikryl\WinSCP 2\Sessions" 2>nul | findstr /I /V "HKEY_" | findstr /R "." >nul
if !errorlevel!==0 (
    call :AddChecked "winscp_sessions" "HKCU\WinSCP 2\Sessions"
    call :AddInterest "winscp_session_review" "HKCU\WinSCP 2\Sessions"
)
for %%D in ("%APPDATA%" "%LOCALAPPDATA%" "%USERPROFILE%") do (
    if exist "%%~D\" (
        for /r "%%~D" %%F in (WinSCP.ini) do (
            call :AddInterest "winscp_ini" "%%~F"
            call :ScanFile "%%~F" "winscp_ini"
        )
    )
)
goto :EOF

:Stage1_VNC
if not defined QUIET echo !CB![*] Stage 1.8 - VNC registry!CNC!
for %%K in (
    "HKLM\SOFTWARE\TightVNC\Server"
    "HKLM\SOFTWARE\WOW6432Node\TightVNC\Server"
    "HKLM\SOFTWARE\RealVNC\WinVNC4"
    "HKLM\SOFTWARE\WOW6432Node\RealVNC\WinVNC4"
    "HKLM\SOFTWARE\RealVNC\vncserver"
    "HKLM\SOFTWARE\ORL\WinVNC3"
    "HKLM\SOFTWARE\WOW6432Node\ORL\WinVNC3"
    "HKLM\SOFTWARE\TigerVNC\WinVNC4"
    "HKCU\Software\TightVNC\Server"
    "HKCU\Software\ORL\WinVNC3"
    "HKCU\Software\RealVNC\WinVNC4"
    "HKCU\Software\TigerVNC\vncserver"
) do (
    reg query %%K 2>nul ^| findstr /I "password" >nul
    if !errorlevel!==0 (
        call :AddHigh "vnc/stored_password" "%%~K" "0" "Password value in registry"
    )
    reg query %%K 2>nul ^| findstr /R "." >nul
    if !errorlevel!==0 call :AddChecked "vnc_registry" "%%~K"
)
goto :EOF

:Stage1_SNMP
if not defined QUIET echo !CB![*] Stage 1.9 - SNMP community strings!CNC!
reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" 2>nul | findstr /R "." >nul
if !errorlevel!==0 (
    call :AddChecked "snmp_communities" "HKLM\...\ValidCommunities"
    for /f "skip=2 tokens=*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities" 2^>nul') do (
        call :AddHigh "snmp/community" "HKLM\...\ValidCommunities" "0" "community = %%a"
    )
)
goto :EOF

:Stage1_SAM
if not defined QUIET echo !CB![*] Stage 1.10 - SAM/SYSTEM/SECURITY hive files!CNC!
for %%H in (
    "%SystemRoot%\System32\config\SAM"
    "%SystemRoot%\System32\config\SYSTEM"
    "%SystemRoot%\System32\config\SECURITY"
    "%SystemRoot%\repair\SAM"
    "%SystemRoot%\repair\SYSTEM"
    "%SystemRoot%\repair\SECURITY"
    "%SystemRoot%\System32\config\RegBack\SAM"
    "%SystemRoot%\System32\config\RegBack\SYSTEM"
    "%SystemRoot%\System32\config\RegBack\SECURITY"
) do (
    if exist "%%~H" (
        call :AddChecked "sam_hive" "%%~H"
        call :AddInterest "readable_hive" "%%~H"
        call :AddKey "readable_sam_hive" "%%~H" "0" "Hive readable - extract with secretsdump"
    )
)
goto :EOF

:Stage1_IIS
if not defined QUIET echo !CB![*] Stage 1.11 - IIS configs!CNC!
for %%F in (
    "%SystemRoot%\System32\inetsrv\config\applicationHost.config"
    "%SystemRoot%\System32\inetsrv\config\administration.config"
    "%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\Config\machine.config"
    "%SystemRoot%\Microsoft.NET\Framework64\v4.0.30319\Config\machine.config"
    "%SystemRoot%\Microsoft.NET\Framework\v2.0.50727\Config\machine.config"
    "%SystemRoot%\Microsoft.NET\Framework64\v2.0.50727\Config\machine.config"
) do (
    if exist "%%~F" call :ScanFile "%%~F" "iis_config"
)
if exist "%SystemDrive%\inetpub\" (
    for /r "%SystemDrive%\inetpub" %%F in (web.config) do (
        call :ScanFile "%%~F" "iis_webconfig"
    )
    for /r "%SystemDrive%\inetpub" %%F in (appsettings*.json) do (
        call :ScanFile "%%~F" "aspnet_appsettings"
    )
)
goto :EOF

:Stage1_Tasks
if not defined QUIET echo !CB![*] Stage 1.12 - Scheduled task XML!CNC!
if exist "%SystemRoot%\System32\Tasks\" (
    for /r "%SystemRoot%\System32\Tasks" %%F in (*) do (
        findstr /I /M /C:"Password" "%%~F" >nul 2>&1
        if !errorlevel!==0 call :ScanFile "%%~F" "scheduled_task"
    )
)
goto :EOF

:Stage1_WiFi
if not defined QUIET echo !CB![*] Stage 1.13 - Saved Wi-Fi profiles!CNC!
set "WIFITMP=%TMPDIR%\wifi"
mkdir "%WIFITMP%" 2>nul
netsh wlan export profile key=clear folder="%WIFITMP%" >nul 2>&1
if exist "%WIFITMP%\*.xml" (
    for %%F in ("%WIFITMP%\*.xml") do (
        findstr /I /M /C:"<keyMaterial>" "%%~F" >nul 2>&1
        if !errorlevel!==0 (
            for /f "tokens=2 delims=<>" %%a in ('findstr /I "<keyMaterial>" "%%~F"') do (
                call :IsFP "%%a"
                if errorlevel 1 call :AddHigh "wifi/key_clear" "wifi:%%~nF" "0" "SSID %%~nF: %%a"
            )
        )
    )
)
if exist "%WIFITMP%\" rmdir /S /Q "%WIFITMP%" 2>nul
goto :EOF

:Stage1_McAfee
if not defined QUIET echo !CB![*] Stage 1.14 - McAfee SiteList!CNC!
for %%F in (
    "%ProgramFiles%\McAfee\Common Framework\SiteList.xml"
    "%ProgramFiles(x86)%\McAfee\Common Framework\SiteList.xml"
    "%ALLUSERSPROFILE%\McAfee\Common Framework\SiteList.xml"
    "%ALLUSERSPROFILE%\McAfee\Common Framework\SiteMgr.xml"
) do (
    if exist "%%~F" (
        call :AddInterest "mcafee_sitelist" "%%~F"
        call :ScanFile "%%~F" "mcafee_sitelist"
    )
)
goto :EOF

:Stage1_Browser
if not defined QUIET echo !CB![*] Stage 1.15 - Browser credential databases!CNC!
for /d %%U in ("%SystemDrive%\Users\*") do (
    for %%F in (
        "%%~U\AppData\Local\Google\Chrome\User Data\Default\Login Data"
        "%%~U\AppData\Local\Microsoft\Edge\User Data\Default\Login Data"
        "%%~U\AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data"
        "%%~U\AppData\Roaming\Opera Software\Opera Stable\Login Data"
    ) do (
        if exist "%%~F" call :AddInterest "browser_credentials" "%%~F"
    )
    if exist "%%~U\AppData\Roaming\Mozilla\Firefox\Profiles\" (
        call :AddInterest "firefox_profiles" "%%~U\AppData\Roaming\Mozilla\Firefox\Profiles"
    )
)
goto :EOF

:Stage1_CloudCLI
if not defined QUIET echo !CB![*] Stage 1.16 - Cloud CLI credential stores!CNC!
for /d %%U in ("%SystemDrive%\Users\*") do (
    for %%F in (
        "%%~U\.aws\credentials"
        "%%~U\.aws\config"
        "%%~U\.azure\accessTokens.json"
        "%%~U\.azure\azureProfile.json"
        "%%~U\.kube\config"
        "%%~U\.docker\config.json"
        "%%~U\.netrc"
        "%%~U\_netrc"
        "%%~U\.git-credentials"
        "%%~U\.npmrc"
        "%%~U\.pypirc"
        "%%~U\.s3cfg"
        "%%~U\AppData\Roaming\rclone\rclone.conf"
        "%%~U\AppData\Roaming\gcloud\credentials.db"
        "%%~U\AppData\Roaming\gcloud\access_tokens.db"
        "%%~U\AppData\Roaming\gcloud\application_default_credentials.json"
        "%%~U\.config\gcloud\credentials.db"
        "%%~U\.config\gcloud\application_default_credentials.json"
    ) do (
        if exist "%%~F" (
            call :AddInterest "cloud_credential_file" "%%~F"
            call :ScanFile "%%~F" "cloud_cli"
        )
    )
)
goto :EOF

:Stage1_SSH
if not defined QUIET echo !CB![*] Stage 1.17 - SSH keys in user profiles!CNC!
for /d %%U in ("%SystemDrive%\Users\*") do (
    if exist "%%~U\.ssh\" (
        call :AddChecked "ssh_dir" "%%~U\.ssh"
        for %%F in ("%%~U\.ssh\*") do (
            call :ScanFile "%%~F" "ssh"
        )
    )
)
goto :EOF

:Stage1_RDP
if not defined QUIET echo !CB![*] Stage 1.18 - Saved RDP sessions!CNC!
reg query "HKCU\Software\Microsoft\Terminal Server Client\Servers" 2>nul | findstr /R "." >nul
if !errorlevel!==0 (
    call :AddChecked "rdp_registry" "HKCU\...\Terminal Server Client\Servers"
    call :AddInterest "rdp_session_review" "HKCU\...\Terminal Server Client\Servers"
)
reg query "HKCU\Software\Microsoft\Terminal Server Client\Default" 2>nul | findstr /R "." >nul
if !errorlevel!==0 (
    call :AddChecked "rdp_registry" "HKCU\...\Terminal Server Client\Default"
)
for %%D in ("%USERPROFILE%" "%PUBLIC%" "%SystemDrive%\Users") do (
    if exist "%%~D\" (
        for /r "%%~D" %%F in (*.rdp *.rdg) do (
            call :AddInterest "saved_rdp_file" "%%~F"
            call :ScanFile "%%~F" "rdp_file"
        )
    )
)
for %%F in ("%LOCALAPPDATA%\Microsoft\Remote Desktop Connection Manager\RDCMan.settings") do (
    if exist "%%~F" (
        call :AddInterest "rdcman_settings" "%%~F"
        call :ScanFile "%%~F" "rdcman"
    )
)
goto :EOF

:Stage1_RemoteMgr
if not defined QUIET echo !CB![*] Stage 1.19 - Remote access managers!CNC!
for %%F in (
    "%APPDATA%\mRemoteNG\confCons.xml"
    "%APPDATA%\mRemoteNG\confCons.xml.bak"
) do (
    if exist "%%~F" (
        call :AddInterest "mremoteng_session" "%%~F"
        call :ScanFile "%%~F" "mremoteng"
    )
)
for %%F in (
    "%APPDATA%\Devolutions\RemoteDesktopManager\Connections.xml"
    "%LOCALAPPDATA%\Devolutions\RemoteDesktopManager\Connections.xml"
) do (
    if exist "%%~F" (
        call :AddInterest "devolutions_rdm" "%%~F"
        call :ScanFile "%%~F" "devolutions_rdm"
    )
)
for /r "%APPDATA%" %%F in (*.rtsz *.rtsg) do (
    call :AddInterest "royal_ts_session" "%%~F"
    call :ScanFile "%%~F" "royal_ts"
)
for %%F in (
    "%APPDATA%\.purple\accounts.xml"
    "%APPDATA%\Pidgin\accounts.xml"
) do (
    if exist "%%~F" call :ScanFile "%%~F" "pidgin"
)
goto :EOF

:Stage1_WlanSvc
if not defined QUIET echo !CB![*] Stage 1.20 - Wlansvc profile XML files!CNC!
if exist "%ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces\" (
    for /r "%ProgramData%\Microsoft\Wlansvc\Profiles\Interfaces" %%F in (*.xml) do (
        call :AddInterest "wlansvc_profile_xml" "%%~F"
    )
)
goto :EOF

:Stage1_Autopilot
if not defined QUIET echo !CB![*] Stage 1.21 - Autopilot / provisioning packages!CNC!
if exist "%SystemRoot%\Provisioning\Autopilot\" (
    for %%F in ("%SystemRoot%\Provisioning\Autopilot\*.json") do (
        call :ScanFile "%%~F" "autopilot"
    )
)
goto :EOF

:Stage1_StickyNotes
if not defined QUIET echo !CB![*] Stage 1.22 - Sticky Notes!CNC!
for /d %%U in ("%SystemDrive%\Users\*") do (
    for %%F in (
        "%%~U\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
        "%%~U\AppData\Roaming\Microsoft\Sticky Notes\StickyNotes.snt"
    ) do (
        if exist "%%~F" call :AddInterest "sticky_notes" "%%~F"
    )
)
goto :EOF

:Stage1_IISHistory
if not defined QUIET echo !CB![*] Stage 1.23 - IIS config history!CNC!
if exist "%SystemDrive%\inetpub\history\" (
    for /r "%SystemDrive%\inetpub\history" %%F in (applicationHost.config) do (
        call :ScanFile "%%~F" "iis_config_history"
    )
)
goto :EOF

:Stage1_FileZilla
if not defined QUIET echo !CB![*] Stage 1.24 - FileZilla saved sites!CNC!
for %%F in (
    "%APPDATA%\FileZilla\sitemanager.xml"
    "%APPDATA%\FileZilla\recentservers.xml"
    "%APPDATA%\FileZilla\filezilla.xml"
    "%APPDATA%\FileZilla\queue.xml"
) do (
    if exist "%%~F" (
        call :AddInterest "filezilla_session" "%%~F"
        call :ScanFile "%%~F" "filezilla"
    )
)
goto :EOF

:Stage1_OpenSSH
if not defined QUIET echo !CB![*] Stage 1.25 - OpenSSH server!CNC!
if exist "%ProgramData%\ssh\" (
    call :AddChecked "openssh_server" "%ProgramData%\ssh"
    for %%F in ("%ProgramData%\ssh\*") do (
        call :ScanFile "%%~F" "openssh_server"
    )
)
goto :EOF

:Stage1_MobaXterm
if not defined QUIET echo !CB![*] Stage 1.26 - MobaXterm sessions!CNC!
if exist "%APPDATA%\MobaXterm\MobaXterm.ini" (
    call :AddInterest "mobaxterm_ini" "%APPDATA%\MobaXterm\MobaXterm.ini"
    call :ScanFile "%APPDATA%\MobaXterm\MobaXterm.ini" "mobaxterm"
)
reg query "HKCU\Software\Mobatek\MobaXterm\Sessions" 2>nul | findstr /R "." >nul
if !errorlevel!==0 (
    call :AddInterest "mobaxterm_registry" "HKCU\...\MobaXterm\Sessions"
)
goto :EOF

:Stage1_DBClients
if not defined QUIET echo !CB![*] Stage 1.27 - DB GUI clients!CNC!
for %%D in ("%APPDATA%\DBeaverData" "%APPDATA%\DBeaver") do (
    if exist "%%~D\" (
        for /r "%%~D" %%F in (*) do (
            if "%%~nxF"=="credentials-config.json" call :AddInterest "dbeaver_credentials" "%%~F"
            if "%%~nxF"=="data-sources.json" call :AddInterest "dbeaver_credentials" "%%~F"
        )
    )
)
reg query "HKCU\Software\HeidiSQL\Servers" 2>nul | findstr /R "." >nul
if !errorlevel!==0 (
    call :AddChecked "heidisql_servers" "HKCU\...\HeidiSQL\Servers"
    call :AddInterest "heidisql_server" "HKCU\...\HeidiSQL\Servers"
)
goto :EOF

:Stage1_AppServers
if not defined QUIET echo !CB![*] Stage 1.28 - App servers (Jenkins / Tomcat)!CNC!
for %%R in ("%SystemDrive%\Jenkins" "%ProgramData%\Jenkins\.jenkins" "%ProgramFiles%\Jenkins") do (
    if exist "%%~R\" (
        for %%F in ("%%~R\credentials.xml" "%%~R\secrets\master.key" "%%~R\secrets\hudson.util.Secret") do (
            if exist "%%~F" call :AddInterest "jenkins_secret" "%%~F"
        )
        if exist "%%~R\credentials.xml" call :ScanFile "%%~R\credentials.xml" "jenkins"
    )
)
for %%D in ("%ProgramFiles%\Apache Software Foundation" "%ProgramFiles(x86)%\Apache Software Foundation") do (
    if exist "%%~D\" (
        for /d %%T in ("%%~D\Tomcat*") do (
            if exist "%%~T\conf\tomcat-users.xml" (
                call :AddInterest "tomcat_users" "%%~T\conf\tomcat-users.xml"
                call :ScanFile "%%~T\conf\tomcat-users.xml" "tomcat"
            )
        )
    )
)
goto :EOF

:Stage1_DotNetSecrets
if not defined QUIET echo !CB![*] Stage 1.29 - .NET user-secrets!CNC!
if exist "%APPDATA%\Microsoft\UserSecrets\" (
    call :AddChecked "dotnet_user_secrets" "%APPDATA%\Microsoft\UserSecrets"
    for /d %%D in ("%APPDATA%\Microsoft\UserSecrets\*") do (
        if exist "%%~D\secrets.json" (
            call :AddInterest "dotnet_user_secrets" "%%~D\secrets.json"
            call :ScanFile "%%~D\secrets.json" "user_secrets"
        )
    )
)
goto :EOF

:BuildExclusions
set "EXCL_DIRS=.hg .svn .bzr CVS _darcs node_modules .npm .pnpm-store .yarn .yarn-cache .bun .venv venv env .pyenv .virtualenvs __pycache__ .mypy_cache .pytest_cache .tox .nox .ruff_cache site-packages dist-packages vendor bower_components .terraform .terragrunt-cache .gradle .m2 .ivy2 .sbt target dist build out coverage .next .nuxt obj .cache .ccache .npm-cache .composer .idea .vscode .vs .history WinSxS Installer SoftwareDistribution CrashDumps LiveKernelReports servicing AppPatch assembly Fonts Help IME Media PolicyDefinitions .Trash .Spotlight-V100 .fseventsd"
set "EXCL_PREFIXES=%SystemRoot% %ProgramFiles%\WindowsApps %LOCALAPPDATA%\Microsoft\WindowsApps %LOCALAPPDATA%\Packages %SystemDrive%\$Recycle.Bin %SystemDrive%\System Volume Information %SystemDrive%\PerfLogs %ProgramFiles%\Microsoft SQL Server %ProgramFiles(x86)%\Microsoft SQL Server %ProgramData%\Microsoft\Windows\Caches %ProgramData%\USOPrivate %ProgramData%\USOShared %ProgramData%\Microsoft\IdentityCRL %ProgramData%\Microsoft\Device Stage %ProgramData%\Microsoft\NetFramework\BreadcrumbStore %ProgramData%\Vmware"
if not defined NODEFAULTEXCLUDE (
    set "EXCL_PREFIXES=!EXCL_PREFIXES! %ProgramFiles%\Windows Defender %ProgramFiles%\Windows Defender Advanced Threat Protection %ProgramFiles%\Windows Kits %ProgramFiles%\Microsoft SDKs %ProgramFiles%\Microsoft Visual Studio %ProgramFiles%\dotnet %ProgramFiles%\MSBuild %ProgramFiles%\Reference Assemblies %ProgramFiles%\Microsoft Office %ProgramFiles%\Common Files\Microsoft Shared %ProgramFiles%\NVIDIA Corporation %ProgramFiles%\Intel %ProgramFiles%\AMD %ProgramFiles%\Realtek %ProgramFiles%\Windows Photo Viewer %ProgramFiles%\Windows Media Player %ProgramFiles%\Windows NT %ProgramFiles%\Windows Mail %ProgramFiles%\VMware %ProgramFiles%\Amazon %ProgramFiles%\AWS Tools %ProgramFiles%\AWS SDK for .NET %ProgramFiles%\AWS Tools for Windows PowerShell %ProgramFiles%\WindowsPowerShell\Modules %ProgramFiles%\Microsoft.NET %ProgramData%\Microsoft %ProgramData%\Amazon %ProgramData%\Vmware %ProgramData%\Package Cache %ProgramData%\NVIDIA %ProgramData%\NVIDIA Corporation %ProgramData%\Intel %SystemDrive%\MSOCache %SystemDrive%\Recovery %SystemDrive%\Config.Msi %SystemDrive%\$WinREAgent %SystemDrive%\$SysReset %SystemDrive%\$GetCurrent %SystemDrive%\$Windows.~BT %SystemDrive%\$Windows.~WS %SystemDrive%\OneDriveTemp %SystemDrive%\Intel %SystemDrive%\AMD %SystemDrive%\NVIDIA"
)
goto :EOF

:WalkDir
set "startDir=%~1"
for /f "delims=" %%F in ('dir /S /B /A:-D "!startDir!\" 2^>nul') do (
    set "fp=%%~fF"
    set "skip=0"
    for %%P in (!EXCL_PREFIXES!) do (
        if not !skip!==1 (
            echo !fp! ^| findstr /I /B "%%~P" >nul 2>&1
            if !errorlevel!==0 set skip=1
        )
    )
    if !skip!==0 (
        echo !fp! ^| findstr /I "\AppData\Local\Microsoft\Windows\Caches \AppData\Local\Microsoft\Windows\Explorer \AppData\Local\Microsoft\Windows\Notifications \AppData\Local\ConnectedDevicesPlatform \AppData\Local\Microsoft\Edge\User Data\Default\Cache \AppData\Local\Microsoft\Edge\User Data\Default\Code Cache \AppData\Local\Microsoft\Edge\User Data\Default\GPUCache \AppData\Local\Microsoft\Edge\User Data\Default\ShaderCache \AppData\Local\Microsoft\Edge\User Data\Default\Service Worker \AppData\Local\Microsoft\Edge\User Data\BrowserMetrics \AppData\Local\Microsoft\Edge\User Data\Crashpad \AppData\Local\Microsoft\Edge\User Data\ShaderCache \AppData\Local\Google\Chrome\User Data\Default\Cache \AppData\Local\Google\Chrome\User Data\Default\Code Cache \AppData\Roaming\Microsoft\NetFramework\BreadcrumbStore" >nul 2>&1
        if !errorlevel!==0 set skip=1
    )
    if !skip!==0 (
        for %%D in (!EXCL_DIRS!) do (
            if not !skip!==1 (
                echo !fp! ^| findstr /I /C:"\%%~D\" >nul 2>&1
                if !errorlevel!==0 set skip=1
            )
        )
    )
    if !skip!==1 (
        echo [SKIP] excluded_path  !fp! >> "%SKIPPED%"
        set /a nSkip+=1
    ) else (
        echo !fp! >> "%FILELIST%"
    )
)
goto :EOF

:DoStage2
if not defined QUIET echo !CB![*] Stage 2 - Confirmed credential containers!CNC!
for /f "delims=" %%F in ('type "%FILELIST%" ^| findstr /I /E "\.kdbx \.kdb \.psafe3 \.agilekeychain \.opvault \.1pif \.1pux \.lpdb \.enpass \.enpassdb \.bitwarden_export \.ppk \.pfx \.p12 \.pvk \.jks \.keystore \.truststore \.bek \.fve \.keytab \.dpapimk"') do (
    call :AddGuaranteed "%%~xF" "%%~F"
)
goto :EOF

:DoStage3
if not defined QUIET echo !CB![*] Stage 3 - High-value file types!CNC!
for /f "delims=" %%F in ('type "%FILELIST%" ^| findstr /I /E "\.pem \.key \.priv \.crt \.cer \.csr \.env \.envrc \.keytab \.sh \.bash \.bak \.old \.orig \.backup \.swp \.save \.db \.sqlite \.sqlite3 \.log \.pcap \.pcapng \.tar \.tgz \.gz \.zip \.7z"') do (
    call :AddInterest "high_value_file" "%%~F"
)
for /f "delims=" %%F in ('type "%FILELIST%" ^| findstr /I /E "\krb5.conf \.htpasswd \.netrc \.pgpass \.my.cnf \my.cnf \.mysql.cnf"') do (
    call :AddInterest "high_value_file" "%%~F"
)
for /f "delims=" %%F in ('type "%FILELIST%" ^| findstr /I /R "\\krb5cc_.* \\.env\..* \\*\.tar\.gz"') do (
    call :AddInterest "high_value_file" "%%~F"
)
goto :EOF

:DoStage4
if not defined QUIET echo !CB![*] Stage 4 - Filename substring search!CNC!
for /f "delims=" %%F in ('type "%FILELIST%" ^| findstr /I /R "credential secret password passwd"') do (
    call :AddName "%%~F"
)
goto :EOF

:DoStage5
if not defined QUIET echo !CB![*] Stage 5 - Recursive content scan!CNC!
set /a scanned=0
for /f "delims=" %%F in ('type "%FILELIST%"') do call :Stage5File "%%~F"
if not defined QUIET echo !CG![+] Stage 5 complete.!CNC!
goto :EOF

:DoStage6
if not defined QUIET (
    echo.
    echo   !CC!==== STAGE 6 -- Git repository discovery ========================!CNC!
)
type nul > "%GIT%"
setlocal DisableDelayedExpansion
set "gitPaths=%PATHS%"
for %%P in ("%gitPaths:;=" "%") do if not "%%~P"=="" (
    if exist "%%~fP\" (
        for %%R in ("%%~fP") do call :GitVisitDirectory "%%~fR" "%%~nxR"
    ) else if exist "%%~fP" (
        for %%R in ("%%~fP") do if /I "%%~nxR"==".git" call :GitVisitFile "%%~fR" "%%~dpR"
    )
)
endlocal
sort /UNIQUE "%GIT%" > "%GIT%.sorted" 2>nul
move /Y "%GIT%.sorted" "%GIT%" >nul 2>&1
for /f %%N in ('find /V /C "" ^< "%GIT%"') do set /a nGit=%%N
if not defined QUIET if !nGit! GTR 0 (
    setlocal DisableDelayedExpansion
    for /f "usebackq delims=" %%L in ("%GIT%") do echo   %CB%%%L%CNC%
    endlocal
)
goto :EOF

:GitVisitFile
setlocal DisableDelayedExpansion
set "marker=%~1"
set "repoRoot=%~2"
for %%A in ("%marker%") do set "markerAttrs=%%~aA"
if not "%markerAttrs:l=%"=="%markerAttrs%" (endlocal & exit /b 0)
for %%R in ("%repoRoot%.") do call :GitDirectoryExcluded "%%~fR" "%%~nxR"
if errorlevel 1 call :CheckGitFile "%marker%" "%repoRoot%"
endlocal
exit /b 0

:GitVisitDirectory
setlocal DisableDelayedExpansion
set "candidate=%~1"
set "candidateName=%~2"
call :GitDirectoryExcluded "%candidate%" "%candidateName%"
if not errorlevel 1 (endlocal & exit /b 0)
if /I "%candidateName%"==".git" (
    for %%R in ("%candidate%\..") do call :RecordGit "directory" "%candidate%" "%%~fR"
    endlocal & exit /b 0
)
call :WalkGitDirectory "%candidate%"
endlocal
exit /b 0

:WalkGitDirectory
setlocal DisableDelayedExpansion
set "current=%~1"
if exist "%current%\.git" if not exist "%current%\.git\" call :CheckGitFile "%current%\.git" "%current%"
for /f "delims=" %%D in ('dir /B /A:D "%current%\*" 2^>nul') do (
    call :GitVisitDirectory "%current%\%%D" "%%D"
)
endlocal
exit /b 0

:GitDirectoryExcluded
setlocal DisableDelayedExpansion
set "candidate=%~1"
set "candidateName=%~2"
for %%A in ("%candidate%") do set "candidateAttrs=%%~aA"
if not "%candidateAttrs:l=%"=="%candidateAttrs%" (endlocal & exit /b 0)
for %%E in (%EXCL_DIRS%) do if /I "%candidateName%"=="%%~E" (endlocal & exit /b 0)
for %%X in ("%EXCLUDEPATHS:;=" "%") do if not "%%~X"=="" (
    set "prefix=%%~fX"
    setlocal EnableDelayedExpansion
    >nul echo(!candidate!| findstr /I /B /L /C:"!prefix!" >nul 2>&1
    for %%# in (!errorlevel!) do endlocal & if "%%#"=="0" (endlocal & exit /b 0)
)
for %%X in (%EXCL_PREFIXES%) do (
    set "prefix=%%~X"
    setlocal EnableDelayedExpansion
    >nul echo(!candidate!| findstr /I /B /L /C:"!prefix!" >nul 2>&1
    for %%# in (!errorlevel!) do endlocal & if "%%#"=="0" (endlocal & exit /b 0)
)
endlocal
exit /b 1

:CheckGitFile
setlocal DisableDelayedExpansion
set "marker=%~1"
set "repoRoot=%~2"
set "first="
<"%marker%" set /p "first=" 2>nul
setlocal EnableDelayedExpansion
>nul echo(!first!| findstr /I /B /R /C:" *gitdir: *[^ ]" >nul 2>&1
for %%# in (!errorlevel!) do endlocal & if "%%#"=="0" call :RecordGit "file" "!marker!" "!repoRoot!"
endlocal
exit /b 0

:RecordGit
setlocal DisableDelayedExpansion
set "gitType=%~1"
set "gitMarker=%~2"
set "gitRoot=%~3"
set "gitLine=[GIT] %gitType%  %gitMarker%  -^>  %gitRoot%"
setlocal EnableDelayedExpansion
>>"!GIT!" echo(!gitLine!
endlocal
endlocal
exit /b 0

:Stage5File
set "fp=%~1"
set "ext=%~x1"
set "name=%~n1"
    set "scan=0"
    if defined ALL set "scan=1"
    if /I "!ext!"==".conf" set "scan=1"
    if /I "!ext!"==".config" set "scan=1"
    if /I "!ext!"==".cfg" set "scan=1"
    if /I "!ext!"==".cnf" set "scan=1"
    if /I "!ext!"==".ini" set "scan=1"
    if /I "!ext!"==".env" set "scan=1"
    if /I "!ext!"==".envrc" set "scan=1"
    if /I "!ext!"==".yaml" set "scan=1"
    if /I "!ext!"==".yml" set "scan=1"
    if /I "!ext!"==".toml" set "scan=1"
    if /I "!ext!"==".json" set "scan=1"
    if /I "!ext!"==".jsonc" set "scan=1"
    if /I "!ext!"==".json5" set "scan=1"
    if /I "!ext!"==".xml" set "scan=1"
    if /I "!ext!"==".properties" set "scan=1"
    if /I "!ext!"==".prop" set "scan=1"
    if /I "!ext!"==".props" set "scan=1"
    if /I "!ext!"==".settings" set "scan=1"
    if /I "!ext!"==".tf" set "scan=1"
    if /I "!ext!"==".tfvars" set "scan=1"
    if /I "!ext!"==".tfstate" set "scan=1"
    if /I "!ext!"==".hcl" set "scan=1"
    if /I "!ext!"==".sh" set "scan=1"
    if /I "!ext!"==".bash" set "scan=1"
    if /I "!ext!"==".zsh" set "scan=1"
    if /I "!ext!"==".ksh" set "scan=1"
    if /I "!ext!"==".csh" set "scan=1"
    if /I "!ext!"==".fish" set "scan=1"
    if /I "!ext!"==".bashrc" set "scan=1"
    if /I "!ext!"==".profile" set "scan=1"
    if /I "!ext!"==".zshrc" set "scan=1"
    if /I "!ext!"==".ps1" set "scan=1"
    if /I "!ext!"==".psm1" set "scan=1"
    if /I "!ext!"==".psd1" set "scan=1"
    if /I "!ext!"==".bat" set "scan=1"
    if /I "!ext!"==".cmd" set "scan=1"
    if /I "!ext!"==".vbs" set "scan=1"
    if /I "!ext!"==".vbe" set "scan=1"
    if /I "!ext!"==".wsf" set "scan=1"
    if /I "!ext!"==".ahk" set "scan=1"
    if /I "!ext!"==".py" set "scan=1"
    if /I "!ext!"==".pl" set "scan=1"
    if /I "!ext!"==".rb" set "scan=1"
    if /I "!ext!"==".php" set "scan=1"
    if /I "!ext!"==".phtml" set "scan=1"
    if /I "!ext!"==".php3" set "scan=1"
    if /I "!ext!"==".php5" set "scan=1"
    if /I "!ext!"==".inc" set "scan=1"
    if /I "!ext!"==".lua" set "scan=1"
    if /I "!ext!"==".groovy" set "scan=1"
    if /I "!ext!"==".tcl" set "scan=1"
    if /I "!ext!"==".java" set "scan=1"
    if /I "!ext!"==".cs" set "scan=1"
    if /I "!ext!"==".vb" set "scan=1"
    if /I "!ext!"==".go" set "scan=1"
    if /I "!ext!"==".rs" set "scan=1"
    if /I "!ext!"==".js" set "scan=1"
    if /I "!ext!"==".ts" set "scan=1"
    if /I "!ext!"==".jsx" set "scan=1"
    if /I "!ext!"==".tsx" set "scan=1"
    if /I "!ext!"==".mjs" set "scan=1"
    if /I "!ext!"==".cjs" set "scan=1"
    if /I "!ext!"==".aspx" set "scan=1"
    if /I "!ext!"==".asp" set "scan=1"
    if /I "!ext!"==".ashx" set "scan=1"
    if /I "!ext!"==".asmx" set "scan=1"
    if /I "!ext!"==".asax" set "scan=1"
    if /I "!ext!"==".ascx" set "scan=1"
    if /I "!ext!"==".cshtml" set "scan=1"
    if /I "!ext!"==".vbhtml" set "scan=1"
    if /I "!ext!"==".master" set "scan=1"
    if /I "!ext!"==".svc" set "scan=1"
    if /I "!ext!"==".jsp" set "scan=1"
    if /I "!ext!"==".jspx" set "scan=1"
    if /I "!ext!"==".jspf" set "scan=1"
    if /I "!ext!"==".cfm" set "scan=1"
    if /I "!ext!"==".cfc" set "scan=1"
    if /I "!ext!"==".htaccess" set "scan=1"
    if /I "!ext!"==".dsn" set "scan=1"
    if /I "!ext!"==".udl" set "scan=1"
    if /I "!ext!"==".ora" set "scan=1"
    if /I "!ext!"==".tns" set "scan=1"
    if /I "!ext!"==".reg" set "scan=1"
    if /I "!ext!"==".rdp" set "scan=1"
    if /I "!ext!"==".rdg" set "scan=1"
    if /I "!ext!"==".rdcman" set "scan=1"
    if /I "!ext!"==".inf" set "scan=1"
    if /I "!ext!"==".unattend" set "scan=1"
    if /I "!ext!"==".answerfile" set "scan=1"
    if /I "!ext!"==".ovpn" set "scan=1"
    if /I "!ext!"==".openvpn" set "scan=1"
    if /I "!ext!"==".vnc" set "scan=1"
    if /I "!ext!"==".rdc" set "scan=1"
    if /I "!ext!"==".tcc" set "scan=1"
    if /I "!ext!"==".ica" set "scan=1"
    if /I "!ext!"==".session" set "scan=1"
    if /I "!ext!"==".script" set "scan=1"
    if /I "!ext!"==".kix" set "scan=1"
    if /I "!ext!"==".txt" set "scan=1"
    if /I "!ext!"==".text" set "scan=1"
    if /I "!ext!"==".log" set "scan=1"
    if /I "!ext!"==".logs" set "scan=1"
    if /I "!ext!"==".bak" set "scan=1"
    if /I "!ext!"==".backup" set "scan=1"
    if /I "!ext!"==".old" set "scan=1"
    if /I "!ext!"==".orig" set "scan=1"
    if /I "!ext!"==".original" set "scan=1"
    if /I "!ext!"==".save" set "scan=1"
    if /I "!ext!"==".saved" set "scan=1"
    if /I "!ext!"==".tmp" set "scan=1"
    if /I "!ext!"==".temp" set "scan=1"
    if /I "!ext!"==".ldif" set "scan=1"
    if /I "!ext!"==".ldiff" set "scan=1"
    if /I "!ext!"==".service" set "scan=1"
    if /I "!ext!"==".unit" set "scan=1"
    if /I "!ext!"==".crontab" set "scan=1"
    if /I "!ext!"==".cron" set "scan=1"
    if /I "!ext!"==".local" set "scan=1"
    if /I "!ext!"==".shared" set "scan=1"
    if /I "!ext!"==".secret" set "scan=1"
    if /I "!ext!"==".secrets" set "scan=1"
    if /I "!ext!"==".creds" set "scan=1"
    if /I "!ext!"==".cred" set "scan=1"
    if /I "!ext!"==".passwd" set "scan=1"
    if /I "!ext!"==".auth" set "scan=1"
    if /I "!ext!"==".vault" set "scan=1"
    if /I "!ext!"==".j2" set "scan=1"
    if /I "!ext!"==".erb" set "scan=1"
    if /I "!ext!"==".pp" set "scan=1"
    if /I "!ext!"==".sls" set "scan=1"
    if /I "!ext!"==".tmpl" set "scan=1"
    if /I "!ext!"==".tpl" set "scan=1"
    if /I "!ext!"==".gotmpl" set "scan=1"
    if /I "!ext!"==".bicep" set "scan=1"
    if /I "!ext!"==".pyw" set "scan=1"
    if /I "!ext!"==".kt" set "scan=1"
    if /I "!ext!"==".kts" set "scan=1"
    if /I "!ext!"==".scala" set "scan=1"
    if /I "!ext!"==".sbt" set "scan=1"
    if /I "!ext!"==".gradle" set "scan=1"
    if /I "!ext!"==".clj" set "scan=1"
    if /I "!ext!"==".cljs" set "scan=1"
    if /I "!ext!"==".cljc" set "scan=1"
    if /I "!ext!"==".ex" set "scan=1"
    if /I "!ext!"==".exs" set "scan=1"
    if /I "!ext!"==".erl" set "scan=1"
    if /I "!ext!"==".hrl" set "scan=1"
    if /I "!ext!"==".dart" set "scan=1"
    if /I "!ext!"==".swift" set "scan=1"
    if /I "!ext!"==".vue" set "scan=1"
    if /I "!ext!"==".svelte" set "scan=1"
    if /I "!ext!"==".astro" set "scan=1"
    if /I "!ext!"==".cgi" set "scan=1"
    if /I "!ext!"==".fcgi" set "scan=1"
    if /I "!ext!"==".php4" set "scan=1"
    if /I "!ext!"==".php7" set "scan=1"
    if /I "!ext!"==".phps" set "scan=1"
    if /I "!ext!"==".pht" set "scan=1"
    if /I "!ext!"==".resx" set "scan=1"
    if /I "!ext!"==".resw" set "scan=1"
    if /I "!ext!"==".pubxml" set "scan=1"
    if /I "!ext!"==".publishsettings" set "scan=1"
    if /I "!ext!"==".hta" set "scan=1"
    if /I "!ext!"==".au3" set "scan=1"
    if /I "!ext!"==".url" set "scan=1"
    if /I "!ext!"==".nmconnection" set "scan=1"
    if /I "!ext!"==".wg" set "scan=1"
    if /I "!ext!"==".pcf" set "scan=1"
    if /I "!ext!"==".mobileconfig" set "scan=1"
    if /I "!ext!"==".cql" set "scan=1"
    if /I "!ext!"==".prisma" set "scan=1"
    if /I "!ext!"==".note" set "scan=1"
    if /I "!ext!"==".notes" set "scan=1"
    if /I "!ext!"==".eml" set "scan=1"
    if /I "!ext!"==".dpkg-old" set "scan=1"
    if /I "!ext!"==".dpkg-dist" set "scan=1"
    if /I "!ext!"==".dpkg-new" set "scan=1"
    if /I "!ext!"==".rpmsave" set "scan=1"
    if /I "!ext!"==".rpmnew" set "scan=1"
    if /I "!ext!"==".rpmorig" set "scan=1"
    if /I "!ext!"==".ucf-old" set "scan=1"
    if /I "!ext!"==".ucf-dist" set "scan=1"
    if /I "!ext!"==".bk" set "scan=1"
    if /I "!ext!"==".bkp" set "scan=1"
    if /I "!ext!"==".bkup" set "scan=1"
    if /I "!ext!"==".sav" set "scan=1"
    if /I "!ext!"==".default" set "scan=1"
    if /I "!name!"=="dockerfile" set "scan=1"
    if /I "!name!"=="vagrantfile" set "scan=1"
    if /I "!name!"=="makefile" set "scan=1"
    if /I "!name!"=="jenkinsfile" set "scan=1"
    if /I "!name!"=="authorized_keys" set "scan=1"
    if /I "!name!"=="known_hosts" set "scan=1"
    if /I "!name!"=="identity" set "scan=1"
    if /I "!name!"=="shadow" set "scan=1"
    if /I "!name!"=="gshadow" set "scan=1"
    if /I "!name!"=="sudoers" set "scan=1"
    if /I "!name!"=="opasswd" set "scan=1"
    if /I "!name!"==".htpasswd" set "scan=1"
    if /I "!name!"=="htpasswd" set "scan=1"
    if /I "!name!"==".bashrc" set "scan=1"
    if /I "!name!"==".zshrc" set "scan=1"
    if /I "!name!"==".kshrc" set "scan=1"
    if /I "!name!"==".cshrc" set "scan=1"
    if /I "!name!"==".tcshrc" set "scan=1"
    if /I "!name!"==".bash_profile" set "scan=1"
    if /I "!name!"==".zprofile" set "scan=1"
    if /I "!name!"==".profile" set "scan=1"
    if /I "!name!"==".bash_login" set "scan=1"
    if /I "!name!"==".zlogin" set "scan=1"
    if /I "!name!"==".bash_logout" set "scan=1"
    if /I "!name!"==".envrc" set "scan=1"
    if /I "!name!"==".env" set "scan=1"
    if /I "!name!"==".npmrc" set "scan=1"
    if /I "!name!"==".pypirc" set "scan=1"
    if /I "!name!"==".netrc" set "scan=1"
    if /I "!name!"=="_netrc" set "scan=1"
    if /I "!name!"==".gitconfig" set "scan=1"
    if /I "!name!"==".git-credentials" set "scan=1"
    if /I "!name!"==".s3cfg" set "scan=1"
    if /I "!name!"==".boto" set "scan=1"
    if /I "!name!"==".viminfo" set "scan=1"
    if /I "!name!"==".psqlrc" set "scan=1"
    if /I "!name!"==".mysqlrc" set "scan=1"
    if /I "!name!"==".my.cnf" set "scan=1"
    if /I "!name!"==".bash_history" set "scan=1"
    if /I "!name!"==".zsh_history" set "scan=1"
    if /I "!name!"==".sh_history" set "scan=1"
    if /I "!name!"==".ksh_history" set "scan=1"
    if /I "!name!"==".ash_history" set "scan=1"
    if /I "!name!"==".history" set "scan=1"
    if /I "!name!"==".psql_history" set "scan=1"
    if /I "!name!"==".mysql_history" set "scan=1"
    if /I "!name!"==".sqlite_history" set "scan=1"
    if /I "!name!"==".python_history" set "scan=1"
    if /I "!name!"==".node_repl_history" set "scan=1"
    if /I "!name!"==".irb_history" set "scan=1"
    if /I "!name!"==".rediscli_history" set "scan=1"
    if /I "!name!"==".lesshst" set "scan=1"
    if /I "!name!"=="sitemanager.xml" set "scan=1"
    if /I "!name!"=="recentservers.xml" set "scan=1"
    if /I "!name!"=="winscp.ini" set "scan=1"
    if defined INCLUDEDATA (
        if /I "!ext!"==".sql" set "scan=1"
        if /I "!ext!"==".ddl" set "scan=1"
        if /I "!ext!"==".dump" set "scan=1"
        if /I "!ext!"==".psql" set "scan=1"
        if /I "!ext!"==".pgsql" set "scan=1"
        if /I "!ext!"==".plsql" set "scan=1"
        if /I "!ext!"==".tsql" set "scan=1"
        if /I "!ext!"==".csv" set "scan=1"
        if /I "!ext!"==".tsv" set "scan=1"
    )
    if !scan!==0 goto :EOF

    :: Size check
    set "fsize=0"
    for %%Z in ("!fp!") do set "fsize=%%~zZ"
    if !fsize! GTR %MAXBYTES% (
        if /I "!ext!"==".log" goto :EOF
        if /I "!ext!"==".logs" goto :EOF
        echo [SKIP] size_limit  !fp! >> "%SKIPPED%"
        set /a nSkip+=1
        goto :EOF
    )

    :: Skip known non-credential filenames
    set "bn=%~nx1"
    set "skipfile=0"
    if /I "!bn!"=="LICENSE" set skipfile=1
    if /I "!bn!"=="LICENSE.txt" set skipfile=1
    if /I "!bn!"=="LICENSE.md" set skipfile=1
    if /I "!bn!"=="CHANGELOG" set skipfile=1
    if /I "!bn!"=="CHANGELOG.md" set skipfile=1
    if /I "!bn!"=="README" set skipfile=1
    if /I "!bn!"=="README.md" set skipfile=1
    if /I "!bn!"=="package.json" set skipfile=1
    if /I "!bn!"=="package-lock.json" set skipfile=1
    if /I "!bn!"==".gitignore" set skipfile=1
    if /I "!bn!"==".gitattributes" set skipfile=1
    if /I "!bn!"==".editorconfig" set skipfile=1
    if /I "!bn!"==".gitmodules" set skipfile=1
    if /I "!bn!"==".prettierrc" set skipfile=1
    if /I "!bn!"==".eslintrc" set skipfile=1
    if /I "!bn!"==".babelrc" set skipfile=1
    if /I "!bn!"==".dockerignore" set skipfile=1
    if /I "!bn!"==".npmignore" set skipfile=1
    if /I "!bn!"==".DS_Store" set skipfile=1
    if /I "!bn!"=="Thumbs.db" set skipfile=1
    if /I "!bn!"=="desktop.ini" set skipfile=1
    if !skipfile!==1 goto :EOF

    :: Check for key patterns first
    findstr /I /M /G:"%KEYPATTERNS%" "!fp!" >nul 2>&1
    if !errorlevel!==0 (
        for /f "delims=:" %%a in ('findstr /I /N /G:"%KEYPATTERNS%" "!fp!" 2^>nul') do (
            call :AddKey "content/private_key" "!fp!" "%%a" "Private key header found"
        )
    )

    :: Check for credential patterns
    findstr /I /M /G:"%PATTERNS%" "!fp!" >nul 2>&1
    if !errorlevel!==0 (
        for /f "delims=:" %%a in ('findstr /I /N /G:"%PATTERNS%" "!fp!" 2^>nul') do (
            call :AddHigh "content/credential_match" "!fp!" "%%a" "Credential keyword found"
        )
    )

    set /a scanned+=1
    if not defined QUIET (
        if !scanned! GEQ 500 (
            set /a scanned=0
            echo   !CD![*] Scanned !fp!!CNC!
        )
    )
goto :EOF

:: ---------------------------------------------------------------------------
::  Helper subroutines
:: ---------------------------------------------------------------------------
:IsFP
set "testval=%~1"
set "testval=!testval:"=!"
set "testval=!testval: =!"
set "fp=0"
if /I "!testval!"=="" set fp=1
if /I "!testval!"=="password" set fp=1
if /I "!testval!"=="passwd" set fp=1
if /I "!testval!"=="pwd" set fp=1
if /I "!testval!"=="pass" set fp=1
if /I "!testval!"=="passphrase" set fp=1
if /I "!testval!"=="secret" set fp=1
if /I "!testval!"=="token" set fp=1
if /I "!testval!"=="null" set fp=1
if /I "!testval!"=="none" set fp=1
if /I "!testval!"=="nil" set fp=1
if /I "!testval!"=="undefined" set fp=1
if /I "!testval!"=="empty" set fp=1
if /I "!testval!"=="void" set fp=1
if /I "!testval!"=="true" set fp=1
if /I "!testval!"=="false" set fp=1
if /I "!testval!"=="example" set fp=1
if /I "!testval!"=="sample" set fp=1
if /I "!testval!"=="demo" set fp=1
if /I "!testval!"=="placeholder" set fp=1
if /I "!testval!"=="dummy" set fp=1
if /I "!testval!"=="fake" set fp=1
if /I "!testval!"=="stub" set fp=1
if /I "!testval!"=="mock" set fp=1
if /I "!testval!"=="test" set fp=1
if /I "!testval!"=="testing" set fp=1
if /I "!testval!"=="foo" set fp=1
if /I "!testval!"=="bar" set fp=1
if /I "!testval!"=="baz" set fp=1
if /I "!testval!"=="abc" set fp=1
if /I "!testval!"=="123" set fp=1
if /I "!testval!"=="changeme" set fp=1
if /I "!testval!"=="change_me" set fp=1
if /I "!testval!"=="change-me" set fp=1
if /I "!testval!"=="changethis" set fp=1
if /I "!testval!"=="change-this" set fp=1
if /I "!testval!"=="changeit" set fp=1
if /I "!testval!"=="change-it" set fp=1
if /I "!testval!"=="todo" set fp=1
if /I "!testval!"=="fixme" set fp=1
if /I "!testval!"=="tbd" set fp=1
if /I "!testval!"=="n/a" set fp=1
if /I "!testval!"=="na" set fp=1
if /I "!testval!"=="your_password" set fp=1
if /I "!testval!"=="yourpassword" set fp=1
if /I "!testval!"=="your-password" set fp=1
if /I "!testval!"=="yourpasswordhere" set fp=1
if /I "!testval!"=="insert_password" set fp=1
if /I "!testval!"=="replace_me" set fp=1
if /I "!testval!"=="replace-me" set fp=1
if /I "!testval!"=="replace_this" set fp=1
if /I "!testval!"=="insert_here" set fp=1
if /I "!testval!"=="<password>" set fp=1
if /I "!testval!"=="<pass>" set fp=1
if /I "!testval!"=="<secret>" set fp=1
if /I "!testval!"=="<token>" set fp=1
if /I "!testval!"=="<key>" set fp=1
if /I "!testval!"=="<value>" set fp=1
if /I "!testval!"=="<your-password>" set fp=1
if /I "!testval!"=="<input>" set fp=1
if /I "!testval!"=="<enter>" set fp=1
if /I "!testval!"=="<here>" set fp=1
if /I "!testval!"=="..." set fp=1
if /I "!testval!"=="********" set fp=1
if /I "!testval!"=="*****" set fp=1
if /I "!testval!"=="***" set fp=1
if /I "!testval!"=="xxxxxxxx" set fp=1
if /I "!testval!"=="xxxxx" set fp=1
if /I "!testval!"=="xxx" set fp=1
if /I "!testval!"=="redacted" set fp=1
if /I "!testval!"=="hidden" set fp=1
if /I "!testval!"=="masked" set fp=1
if /I "!testval!"=="sanitized" set fp=1
if /I "!testval!"=="username" set fp=1
if /I "!testval!"=="email" set fp=1
if /I "!testval!"=="hostname" set fp=1
if /I "!testval!"=="host" set fp=1
if /I "!testval!"=="database" set fp=1
if /I "!testval!"=="value" set fp=1
if /I "!testval!"=="string" set fp=1
if /I "!testval!"=="text" set fp=1
if /I "!testval!"=="data" set fp=1
if /I "!testval!"=="admin" set fp=1
if /I "!testval!"=="administrator" set fp=1
if /I "!testval!"=="localhost" set fp=1
if /I "!testval!"=="127.0.0.1" set fp=1
if /I "!testval!"=="0.0.0.0" set fp=1
if /I "!testval!"=="::1" set fp=1
if /I "!testval!"=="enabled" set fp=1
if /I "!testval!"=="disabled" set fp=1
if /I "!testval!"=="default" set fp=1
if /I "!testval!"=="auto" set fp=1
if /I "!testval!"=="unknown" set fp=1
if /I "!testval!"=="yes" set fp=1
if /I "!testval!"=="no" set fp=1
if /I "!testval!"=="on" set fp=1
if /I "!testval!"=="off" set fp=1
if /I "!testval!"=="optional" set fp=1
if /I "!testval!"=="required" set fp=1
if /I "!testval!"=="mandatory" set fp=1
if !fp!==1 exit /b 0
exit /b 1

:AddHigh
set "hLabel=%~1"
set "hPath=%~2"
set "hLine=%~3"
set "hPreview=%~4"
set "hKey=[HIGH] !hLabel! !hPath!:!hLine!"
findstr /X /C:"!hKey!" "%DEDUP%" >nul 2>&1
if !errorlevel!==0 goto :EOF
echo !hKey! >> "%DEDUP%"
echo !hKey!  !hPreview! >> "%HIGH%"
if not defined QUIET echo   !CR![HIGH]!CNC! !CD!!hLabel!!CNC!  !CY!!hPath!:!hLine!!CNC!
if not defined QUIET echo        !CD!!hPreview!!CNC!
if defined OUTPUTFILE echo [HIGH] !hLabel! !hPath!:!hLine!  !hPreview! >> "%OUTPUTFILE%"
set /a nHigh+=1
set /a EXITCODE=1
goto :EOF

:AddKey
set "kLabel=%~1"
set "kPath=%~2"
set "kLine=%~3"
set "kPreview=%~4"
set "kKey=[KEY] !kLabel! !kPath!:!kLine!"
findstr /X /C:"!kKey!" "%DEDUP%" >nul 2>&1
if !errorlevel!==0 goto :EOF
echo !kKey! >> "%DEDUP%"
echo !kKey!  !kPreview! >> "%KEY%"
if not defined QUIET echo   !CM![KEY]!CNC! !CD!!kLabel!!CNC!  !CY!!kPath!:!kLine!!CNC!
if not defined QUIET echo        !CD!!kPreview!!CNC!
if defined OUTPUTFILE echo [KEY] !kLabel! !kPath!:!kLine!  !kPreview! >> "%OUTPUTFILE%"
set /a nKey+=1
set /a EXITCODE=1
goto :EOF

:AddInterest
set "iCat=%~1"
set "iPath=%~2"
set "iKey=[INTEREST] !iCat! !iPath!"
findstr /X /C:"!iKey!" "%DEDUP%" >nul 2>&1
if !errorlevel!==0 goto :EOF
echo !iKey! >> "%DEDUP%"
echo !iKey! >> "%INTEREST%"
if not defined QUIET echo   !CC![INTEREST]!CNC! !CD!!iCat!!CNC!  !iPath!
if defined OUTPUTFILE echo [INTEREST] !iCat!  !iPath! >> "%OUTPUTFILE%"
set /a nInt+=1
goto :EOF

:AddName
set "nPath=%~1"
set "nKey=[NAME] !nPath!"
findstr /X /C:"!nKey!" "%DEDUP%" >nul 2>&1
if !errorlevel!==0 goto :EOF
echo !nKey! >> "%DEDUP%"
echo !nKey! >> "%NAME%"
if not defined QUIET echo   !CY![NAME]!CNC! !nPath!
if defined OUTPUTFILE echo [NAME] !nPath! >> "%OUTPUTFILE%"
set /a nName+=1
goto :EOF

:AddGuaranteed
set "gExt=%~1"
set "gPath=%~2"
set "gKey=[CRITICAL] !gExt!  !gPath!"
findstr /X /C:"!gKey!" "%DEDUP%" >nul 2>&1
if !errorlevel!==0 goto :EOF
echo !gKey! >> "%DEDUP%"
echo !gKey! >> "%GUAR%"
if not defined QUIET echo   !CR![CRITICAL]!CNC! !CD!!gExt!!CNC!  !CW!!gPath!!CNC!
if defined OUTPUTFILE echo [CRITICAL] !gExt!  !gPath! >> "%OUTPUTFILE%"
set /a nGuar+=1
set /a EXITCODE=1
goto :EOF

:AddChecked
set "cLabel=%~1"
set "cPath=%~2"
set "cKey=[CHECK] !cLabel!  !cPath!"
findstr /X /C:"!cKey!" "%DEDUP%" >nul 2>&1
if !errorlevel!==0 goto :EOF
echo !cKey! >> "%DEDUP%"
echo !cKey! >> "%CHECKED%"
set /a nCheck+=1
goto :EOF

:ScanFile
set "sPath=%~1"
set "sLabel=%~2"
findstr /I /M /G:"%KEYPATTERNS%" "!sPath!" >nul 2>&1
if !errorlevel!==0 (
    for /f "delims=:" %%a in ('findstr /I /N /G:"%KEYPATTERNS%" "!sPath!" 2^>nul') do (
        call :AddKey "!sLabel!/private_key" "!sPath!" "%%a" "Private key header found"
    )
)
findstr /I /M /G:"%PATTERNS%" "!sPath!" >nul 2>&1
if !errorlevel!==0 (
    for /f "delims=:" %%a in ('findstr /I /N /G:"%PATTERNS%" "!sPath!" 2^>nul') do (
        call :AddHigh "!sLabel!/credential_match" "!sPath!" "%%a" "Credential keyword found"
    )
)
goto :EOF

:WriteSummary
if not defined QUIET (
    echo.
    echo   !CC!==== SUMMARY =====================================================!CNC!
)
if %nGuar% GTR 0 (
    if not defined QUIET (
        echo.
        echo   !CW!^> Confirmed credential containers!CNC!
    )
    if defined OUTPUTFILE echo === Confirmed credential containers === >> "%OUTPUTFILE%"
    for /f "delims=" %%a in ('type "%GUAR%"') do (
        if not defined QUIET echo   !CR!%%a!CNC!
        if defined OUTPUTFILE echo %%a >> "%OUTPUTFILE%"
    )
)
if %nHigh% GTR 0 (
    if not defined QUIET (
        echo.
        echo   !CW!^> Reusable credentials!CNC!
    )
    if defined OUTPUTFILE echo === Reusable credentials === >> "%OUTPUTFILE%"
    for /f "delims=" %%a in ('type "%HIGH%"') do (
        if not defined QUIET echo   !CR!%%a!CNC!
        if defined OUTPUTFILE echo %%a >> "%OUTPUTFILE%"
    )
)
if %nKey% GTR 0 (
    if not defined QUIET (
        echo.
        echo   !CW!^> Private keys / authentication material!CNC!
    )
    if defined OUTPUTFILE echo === Private keys / authentication material === >> "%OUTPUTFILE%"
    for /f "delims=" %%a in ('type "%KEY%"') do (
        if not defined QUIET echo   !CM!%%a!CNC!
        if defined OUTPUTFILE echo %%a >> "%OUTPUTFILE%"
    )
)
if %nInt% GTR 0 (
    if not defined QUIET (
        echo.
        echo   !CW!^> Auxiliary credential-related files!CNC!
    )
    if defined OUTPUTFILE echo === Auxiliary credential-related files === >> "%OUTPUTFILE%"
    for /f "delims=" %%a in ('type "%INTEREST%"') do (
        if not defined QUIET echo   !CC!%%a!CNC!
        if defined OUTPUTFILE echo %%a >> "%OUTPUTFILE%"
    )
)
if %nName% GTR 0 (
    if not defined QUIET (
        echo.
        echo   !CW!^> Suspicious filenames ^(substring match^)!CNC!
    )
    if defined OUTPUTFILE echo === Suspicious filenames === >> "%OUTPUTFILE%"
    for /f "delims=" %%a in ('type "%NAME%"') do (
        if not defined QUIET echo   !CY!%%a!CNC!
        if defined OUTPUTFILE echo %%a >> "%OUTPUTFILE%"
    )
)
if %nGit% GTR 0 (
    if not defined QUIET (
        echo.
        echo   !CW!^> Git repositories!CNC!
    )
    if defined OUTPUTFILE echo === Git repositories === >> "%OUTPUTFILE%"
    setlocal DisableDelayedExpansion
    for /f "usebackq delims=" %%a in ("%GIT%") do (
        echo   %CB%%%a%CNC%
        if defined OUTPUTFILE echo %%a >> "%OUTPUTFILE%"
    )
    endlocal
)
if %nCheck% GTR 0 (
    if not defined QUIET (
        echo.
        echo   !CW!^> OS locations checked!CNC!
    )
    if defined OUTPUTFILE echo === OS locations checked === >> "%OUTPUTFILE%"
    for /f "delims=" %%a in ('type "%CHECKED%"') do (
        if not defined QUIET echo   !CB!%%a!CNC!
        if defined OUTPUTFILE echo %%a >> "%OUTPUTFILE%"
    )
)
if %nSkip% GTR 0 (
    if not defined QUIET (
        echo.
        echo   !CW!^> Skipped files!CNC!
        echo   !CD![SKIP] %nSkip% file^(s^) skipped ^(binary / size / unreadable^). See log.!CNC!
    )
    if defined OUTPUTFILE echo === Skipped files === >> "%OUTPUTFILE%"
    for /f "delims=" %%a in ('type "%SKIPPED%"') do (
        if defined OUTPUTFILE echo %%a >> "%OUTPUTFILE%"
    )
)

if not defined QUIET (
    echo.
    echo   !CC!==== COUNTS ======================================================!CNC!
    echo   !CR!Confirmed credential containers ............ %nGuar%!CNC!
    echo   !CR!Reusable credentials ........................ %nHigh%!CNC!
    echo   !CM!Private keys / auth material ............... %nKey%!CNC!
    echo   !CC!Auxiliary credential-related files .......... %nInt%!CNC!
    echo   !CY!Suspicious filenames ^(substring^) ............ %nName%!CNC!
    echo   !CB!Git repositories found ...................... %nGit%!CNC!
    echo   !CB!OS locations checked ........................ %nCheck%!CNC!
    echo   !CD!Files skipped ^(size/binary/perm^) ............ %nSkip%!CNC!
)
if defined OUTPUTFILE (
    echo. >> "%OUTPUTFILE%"
    echo Summary: >> "%OUTPUTFILE%"
    echo   Confirmed credential containers: %nGuar% >> "%OUTPUTFILE%"
    echo   Reusable credentials:            %nHigh% >> "%OUTPUTFILE%"
    echo   Private keys / material:         %nKey% >> "%OUTPUTFILE%"
    echo   Auxiliary credential-related:    %nInt% >> "%OUTPUTFILE%"
    echo   Suspicious filenames:            %nName% >> "%OUTPUTFILE%"
    echo   Git repositories found:           %nGit% >> "%OUTPUTFILE%"
    echo   OS locations checked:            %nCheck% >> "%OUTPUTFILE%"
    echo   Files skipped:                   %nSkip% >> "%OUTPUTFILE%"
    if not defined QUIET echo !CB![*] Full log written to !CW!!OUTPUTFILE!!CNC!
)
goto :EOF

