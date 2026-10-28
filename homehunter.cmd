@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem HomeHunter - read-only CMD scanner for all local Windows user profiles.

set "VERSION=1.0.0"
set "MAXMB=5"
set "OUTPUTFILE="
set "QUIET="
set "NOCOLOR="
set "ONLYSPEC="
set /a EXTRACOUNT=0

:ParseArgs
if "%~1"=="" goto Init
if /I "%~1"=="-MaxFileSizeMB" (
    if "%~2"=="" goto ArgError
    set "MAXMB=%~2"& shift & shift & goto ParseArgs
)
if /I "%~1"=="-OutputFile" (
    if "%~2"=="" goto ArgError
    set "OUTPUTFILE=%~2"& shift & shift & goto ParseArgs
)
if /I "%~1"=="-Home" (
    if "%~2"=="" goto ArgError
    set /a EXTRACOUNT+=1
    set "EXTRAHOME!EXTRACOUNT!=%~2"
    shift & shift & goto ParseArgs
)
if /I "%~1"=="-OnlySpecifiedHomes" set "ONLYSPEC=1"& shift & goto ParseArgs
if /I "%~1"=="-Quiet" set "QUIET=1"& shift & goto ParseArgs
if /I "%~1"=="-NoColor" set "NOCOLOR=1"& shift & goto ParseArgs
if /I "%~1"=="-Help" goto Help
if /I "%~1"=="-h" goto Help
if /I "%~1"=="-Version" echo homehunter %VERSION%& exit /b 0
echo [ERROR] Unknown option: %~1 1>&2
exit /b 2

:ArgError
echo [ERROR] Option %~1 requires a value. 1>&2
exit /b 2

:Help
echo homehunter.cmd v%VERSION%
echo.
echo Usage: homehunter.cmd [options]
echo   -MaxFileSizeMB N       Maximum text file size, default 5, maximum 512
echo   -OutputFile FILE       Append findings to a restricted text log
echo   -Home PATH             Add explicit home path, repeatable
echo   -OnlySpecifiedHomes    Scan only paths supplied with -Home
echo   -Quiet                 Suppress progress
echo   -NoColor               Output parity option
echo   -Help                  Show help
echo.
echo No options are required. Run elevated for the widest coverage.
exit /b 0

:Init
for /f "delims=0123456789" %%A in ("%MAXMB%") do if not "%%A"=="" (
    echo [ERROR] -MaxFileSizeMB must be an integer. 1>&2& exit /b 2
)
if %MAXMB% LSS 1 echo [ERROR] Size must be positive. 1>&2& exit /b 2
if %MAXMB% GTR 512 echo [ERROR] Size cannot exceed 512 MiB. 1>&2& exit /b 2
if defined ONLYSPEC if %EXTRACOUNT% EQU 0 echo [ERROR] -OnlySpecifiedHomes requires -Home. 1>&2& exit /b 2
set /a MAXBYTES=%MAXMB%*1048576
set "TMPROOT=%TEMP%\homehunter-%RANDOM%-%RANDOM%"
md "%TMPROOT%" >nul 2>&1 || (echo [ERROR] Cannot create temporary directory. 1>&2& exit /b 2)
set "HOMES=%TMPROOT%\homes.txt"
set "REPORTED=%TMPROOT%\reported.txt"
set "PATTERNS=%TMPROOT%\patterns.txt"
set "ERRORS=%TMPROOT%\errors.txt"
type nul >"%HOMES%"
type nul >"%REPORTED%"
(
echo password
echo passwd
echo passphrase
echo pwd=
echo secret=
echo cpassword
echo DefaultPassword
echo AltDefaultPassword
echo PGPASSWORD
echo MYSQL_PWD
echo --password
echo -pw
echo jdbc:
echo $krb5
echo trusted_connection
) >"%PATTERNS%"

set /a nHomes=0,nHomesScanned=0,nFiles=0,nText=0,nHidden=0,nHigh=0,nKey=0,nLarge=0,nBinary=0,nDenied=0
set "EXITCODE=0"

if defined OUTPUTFILE (
    type nul >"%OUTPUTFILE%" 2>nul || (echo [ERROR] Cannot create output file. 1>&2& goto Fatal)
    icacls "%OUTPUTFILE%" /inheritance:r /grant:r "%USERNAME%:(F)" >nul 2>&1
    for %%F in ("%OUTPUTFILE%") do set "OUTPUTFILE=%%~fF"
)

if not defined ONLYSPEC call :DiscoverHomes
for /L %%I in (1,1,%EXTRACOUNT%) do call :AddHome "!EXTRAHOME%%I!"
for /f %%N in ('find /v /c "" ^< "%HOMES%"') do set /a nHomes=%%N
if !nHomes! EQU 0 echo [ERROR] No home directories discovered. 1>&2& goto Fatal
if not defined QUIET echo [*] Discovered !nHomes! home directories; text limit %MAXMB% MiB

for /f "usebackq delims=" %%H in ("%HOMES%") do call :ScanHome "%%H"
call :Summary
rd /s /q "%TMPROOT%" >nul 2>&1
exit /b %EXITCODE%

:DiscoverHomes
for /f "tokens=2,*" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" /s /v ProfileImagePath 2^>nul ^| findstr /I "ProfileImagePath"') do call :AddHome "%%B"
if exist "%SystemDrive%\Users\" for /d %%D in ("%SystemDrive%\Users\*") do call :AddHome "%%~fD"
if defined USERPROFILE call :AddHome "%USERPROFILE%"
goto :eof

:AddHome
set "hh=%~1"
if not defined hh goto :eof
call set "hh=%%hh%%"
if not exist "%hh%\" goto :eof
for %%D in ("%hh%") do set "hh=%%~fD"
findstr /I /L /X /C:"%hh%" "%HOMES%" >nul 2>&1 && goto :eof
>>"%HOMES%" echo %hh%
goto :eof

:ScanHome
set "scanHome=%~1"
if not defined QUIET echo [*] Scanning %scanHome%
dir /b "%scanHome%" >nul 2>&1 || (call :Report DENIED "%scanHome%" ""& set /a nDenied+=1& goto :eof)
set /a nHomesScanned+=1

rem Report every Hidden/System item. Children merely under a hidden parent are
rem not tagged unless they carry Hidden/System themselves.
for /f "usebackq delims=" %%I in (`dir /s /b /a:h "%scanHome%" 2^>nul`) do call :ReportHidden "%%I"
for /f "usebackq delims=" %%I in (`dir /s /b /a:s "%scanHome%" 2^>nul`) do call :ReportHidden "%%I"

type nul >"%ERRORS%"
for /f "usebackq delims=" %%F in (`dir /s /b /a:-d-l "%scanHome%" 2^>"%ERRORS%"`) do call :HandleFile "%%F"
for %%E in ("%ERRORS%") do if %%~zE GTR 0 (
    call :Report DENIED "%scanHome%" "partial traversal error"
    set /a nDenied+=1
)
goto :eof

:ReportHidden
call :Report HIDDEN "%~1" ""
if "%REPORT_ADDED%"=="1" set /a nHidden+=1
goto :eof

:HandleFile
set "f=%~1"
if defined OUTPUTFILE if /I "%f%"=="%OUTPUTFILE%" goto :eof
set /a nFiles+=1
call :TypeTag "%f%"
if defined FILETAG call :Report %FILETAG% "%f%" ""
for %%Z in ("%f%") do set "fsize=%%~zZ"
if not defined fsize (call :Report DENIED "%f%" "cannot stat"& set /a nDenied+=1& goto :eof)
if %fsize% GTR %MAXBYTES% (
    call :Report "SKIP:size>%MAXMB%MB" "%f%" "%fsize% bytes"
    set /a nLarge+=1
    goto :eof
)
if %fsize% EQU 0 goto :eof
findstr /P /M /R "." "%f%" >nul 2>&1
if errorlevel 1 (
    call :Report SKIP:binary "%f%" ""
    set /a nBinary+=1
    goto :eof
)
set /a nText+=1
findstr /I /N /C:"-----BEGIN PRIVATE KEY-----" /C:"-----BEGIN RSA PRIVATE KEY-----" /C:"-----BEGIN OPENSSH PRIVATE KEY-----" /C:"PuTTY-User-Key-File-" "%f%" >"%TMPROOT%\keymatch.txt" 2>nul
for /f "usebackq tokens=1,* delims=:" %%A in ("%TMPROOT%\keymatch.txt") do call :AddKey "%f%" "%%A" "%%B"
findstr /I /N /G:"%PATTERNS%" "%f%" >"%TMPROOT%\highmatch.txt" 2>nul
for /f "usebackq tokens=1,* delims=:" %%A in ("%TMPROOT%\highmatch.txt") do call :AddHigh "%f%" "%%A" "%%B"
goto :eof

:AddKey
call :Report KEY "%~1:%~2" "private_key %~3"
if "%REPORT_ADDED%"=="1" set /a nKey+=1& set "EXITCODE=1"
goto :eof

:AddHigh
set "matchLine=%~3"
echo(!matchLine!| findstr /I /C:"example" /C:"sample" /C:"dummy" /C:"changeme" /C:"replace_me" /C:"your_password" /C:"redacted" /C:"masked" >nul 2>&1 && goto :eof
call :Report HIGH "%~1:%~2" "credential_match %matchLine%"
if "%REPORT_ADDED%"=="1" set /a nHigh+=1& set "EXITCODE=1"
goto :eof

:TypeTag
set "FILETAG="
for %%Z in ("%~1") do set "ext=%%~xZ"
for %%E in (.doc .docx .docm .dot .dotx .dotm .xls .xlsx .xlsm .xlsb .xlt .xltx .xltm .ppt .pptx .pptm .pot .potx .potm .pps .ppsx .ppsm .vsd .vsdx .pub .mdb .accdb) do if /I "%ext%"=="%%E" set "FILETAG=OFFICE"
for %%E in (.sql .ddl .dump .psql .pgsql .plsql .tsql .mdf .ndf .ldf .db .sqlite .sqlite3) do if /I "%ext%"=="%%E" set "FILETAG=SQL"
for %%E in (.zip .7z .rar .tar .tgz .gz .bz2 .xz .cab) do if /I "%ext%"=="%%E" set "FILETAG=ARCHIVE"
for %%E in (.kdbx .kdb .psafe3 .opvault .1pif .1pux .pfx .p12 .jks .keystore .keytab .ppk .pcap .pcapng .pem .key .priv .pvk) do if /I "%ext%"=="%%E" set "FILETAG=INTEREST"
goto :eof

:Report
set "REPORT_ADDED=0"
set "rTag=%~1"
set "rPath=%~2"
set "rDetail=%~3"
set "rKey=[%rTag%] %rPath%  %rDetail%"
findstr /L /X /C:"%rKey%" "%REPORTED%" >nul 2>&1 && goto :eof
>>"%REPORTED%" echo(!rKey!
echo(!rKey!
if defined OUTPUTFILE >>"%OUTPUTFILE%" echo(!rKey!
set "REPORT_ADDED=1"
goto :eof

:Summary
echo.
if defined OUTPUTFILE echo.>>"%OUTPUTFILE%"
call :Out "=== HomeHunter Summary ==="
call :Out "Homes discovered:       %nHomes%"
call :Out "Homes scanned:          %nHomesScanned%"
call :Out "Files enumerated:       %nFiles%"
call :Out "Text files scanned:     %nText%"
call :Out "Hidden items:           %nHidden%"
call :Out "Credential findings:    %nHigh%"
call :Out "Private-key findings:   %nKey%"
call :Out "Large files skipped:    %nLarge%"
call :Out "Binary files skipped:   %nBinary%"
call :Out "Permission denied:      %nDenied%"
goto :eof

:Out
echo(%~1
if defined OUTPUTFILE >>"%OUTPUTFILE%" echo(%~1
goto :eof

:Fatal
rd /s /q "%TMPROOT%" >nul 2>&1
exit /b 2
