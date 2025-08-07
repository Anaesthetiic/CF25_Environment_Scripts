<# --------------------------------------------------------------------------------------------------------------------
  CF25_BRUTE_FORCE_GPOs.ps1
  Brute-force registry implementation compatible with older PowerShell versions for Cyber Fortress 2025
  Author:  Jacob Heusuk
  Usage :  .\CF25_BRUTE_FORCE_GPOs_FIXED.ps1
  NOTE  :  Must be run with local Administrator rights.
--------------------------------------------------------------------------------------------------------------------#>

# region  >>> Utility helpers <<<

$LogFile = 'C:\CF25_GPO_Deploy.log'
Start-Transcript -Path $LogFile -Append | Out-Null

function Write-Info   { param($m) ; Write-Host "[INFO ] $m"  -ForegroundColor Cyan   }
function Write-Good   { param($m) ; Write-Host "[PASS ] $m"  -ForegroundColor Green  }
function Write-Warn   { param($m) ; Write-Host "[WARN ] $m"  -ForegroundColor Yellow }
function Write-ErrorX { param($m) ; Write-Host "[FAIL ] $m"  -ForegroundColor Red    ; Stop-Transcript ; throw $m }

function Set-RegValue {
    param(
        [string]$Root,        # e.g. HKLM
        [string]$Path,        # sub-key
        [string]$Name,
        [ValidateSet('String','DWORD','QWORD')]$Type,
        [Object]$Value
    )

    $full = "$Root`:$Path"
    try {
        if (-not (Test-Path $full)) { 
            New-Item -Path $full -Force | Out-Null 
        }
        
        # Use older compatible syntax without -Type parameter
        switch ($Type) {
            'String' { 
                Set-ItemProperty -Path $full -Name $Name -Value ([string]$Value)
            }
            'DWORD'  { 
                New-ItemProperty -Path $full -Name $Name -Value ([int]$Value) -PropertyType DWord -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $full -Name $Name -Value ([int]$Value)
            }
            'QWORD'  { 
                New-ItemProperty -Path $full -Name $Name -Value ([long]$Value) -PropertyType QWord -Force -ErrorAction SilentlyContinue
                Set-ItemProperty -Path $full -Name $Name -Value ([long]$Value)
            }
        }
    } catch { 
        Write-ErrorX "Could not set $full\$Name : $_" 
    }

    # --- Verify ---
    try {
        $readBack = (Get-ItemProperty -Path $full -Name $Name -ErrorAction Stop).$Name
        if ($readBack.ToString() -ne $Value.ToString()) {
            Write-ErrorX "Verification failed for $full\$Name (expected '$Value' got '$readBack')"
        } else {
            Write-Good "$full\$Name = $Value ($Type)"
        }
    } catch { 
        Write-ErrorX "Verification read failed for $full\$Name : $_" 
    }
}

function Set-ServiceStartMode {
    param(
        [string]$ServiceName,
        [int]   $StartValue    # 2 = Automatic
    )
    $regKey = "SYSTEM\CurrentControlSet\Services\$ServiceName"
    Set-RegValue -Root 'HKLM' -Path $regKey -Name 'Start' -Type DWORD -Value $StartValue
}

# endregion

Write-Info "CF25 brute-force GPO deployment started on $env:COMPUTERNAME"

# region  >>> 1. Auto-login policy <<<
Write-Info "Applying AutoLogin settings"
Set-RegValue -Root HKLM -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultUserName'     -Type String -Value 'Administrator'
Set-RegValue -Root HKLM -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'DefaultPassword'     -Type String -Value 'P@ssw0rd123'
Set-RegValue -Root HKLM -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoAdminLogon'      -Type DWORD  -Value 1
Set-RegValue -Root HKLM -Path 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'ForceAutoLogon'      -Type DWORD  -Value 1
# endregion

# region  >>> 2. Enable PowerShell Remoting <<<
Write-Info "Enabling basic/unprotected WinRM (PowerShell remoting)"
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowAutoConfig' -Type DWORD -Value 1
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowBasic'     -Type DWORD -Value 1
Set-RegValue -Root HKLM -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service' -Name 'allow_unencrypted' -Type DWORD -Value 1
# endregion

# region  >>> 3. Enable WinRM domain-wide filters <<<
Write-Info "Opening WinRM to all addresses"
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'IPv4Filter' -Type String -Value '*'
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'IPv6Filter' -Type String -Value '*'
Set-RegValue -Root HKLM -Path 'SYSTEM\CurrentControlSet\Services\WinRM'            -Name 'Start'      -Type DWORD  -Value 2
# endregion

# region  >>> 4. Enable PowerShell logging <<<
Write-Info "Turning on extensive PowerShell logging"
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name 'Enable' -Type DWORD -Value 1
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'      -Name 'Enable' -Type DWORD -Value 1
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'      -Name 'Enable' -Type DWORD -Value 1
# endregion

# region  >>> 5. Disable automatic updates <<<
Write-Info "Disabling Windows Update AU"
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'NoAutoUpdate' -Type DWORD -Value 1
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name 'AUOptions'    -Type DWORD -Value 1
# endregion

# region  >>> 6. Enable (vulnerable) Remote Desktop <<<
Write-Info "Enabling Remote Desktop with weak security for exercise"
Set-RegValue -Root HKLM -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server'                              -Name 'fDenyTSConnections' -Type DWORD -Value 0
Set-RegValue -Root HKLM -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'         -Name 'SecurityLayer'      -Type DWORD -Value 0
Set-RegValue -Root HKLM -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'         -Name 'UserAuthentication' -Type DWORD -Value 0
Set-RegValue -Root HKLM -Path 'SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'         -Name 'MinEncryptionLevel' -Type DWORD -Value 1
Set-RegValue -Root HKLM -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' -Name 'AllowEncryptionOracle' -Type DWORD -Value 2
# endregion

# region  >>> 7. "Security Patch" that actually weakens UAC <<<
Write-Info "Weakening local UAC (exercise requirement)"
Set-RegValue -Root HKLM -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA'               -Type DWORD -Value 0
Set-RegValue -Root HKLM -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'ConsentPromptBehaviorAdmin' -Type DWORD -Value 0
Set-RegValue -Root HKLM -Path 'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'PromptOnSecureDesktop'      -Type DWORD -Value 0
# endregion

# region  >>> 8. Enable exploitable services <<<
Write-Info "Setting service start to Automatic for RemoteRegistry, Telnet, SNMP"
Set-ServiceStartMode -ServiceName 'RemoteRegistry' -StartValue 2
Set-ServiceStartMode -ServiceName 'Telnet'         -StartValue 2
Set-ServiceStartMode -ServiceName 'SNMP'           -StartValue 2
# endregion

# region  >>> 9. Disable Microsoft Defender <<<
Write-Info "Disabling Defender real-time protection"
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows Defender'                              -Name 'DisableAntiSpyware'      -Type DWORD -Value 1
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection'         -Name 'DisableRealtimeMonitoring' -Type DWORD -Value 1
Set-RegValue -Root HKLM -Path 'SOFTWARE\Microsoft\Windows Defender\Features'                              -Name 'TamperProtection'        -Type DWORD -Value 0
# endregion

# region  >>> 10. Configure DNS client <<<
Write-Info "Configuring DNS devolution"
Set-RegValue -Root HKLM -Path 'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'UseDomainNameDevolution' -Type DWORD -Value 1
# endregion

# region  >>> 11. Additional WinRM client/service tweaks <<<
Write-Info "Allowing unencrypted/basic auth for WinRM client as well"
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' -Name 'AllowUnencrypted' -Type DWORD -Value 1
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'  -Name 'AllowUnencrypted' -Type DWORD -Value 1
Set-RegValue -Root HKLM -Path 'SOFTWARE\Policies\Microsoft\Windows\WinRM\Client'  -Name 'AllowBasic'       -Type DWORD -Value 1
# endregion

# region  >>> 12. System Update GPO stub <<<
Write-Info "System Update GPO (registry portion) – no scripts pushed here"
# (Placeholder – startup scripts must still be copied manually)
# endregion

# region  >>> Final verification of critical keys <<<
Write-Info "Running final verification sweep"
$critical = @(
 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon::AutoAdminLogon',
 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service::AllowAutoConfig',
 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging::Enable',
 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU::NoAutoUpdate',
 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server::fDenyTSConnections'
)

foreach ($item in $critical) {
    $split = $item -split '::'
    try {
        $val = (Get-ItemProperty -Path $split[0] -Name $split[1] -ErrorAction Stop).$($split[1])
        Write-Good "$item = $val   (verified final sweep)"
    } catch {
        Write-Warn "Could not verify $item - may not exist yet"
    }
}
# endregion

Write-Info  "All requested registry settings applied and verified."
Write-Info  "Log file saved to: $LogFile"
Stop-Transcript
