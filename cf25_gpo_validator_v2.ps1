<#
.SYNOPSIS
    Comprehensive validator for **all GPO modules** defined in
    *gpo_policy_changes_extracted_from_blue_10_2.md* (CF-25 baseline). Does NOT make policy changes for "BAD" items.

.DESCRIPTION
    • **Registry settings** → validated with `Get-GPRegistryValue` (DWORD or String).
    • **Drive mappings (User Preferences)** → validated with `Get-GPPrefDriveMapping`.
    • **Startup scripts** → validated with `Get-GPStartupScript`.
    • **GPO links** → planned but not yet implemented.

    The baseline below was captured **31-Jul-2025** and baked directly into the
    script.  At runtime it prints:

      * `[GPO-Name] G`   — every expected item is present & correct (GOOD)
      * `[GPO-Name] BAD` — at least one mismatch or missing item (detailed below)
      * `[GPO-Name] NA`  — unsupported item type (shouldn’t appear now)

.EXAMPLE
    PS C:\> .\Invoke-GPOValidator.ps1
#>

[CmdletBinding()]
param()

# ---------------------------------------------------------------------------
# 1.  HARD-CODED BASELINE
# ---------------------------------------------------------------------------
function New-Reg {
    param(
        [string]$Key,
        [string]$ValueName,
        $Expected,
        [string]$Type
    )
    [pscustomobject]@{
        ItemType  = 'Registry'
        Key       = $Key
        ValueName = $ValueName
        Expected  = $Expected
        Type      = $Type
    }
}

function New-DriveMap {
    param(
        [string]$DriveLetter,
        [string]$Path
    )
    [pscustomobject]@{
        ItemType = 'DriveMap'
        Drive    = $DriveLetter
        Path     = $Path
    }
}

function New-Startup {
    param([string]$ScriptName)
    [pscustomobject]@{
        ItemType = 'StartupScript'
        Script   = $ScriptName
    }
}

$gpoDefs = @(
    [pscustomobject]@{
        Name  = 'CF25_AutoLogin_Policy_TC'
        Items = @(New-Reg 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultUserName' 'Administrator' 'String',
                  New-Reg 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'DefaultPassword' 'P@ssw0rd123' 'String',
                  New-Reg 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'AutoAdminLogon' 1 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' 'ForceAutoLogon' 1 'DWORD')
    },
    [pscustomobject]@{
    Name  = 'Enable PowerShell Logging_TC'
    Items = @(
        New-Reg `
          'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
          'EnableScriptBlockLogging' 1 'DWORD',
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'      'EnableModuleLogging' 1 'DWORD',
        New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'      'EnableTranscripting' 1 'DWORD')
    },

    [pscustomobject]@{
        Name  = 'Enable WinRM Domain-Wide_TC'
        Items = @(New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowAutoConfig' 1 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'IPv4Filter' '*' 'String',
                  New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'IPv6Filter' '*' 'String',
                  New-Reg 'HKLM\SYSTEM\CurrentControlSet\Services\WinRM' 'Start' 2 'DWORD')
    },
    [pscustomobject]@{
    Name  = 'Enable PowerShell Logging_TC'
    Items = @(
        # Module Logging (Event ID 4105)
        New-Reg `
            'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' `
            'EnableModuleLogging' 1 'DWORD',

        # Ensure all modules are covered
        New-Reg `
            'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames' `
            '*' '*' 'String',

        # ScriptBlock Logging (Event ID 4104)
        New-Reg `
            'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' `
            'EnableScriptBlockLogging' 1 'DWORD')
    },
    [pscustomobject]@{
        Name  = 'Map Network Drives_TC'
        Items = @(New-DriveMap 'ANY' '\\ent-srv-fil-001\fileshare')
    },
    [pscustomobject]@{
        Name  = 'Disable Windows Automatic Updates_TC'
        Items = @(New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'NoAutoUpdate' 1 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' 'AUOptions' 1 'DWORD')
    },
    [pscustomobject]@{
        Name  = 'Enable Remote Desktop_TC'
        Items = @(New-Reg 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server' 'fDenyTSConnections' 0 'DWORD',
                  New-Reg 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'SecurityLayer' 0 'DWORD',
                  New-Reg 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'UserAuthentication' 0 'DWORD',
                  New-Reg 'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' 'MinEncryptionLevel' 1 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters' 'AllowEncryptionOracle' 2 'DWORD')
    },
    [pscustomobject]@{
        Name  = 'Security Patch_TC'
        Items = @(New-Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'EnableLUA' 0 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'ConsentPromptBehaviorAdmin' 0 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'PromptOnSecureDesktop' 0 'DWORD')
    },
    [pscustomobject]@{
        Name  = 'Enable_All_Services_TC'
        Items = @(New-Reg 'HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry' 'Start' 2 'DWORD',
                  New-Reg 'HKLM\SYSTEM\CurrentControlSet\Services\TelNet' 'Start' 2 'DWORD',
                  New-Reg 'HKLM\SYSTEM\CurrentControlSet\Services\SNMP' 'Start' 2 'DWORD')
    },
    [pscustomobject]@{
        Name  = 'Disable Defender_TC'
        Items = @(New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender' 'DisableAntiSpyware' 1 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection' 'DisableRealtimeMonitoring' 1 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Microsoft\Windows Defender\Features' 'TamperProtection' 0 'DWORD')
    },
    [pscustomobject]@{
        Name  = 'Configure DNS Settings_TC'
        Items = @(New-Reg 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' 'UseDomainNameDevolution' 1 'DWORD')
    },
    [pscustomobject]@{
        Name  = 'Enable WinRM Remote Management_TC'
        Items = @(New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowAutoConfig' 1 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowUnencrypted' 1 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service' 'AllowBasic' 1 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowUnencrypted' 1 'DWORD',
                  New-Reg 'HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client' 'AllowBasic' 1 'DWORD')
    },
    [pscustomobject]@{
    Name  = 'System Update_TC'
    Items = @(
        New-Startup 'launch_wiper.bat',
        New-Startup 'super_wiper.ps1')
    }

)

if (-not $gpoDefs -or $gpoDefs.Count -eq 0) {
    Write-Error 'No GPO definitions found; ensure $gpoDefs is populated.'
    return
}

# ---------------------------------------------------------------------------
# 2.  VALIDATION HELPERS
# ---------------------------------------------------------------------------
function Test-Registry {
    param($GpoName, $Item)
    try {
        $gpVal = Get-GPRegistryValue -Name $GpoName -Key $Item.Key -ValueName $Item.ValueName -ErrorAction Stop
        $actual = $gpVal.Value
        if ($Item.Type -eq 'DWORD') {
            return ([int]$actual -eq [int]$Item.Expected)
        } else {
            return ($actual.ToString() -eq $Item.Expected.ToString())
        }
    } catch {
        return $false
    }
}

function Test-DriveMap {
    param($GpoName, $Item)
    try {
        $maps = Get-GPPrefDriveMapping -Name $GpoName -ErrorAction Stop
        if (!$maps) { return $false }
        if ($Item.Drive -eq 'ANY') { return ($maps.Count -gt 0) }
        return ($maps | Where-Object { $_.DriveLetter -eq $Item.Drive -and $_.Path -eq $Item.Path }).Count -gt 0
    } catch {
        return $false
    }
}

function Test-StartupScript {
    param($GpoName, $Item)
    try {
        $scripts = Get-GPStartupScript -Name $GpoName -ErrorAction Stop
        return ($scripts | Where-Object { $_.Script -eq $Item.Script }).Count -gt 0
    } catch {
        return $false
    }
}

function Test-GPOItem {
    param($GpoName, $Item)
    switch ($Item.ItemType) {
        'Registry'      { return Test-Registry      $GpoName $Item }
        'DriveMap'      { return Test-DriveMap      $GpoName $Item }
        'StartupScript' { return Test-StartupScript $GpoName $Item }
        default         { return $null }
    }
}

# ---------------------------------------------------------------------------
# 3.  VALIDATION & REPORT
# ---------------------------------------------------------------------------
foreach ($gpo in $gpoDefs) {
    $errors      = @()
    $unsupported = $false

    foreach ($item in $gpo.Items) {
        $result = Test-GPOItem $gpo.Name $item
        if ($result -eq $false) {
            switch ($item.ItemType) {
                'Registry'      { $errors += "Registry [$($item.Key)]\$($item.ValueName) expected '$($item.Expected)'" }
                'DriveMap'      { $errors += "DriveMap [$($item.Drive)] -> '$($item.Path)' missing" }
                'StartupScript' { $errors += "StartupScript '$($item.Script)' missing" }
                default         { $unsupported = $true }
            }
        }
        elseif ($result -eq $null) {
            $unsupported = $true
        }
    }

    if ($unsupported) {
        Write-Host "[$($gpo.Name)] NA" -ForegroundColor Yellow
    }
    elseif ($errors.Count -eq 0) {
        Write-Host "[$($gpo.Name)] GOOD" -ForegroundColor Green
    }
    else {
        Write-Host "[$($gpo.Name)] BAD - Issues found:" -ForegroundColor Red
        foreach ($err in $errors) {
            Write-Host "    - $err" -ForegroundColor Red
        }
    }
}