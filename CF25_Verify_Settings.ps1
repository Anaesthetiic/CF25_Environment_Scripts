# CF25_Verify_Settings.ps1
function Test-RegValue {
    param($Path, $Name, $ExpectedValue, $Description)
    try {
        $actual = (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name
        if ($actual -eq $ExpectedValue) {
            Write-Host "[PASS] $Description - Value: $actual" -ForegroundColor Green
        } else {
            Write-Host "[FAIL] $Description - Expected: $ExpectedValue, Got: $actual" -ForegroundColor Red
        }
    } catch {
        Write-Host "[MISS] $Description - Registry key not found" -ForegroundColor Yellow
    }
}

Write-Host "=== CF25 GPO Settings Verification ===" -ForegroundColor Cyan

# AutoLogin Settings
Test-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -ExpectedValue 1 -Description "Auto Admin Logon"
Test-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -ExpectedValue "Administrator" -Description "Default Username"
Test-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "ForceAutoLogon" -ExpectedValue 1 -Description "Force Auto Logon"

# WinRM Settings
Test-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowAutoConfig" -ExpectedValue 1 -Description "WinRM Auto Config"
Test-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowBasic" -ExpectedValue 1 -Description "WinRM Basic Auth"
Test-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -Name "AllowUnencrypted" -ExpectedValue 1 -Description "WinRM Unencrypted"

# PowerShell Logging
Test-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Name "Enable" -ExpectedValue 1 -Description "PowerShell Script Block Logging"
Test-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -Name "Enable" -ExpectedValue 1 -Description "PowerShell Module Logging"

# Windows Updates
Test-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -Name "NoAutoUpdate" -ExpectedValue 1 -Description "Disable Auto Updates"

# Remote Desktop
Test-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ExpectedValue 0 -Description "Enable Remote Desktop"

# UAC Settings
Test-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -ExpectedValue 0 -Description "Disable UAC"
Test-RegValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -ExpectedValue 0 -Description "UAC Admin Prompt Behavior"

# Defender
Test-RegValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" -Name "DisableAntiSpyware" -ExpectedValue 1 -Description "Disable Defender Anti-Spyware"

# Services
Test-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM" -Name "Start" -ExpectedValue 2 -Description "WinRM Service Start Mode"
Test-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -Name "Start" -ExpectedValue 2 -Description "Remote Registry Service"
Test-RegValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" -Name "Start" -ExpectedValue 2 -Description "SNMP Service"

Write-Host "=== Verification Complete ===" -ForegroundColor Cyan
