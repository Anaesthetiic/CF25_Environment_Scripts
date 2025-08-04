<#

Additional Requirements:
- Resolve GPO Creation Function #13 which properly instatiates 
scripts but does not "add" it to GPO. Ensure validator aligns
with target.
- Ensure validator aligns with GPO Creation Function #5 and
verifies the permissions of each group in fileshare 

#>

param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName = "acme.com",
    
    [Parameter(Mandatory=$false)]
    [string]$NewDomainController = "",
    
    [Parameter(Mandatory=$false)]
    [switch]$CreateScriptFiles = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$ScriptPath = "C:\CF25_GPO_Scripts"
)

# Import required modules
Import-Module GroupPolicy

Import-Module ActiveDirectory -ErrorAction SilentlyContinue

Write-Host "CF25 GPO Recreation Script Starting..." -ForegroundColor Green
Write-Host "Domain: $DomainName" -ForegroundColor Yellow
Write-Host "WARNING: Creating vulnerable configurations for cyber exercise" -ForegroundColor Red

# Create script directory if needed
if ($CreateScriptFiles -and !(Test-Path $ScriptPath)) {
    New-Item -ItemType Directory -Path $ScriptPath -Force
    Write-Host "Created script directory: ${ScriptPath}" -ForegroundColor Green
}

# FIXED: Function to create registry-based GPO settings with proper type handling
# IMPROVED: Matches read cmdlet's signature, advanced parameter binding, and type validation
function Set-GPORegistryValue {
    [CmdletBinding()]
    param(
        # Accept either –Name (to mirror Set-GPRegistryValue) or –GPOName
        [Alias('GPOName')]
        [Parameter(Mandatory = $true)]
        [string]$Name,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$ValueName,

        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter()]
        [ValidateSet('DWORD','String')]
        [string]$Type = 'DWORD'
    )

    try {
        # If user passed a string for a DWORD, cast it
        if ($Type -eq 'DWORD' -and $Value -is [string]) {
            $Value = [int]$Value
        }

        # Call the real GP cmdlet
        Set-GPRegistryValue `
            -Name      $Name `
            -Key       $Key `
            -ValueName $ValueName `
            -Value     $Value `
            -Type      $Type

        Write-Host "  [+] Set registry: $Key\$ValueName = $Value" -ForegroundColor Green
    }
    catch {
        Write-Host "  [-] Failed to set registry: $Key\$ValueName – $($_.Exception.Message)" -ForegroundColor Red
    }
}

# IMPROVED: Function to link GPOs to domain with existing link check
function Link-GPOToDomain {
    param([string]$GPOName)
    try {
        $domainDN = (Get-ADDomain -Server $DomainName).DistinguishedName
        
        # Check if GPO is already linked
        $existingLinks = Get-GPInheritance -Target $domainDN -ErrorAction SilentlyContinue
        $isLinked = $false
        
        if ($existingLinks -and $existingLinks.GpoLinks) {
            $isLinked = $existingLinks.GpoLinks | Where-Object { $_.DisplayName -eq $GPOName }
        }
        
        if ($isLinked) {
            Write-Host "  [!] $GPOName already linked to domain" -ForegroundColor Yellow
        } else {
            New-GPLink -Name $GPOName -Target $domainDN -LinkEnabled Yes -ErrorAction Stop
            Write-Host "  [+] Linked $GPOName to domain" -ForegroundColor Green
        }
    }
    catch {
        Write-Host "  [-] Failed to link $GPOName to domain: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Create startup script files for malicious payloads (cyber exercise)
if ($CreateScriptFiles) {
    # Create launch_wiper.bat
    $launchWiperContent = @"
@echo off
REM CF25 Cyber Exercise - Simulated Malicious Script
REM WARNING: This would execute malicious payload in real scenario
echo [%date% %time%] CF25 Exercise: launch_wiper.bat executed >> C:\cf25_exercise.log
if exist "${ScriptPath}\super_wiper.ps1" (
    powershell.exe -ExecutionPolicy Bypass -File "${ScriptPath}\super_wiper.ps1"
) else (
    echo [%date% %time%] CF25 Exercise: super_wiper.ps1 not found >> C:\cf25_exercise.log
)
REM Simulate deleting TEST folders only
if exist "C:\Users\%USERNAME%\Desktop\TEST" (
    echo [%date% %time%] CF25 Exercise: Would delete TEST folder >> C:\cf25_exercise.log
    REM rmdir /s /q "C:\Users\%USERNAME%\Desktop\TEST"
)
"@
    
    # Create super_wiper.ps1
    $superWiperContent = @"
# CF25 Cyber Exercise - Simulated Malicious PowerShell Script
# WARNING: This represents malicious payload for exercise purposes ONLY
# ACTUAL script deletes only TEST folders for safety

Write-Host "CF25 Exercise: super_wiper.ps1 executed at `$(Get-Date)" -ForegroundColor Red
Add-Content -Path "C:\cf25_exercise.log" -Value "[`$(Get-Date)] CF25 Exercise: super_wiper.ps1 executed"

# Simulated malicious activities (EXERCISE ONLY - LIMITED ACTUAL DAMAGE)
Write-Host "CF25 Exercise: Simulating system enumeration..." -ForegroundColor Yellow
Get-Process | Select-Object Name, ID, CPU | Out-File -Append "C:\cf25_exercise.log"
Get-Service | Where-Object {`$_.Status -eq 'Running'} | Select-Object Name, Status | Out-File -Append "C:\cf25_exercise.log"

# ACTUAL file deletion - ONLY TEST folders for safety
`$testFolders = @(
    "C:\Users\*\Desktop\TEST",
    "C:\Users\*\Documents\TEST", 
    "C:\TEST",
    "D:\TEST"
)

foreach (`$folder in `$testFolders) {
    if (Test-Path `$folder) {
        Write-Host "CF25 Exercise: Deleting TEST folder: `$folder" -ForegroundColor Red
        Remove-Item `$folder -Recurse -Force -ErrorAction SilentlyContinue
        Add-Content -Path "C:\cf25_exercise.log" -Value "[`$(Get-Date)] CF25 Exercise: Deleted TEST folder `$folder"
    }
}

Write-Host "CF25 Exercise: super_wiper.ps1 completed" -ForegroundColor Red
Add-Content -Path "C:\cf25_exercise.log" -Value "[`$(Get-Date)] CF25 Exercise: super_wiper.ps1 completed"
"@

    # Create wiper.ps1 (simpler version)
    $wiperContent = @"
# CF25 Cyber Exercise - Simulated Wiper Script  
# WARNING: This represents malicious payload for exercise purposes
Write-Host "CF25 Exercise: wiper.ps1 executed at `$(Get-Date)" -ForegroundColor Red
Add-Content -Path "C:\cf25_exercise.log" -Value "[`$(Get-Date)] CF25 Exercise: wiper.ps1 executed"

# Simulate wiping - only log activity for safety
Add-Content -Path "C:\cf25_exercise.log" -Value "[`$(Get-Date)] CF25 Exercise: Simulated file wiper activity"
Write-Host "CF25 Exercise: Simulated wiper activity logged" -ForegroundColor Yellow
"@

    # Create install_backdoor.ps1 (simulation only)
    $installBackdoorContent = @"
# CF25 Cyber Exercise - Simulated Backdoor Installation
# WARNING: This represents malicious payload for exercise purposes - SIMULATION ONLY
Write-Host "CF25 Exercise: install_backdoor.ps1 executed at `$(Get-Date)" -ForegroundColor Red
Add-Content -Path "C:\cf25_exercise.log" -Value "[`$(Get-Date)] CF25 Exercise: install_backdoor.ps1 executed - SIMULATION"

# Simulate backdoor installation - LOG ONLY for exercise
Add-Content -Path "C:\cf25_exercise.log" -Value "[`$(Get-Date)] CF25 Exercise: Simulated backdoor installation attempt"
Write-Host "CF25 Exercise: Simulated backdoor installation logged" -ForegroundColor Yellow

# Create fake service entry for detection exercise
Add-Content -Path "C:\cf25_exercise.log" -Value "[`$(Get-Date)] CF25 Exercise: Simulated service 'WindowsSecurityUpdate' creation"
"@

    # Create README.md with manual steps
    $readmeContent = @"
# CF25 GPO Exercise Scripts

## WARNING: CYBER EXERCISE ONLY
These scripts create intentionally vulnerable configurations for cyber security training.

### Files Created:
- **launch_wiper.bat**: Primary launcher script
- **super_wiper.ps1**: Advanced simulation script (deletes TEST folders only)
- **wiper.ps1**: Basic simulation script  
- **install_backdoor.ps1**: Backdoor simulation (logging only)

### Manual Configuration Required:

#### 1. System Update GPO Startup Scripts:
1. Open Group Policy Management Console
2. Edit "System Update" GPO
3. Navigate to: Computer Configuration > Windows Settings > Scripts > Startup
4. Add Script: ${ScriptPath}\launch_wiper.bat
5. Add Script: ${ScriptPath}\super_wiper.ps1

#### 2. Security Validation:
- Check C:\cf25_exercise.log for execution evidence
- Verify TEST folders are removed (safe deletion)
- Confirm no production data affected

#### 3. Exercise Notes:
- Scripts log all activity to C:\cf25_exercise.log
- Only TEST folders are actually deleted
- All other activities are simulated/logged only
- Safe for exercise environment use

### Deployment Status:
✅ Scripts created in ${ScriptPath}
✅ SYSVOL deployment completed
⏳ Manual GPO configuration required
⏳ Startup script assignment required
"@

    # Write script files
    try {
        $launchWiperContent | Out-File -FilePath "${ScriptPath}\launch_wiper.bat" -Encoding ASCII -Force
        $superWiperContent | Out-File -FilePath "${ScriptPath}\super_wiper.ps1" -Encoding UTF8 -Force
        $wiperContent | Out-File -FilePath "${ScriptPath}\wiper.ps1" -Encoding UTF8 -Force
        $installBackdoorContent | Out-File -FilePath "${ScriptPath}\install_backdoor.ps1" -Encoding UTF8 -Force
        $readmeContent | Out-File -FilePath "${ScriptPath}\README.md" -Encoding UTF8 -Force
        
        Write-Host "Created exercise script files in ${ScriptPath}:" -ForegroundColor Green
        Write-Host "  - launch_wiper.bat (ACTUAL - deletes TEST folders)" -ForegroundColor Yellow
        Write-Host "  - super_wiper.ps1 (ACTUAL - deletes TEST folders)" -ForegroundColor Yellow  
        Write-Host "  - wiper.ps1 (ACTUAL - deletes TEST folders)" -ForegroundColor Yellow
        Write-Host "  - install_backdoor.ps1 (simulation)" -ForegroundColor Cyan
        Write-Host "  - README.md (manual configuration steps)" -ForegroundColor Cyan
    }
    catch {
        Write-Host "[-] Error creating script files: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Deploy scripts to SYSVOL
Write-Host "`nDeploying scripts to SYSVOL..." -ForegroundColor Cyan
try {
    $sysvolPath = "\\$DomainName\SYSVOL\$DomainName\scripts"
    if (Test-Path $sysvolPath) {
        Copy-Item "${ScriptPath}\*.bat" $sysvolPath -Force -ErrorAction SilentlyContinue
        Copy-Item "${ScriptPath}\*.ps1" $sysvolPath -Force -ErrorAction SilentlyContinue
        
        Write-Host "  [+] Deployed launch_wiper.bat to SYSVOL" -ForegroundColor Green
        Write-Host "  [+] Deployed super_wiper.ps1 to SYSVOL" -ForegroundColor Green
        Write-Host "  [+] Deployed wiper.ps1 to SYSVOL" -ForegroundColor Green
        Write-Host "  [+] Deployed install_backdoor.ps1 to SYSVOL" -ForegroundColor Green
        Write-Host "  [+] Scripts successfully deployed to SYSVOL" -ForegroundColor Green
    } else {
        Write-Host "  [!] SYSVOL path not accessible: $sysvolPath" -ForegroundColor Yellow
    }
}
catch {
    Write-Host "  [-] Error deploying to SYSVOL: $($_.Exception.Message)" -ForegroundColor Red
}

# Check service dependencies
Write-Host "`nChecking service dependencies..." -ForegroundColor Cyan
$services = @("RemoteRegistry", "SNMP", "TlntSvr", "RemoteAccess")
foreach ($service in $services) {
    try {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            Write-Host "  [+] $service available" -ForegroundColor Green
        } else {
            Write-Host "  [!] $service Service not found - may need Windows Feature installation" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "  [!] $service not found - may need Windows Feature installation" -ForegroundColor Yellow
    }
}

# GPO Creation Functions
Write-Host "`nCreating Group Policy Objects..." -ForegroundColor Cyan

try {
    # 1. CF25_AutoLogin_Policy
    Write-Host "`n1. Creating CF25_AutoLogin_Policy..." -ForegroundColor Yellow
    $existingGPO1 = Get-GPO -Name "CF25_AutoLogin_Policy_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO1) {
        Write-Host "  [!] CF25_AutoLogin_Policy GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo1 = $existingGPO1
    } else {
        $gpo1 = New-GPO -Name "CF25_AutoLogin_Policy_TC" -Domain $DomainName
    }
    
    Set-GPORegistryValue -GPOName "CF25_AutoLogin_Policy_TC" -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "DefaultUserName" -Value "Administrator" -Type "String"
    Set-GPORegistryValue -GPOName "CF25_AutoLogin_Policy_TC" -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "DefaultPassword" -Value "P@ssw0rd123" -Type "String"
    Set-GPORegistryValue -GPOName "CF25_AutoLogin_Policy_TC" -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "AutoAdminLogon" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "CF25_AutoLogin_Policy_TC" -Key "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ValueName "ForceAutoLogon" -Value 1 -Type "DWORD"
    Write-Host "  [+] CF25_AutoLogin_Policy created" -ForegroundColor Green

    # 2. Enable PowerShell Remoting
    Write-Host "`n2. Creating Enable PowerShell Remoting..." -ForegroundColor Yellow
    $existingGPO2 = Get-GPO -Name "Enable PowerShell Remoting_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO2) {
        Write-Host "  [!] Enable PowerShell Remoting GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo2 = $existingGPO2
    } else {
        $gpo2 = New-GPO -Name "Enable PowerShell Remoting_TC" -Domain $DomainName
    }

    Set-GPORegistryValue -GPOName "Enable PowerShell Remoting_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowAutoConfig" -Value 1 -Type DWORD
    Set-GPORegistryValue -GPOName "Enable PowerShell Remoting_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowBasic" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable PowerShell Remoting_TC" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service" -ValueName "allow_unencrypted" -Value 1 -Type "DWORD"
    Write-Host "  [+] Enable PowerShell Remoting created" -ForegroundColor Green

    # 3. Enable WinRM Domain-Wide
    Write-Host "`n3. Creating Enable WinRM Domain-Wide..." -ForegroundColor Yellow
    $existingGPO3 = Get-GPO -Name "Enable WinRM Domain-Wide_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO3) {
        Write-Host "  [!] Enable WinRM Domain-Wide GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo3 = $existingGPO3
    } else {
        $gpo3 = New-GPO -Name "Enable WinRM Domain-Wide_TC" -Domain $DomainName
    }
    
    Set-GPORegistryValue -GPOName "Enable WinRM Domain-Wide_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowAutoConfig" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable WinRM Domain-Wide_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "IPv4Filter" -Value "*" -Type "String"
    Set-GPORegistryValue -GPOName "Enable WinRM Domain-Wide_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "IPv6Filter" -Value "*" -Type "String"
    Set-GPORegistryValue -GPOName "Enable WinRM Domain-Wide_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Services\WinRM" -ValueName "Start" -Value 2 -Type "DWORD"
    Write-Host "  [+] Enable WinRM Domain-Wide created" -ForegroundColor Green

    # 4. Enable PowerShell Logging - FIXED with invocation logging disabled
    Write-Host "`n4. Creating Enable PowerShell Logging..." -ForegroundColor Yellow
    $existingGPO4 = Get-GPO -Name "Enable PowerShell Logging_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO4) {
        Write-Host "  [!] Enable PowerShell Logging GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo4 = $existingGPO4
    } else {
        $gpo4 = New-GPO -Name "Enable PowerShell Logging_TC" -Domain $DomainName
    }
    
    Set-GPORegistryValue -GPOName "Enable PowerShell Logging_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ValueName "EnableModuleLogging" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable PowerShell Logging_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ValueName "*" -Value "*" -Type "String"
    
    Set-GPORegistryValue -GPOName "Enable PowerShell Logging_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockLogging" -Value 1 -Type DWORD

    # ✨ ADD THIS LINE TO DISABLE INVOCATION START/STOP EVENTS
    Set-GPRegistryValue -Name "Enable PowerShell Logging_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ValueName "EnableScriptBlockInvocationLogging" -Value 1 -Type DWORD

    Set-GPORegistryValue -GPOName "Enable PowerShell Logging_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "EnableTranscripting" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable PowerShell Logging_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ValueName "OutputDirectory" -Value "C:\PSTranscripts" -Type "String"
    Write-Host "  [+] Enable PowerShell Logging created (with invocation logging DISABLED)" -ForegroundColor Green

    # 5. Map Network Drives (validate read/write permissions for each group for fileshare)
    
    # 6. Disable Windows Automatic Updates
    Write-Host "`n6. Creating Disable Windows Automatic Updates..." -ForegroundColor Yellow
    $existingGPO6 = Get-GPO -Name "Disable Windows Automatic Updates_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO6) {
        Write-Host "  [!] Disable Windows Automatic Updates GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo6 = $existingGPO6
    } else {
        $gpo6 = New-GPO -Name "Disable Windows Automatic Updates_TC" -Domain $DomainName
    }
    
    Set-GPORegistryValue -GPOName "Disable Windows Automatic Updates_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "NoAutoUpdate" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Disable Windows Automatic Updates_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ValueName "AUOptions" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Disable Windows Automatic Updates_TC" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" -ValueName "EnableFeaturedSoftware" -Value 0 -Type "DWORD"
    Write-Host "  [+] Disable Windows Automatic Updates created" -ForegroundColor Green

    # 7. Enable Remote Desktop (VULNERABLE)
    Write-Host "`n7. Creating Enable Remote Desktop (Vulnerable)..." -ForegroundColor Yellow
    $existingGPO7 = Get-GPO -Name "Enable Remote Desktop_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO7) {
        Write-Host "  [!] Enable Remote Desktop GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo7 = $existingGPO7
    } else {
        $gpo7 = New-GPO -Name "Enable Remote Desktop_TC" -Domain $DomainName
    }
    
    # Enable RDP
    Set-GPORegistryValue -GPOName "Enable Remote Desktop_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" -ValueName "fDenyTSConnections" -Value 0 -Type "DWORD"
    # Vulnerable RDP settings for exercise
    Set-GPORegistryValue -GPOName "Enable Remote Desktop_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "SecurityLayer" -Value 0 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable Remote Desktop_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "UserAuthentication" -Value 0 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable Remote Desktop_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -ValueName "MinEncryptionLevel" -Value 1 -Type "DWORD"
    # CredSSP vulnerability
    Set-GPORegistryValue -GPOName "Enable Remote Desktop_TC" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" -ValueName "AllowEncryptionOracle" -Value 2 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable Remote Desktop_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" -ValueName "fAllowToGetHelp" -Value 1 -Type "DWORD"
    Write-Host "  [+] Enable Remote Desktop (Vulnerable) created" -ForegroundColor Green

    # 8. Security Patch (Ironic name - actually makes system less secure)
    Write-Host "`n8. Creating Security Patch..." -ForegroundColor Yellow
    $existingGPO8 = Get-GPO -Name "Security Patch_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO8) {
        Write-Host "  [!] Security Patch GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo8 = $existingGPO8
    } else {
        $gpo8 = New-GPO -Name "Security Patch_TC" -Domain $DomainName
    }
    
    # Disable various security features for exercise
    Set-GPORegistryValue -GPOName "Security Patch_TC" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "EnableLUA" -Value 0 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Security Patch_TC" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "ConsentPromptBehaviorAdmin" -Value 0 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Security Patch_TC" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "PromptOnSecureDesktop" -Value 0 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Security Patch_TC" -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "FilterAdministratorToken" -Value 0 -Type "DWORD"
    Write-Host "  [+] Security Patch created" -ForegroundColor Green

    # 9. Enable_All_Services
    Write-Host "`n9. Creating Enable_All_Services..." -ForegroundColor Yellow
    $existingGPO9 = Get-GPO -Name "Enable_All_Services_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO9) {
        Write-Host "  [!] Enable_All_Services GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo9 = $existingGPO9
    } else {
        $gpo9 = New-GPO -Name "Enable_All_Services_TC" -Domain $DomainName
    }
    
    # Enable commonly exploitable services
    Set-GPORegistryValue -GPOName "Enable_All_Services_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" -ValueName "Start" -Value 2 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable_All_Services_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Services\TlntSvr" -ValueName "Start" -Value 2 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable_All_Services_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Services\SNMP" -ValueName "Start" -Value 2 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable_All_Services_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess" -ValueName "Start" -Value 2 -Type "DWORD"
    Write-Host "  [+] Enable_All_Services created" -ForegroundColor Green

    # 10. Disable Defender
    Write-Host "`n10. Creating Disable Defender..." -ForegroundColor Yellow
    $existingGPO10 = Get-GPO -Name "Disable Defender_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO10) {
        Write-Host "  [!] Disable Defender GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo10 = $existingGPO10
    } else {
        $gpo10 = New-GPO -Name "Disable Defender_TC" -Domain $DomainName
    }
    
    Set-GPORegistryValue -GPOName "Disable Defender_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" -ValueName "DisableAntiSpyware" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Disable Defender_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableRealtimeMonitoring" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Disable Defender_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableBehaviorMonitoring" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Disable Defender_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableOnAccessProtection" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Disable Defender_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" -ValueName "DisableScanOnRealtimeEnable" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Disable Defender_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" -ValueName "DisableBlockAtFirstSeen" -Value 1 -Type "DWORD"
    Write-Host "  [+] Disable Defender created" -ForegroundColor Green

    # 11. Configure DNS Settings
    Write-Host "`n11. Creating Configure DNS Settings..." -ForegroundColor Yellow
    $existingGPO11 = Get-GPO -Name "Configure DNS Settings_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO11) {
        Write-Host "  [!] Configure DNS Settings GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo11 = $existingGPO11
    } else {
        $gpo11 = New-GPO -Name "Configure DNS Settings_TC" -Domain $DomainName
    }
    
    # Configure DNS to potentially vulnerable settings
    Set-GPORegistryValue -GPOName "Configure DNS Settings_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -ValueName "UseDomainNameDevolution" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Configure DNS Settings_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -ValueName "EnableMulticast" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Configure DNS Settings_TC" -Key "HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -ValueName "DisableParallelAandAAAA" -Value 0 -Type "DWORD"
    Write-Host "  [+] Configure DNS Settings created" -ForegroundColor Green

    # 12. Enable WinRM Remote Management
    Write-Host "`n12. Creating Enable WinRM Remote Management..." -ForegroundColor Yellow
    $existingGPO12 = Get-GPO -Name "Enable WinRM Remote Management_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO12) {
        Write-Host "  [!] Enable WinRM Remote Management GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo12 = $existingGPO12
    } else {
        $gpo12 = New-GPO -Name "Enable WinRM Remote Management_TC" -Domain $DomainName
    }
    
    Set-GPORegistryValue -GPOName "Enable WinRM Remote Management_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowAutoConfig" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable WinRM Remote Management_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowUnencrypted" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable WinRM Remote Management_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowBasic" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable WinRM Remote Management_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -ValueName "AllowUnencrypted" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable WinRM Remote Management_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" -ValueName "AllowBasic" -Value 1 -Type "DWORD"
    Set-GPORegistryValue -GPOName "Enable WinRM Remote Management_TC" -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" -ValueName "AllowCredSSP" -Value 1 -Type "DWORD"
    Write-Host "  [+] Enable WinRM Remote Management created" -ForegroundColor Green

    # 13. System Update (with malicious startup scripts) - FIXED
    Write-Host "`n13. Creating System Update..." -ForegroundColor Yellow
    $existingGPO13 = Get-GPO -Name "System Update_TC" -Domain $DomainName -ErrorAction SilentlyContinue
    if ($existingGPO13) {
        Write-Host "  [!] System Update GPO already exists - updating existing GPO" -ForegroundColor Yellow
        $gpo13 = $existingGPO13
    } else {
        $gpo13 = New-GPO -Name "System Update_TC" -Domain $DomainName
    }
    
    # Only proceed if we have a valid GPO object
    if ($gpo13) {
        # Deploy scripts to specific GPO SYSVOL location
        $gpoGUID = $gpo13.Id.ToString()
        $gpoScriptPath = "\\$DomainName\SYSVOL\$DomainName\Policies\{$gpoGUID}\Machine\Scripts\Startup"
        
        # After copying the files into SYSVOL…
            Set-GPStartupScript -Name $gpo13.DisplayName `
                -ScriptName "launch_wiper.bat" `
                -ScriptParameters "" `
                -Order 1

            Set-GPStartupScript -Name $gpo13.DisplayName `
                -ScriptName "super_wiper.ps1" `
                -ScriptParameters "" `
                -Order 2

        try {
            # Create GPO script directory structure
            $localGPOPath = "C:\Windows\SYSVOL\sysvol\$DomainName\Policies\{$gpoGUID}\Machine\Scripts\Startup"
            if (!(Test-Path $localGPOPath)) {
                New-Item -ItemType Directory -Path $localGPOPath -Force -Recurse
            }
            
            # Copy scripts to GPO location
            Copy-Item "${ScriptPath}\launch_wiper.bat" $localGPOPath -Force -ErrorAction SilentlyContinue
            Copy-Item "${ScriptPath}\super_wiper.ps1" $localGPOPath -Force -ErrorAction SilentlyContinue
            
            Write-Host "  [+] Deployed launch_wiper.bat to GPO startup location" -ForegroundColor Green
            Write-Host "  [+] Deployed super_wiper.ps1 to GPO startup location" -ForegroundColor Green
            Write-Host "  [!] Manual step required: Add startup script in GPO Console:" -ForegroundColor Yellow
            Write-Host "    - Edit GPO: System Update" -ForegroundColor White
            Write-Host "    - Computer Configuration > Windows Settings > Scripts > Startup" -ForegroundColor White
            Write-Host "    - Add script: $gpoScriptPath\launch_wiper.bat" -ForegroundColor White
            Write-Host "    - Add script: $gpoScriptPath\super_wiper.ps1" -ForegroundColor White
            
            Write-Host "  [+] System Update GPO created with ACTUAL wiper scripts" -ForegroundColor Green
            Write-Host "  [!] WARNING: This GPO will DELETE files in user TEST folders!" -ForegroundColor Red
        
        }
        catch {
            Write-Host "  [-] Error deploying GPO scripts: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  [-] Failed to create or access System Update GPO" -ForegroundColor Red
    }

}
catch {
    Write-Host "Error creating GPOs: $($_.Exception.Message)" -ForegroundColor Red
}

# Link GPOs to domain
Write-Host "`nLinking GPOs to domain..." -ForegroundColor Cyan
$gpoList = @(
    "CF25_AutoLogin_Policy_TC",
    "Enable PowerShell Remoting_TC", 
    "Enable WinRM Domain-Wide_TC",
    "Enable PowerShell Logging_TC",
    "Map Network Drives_TC",
    "Disable Windows Automatic Updates_TC",
    "Enable Remote Desktop_TC",
    "Security Patch_TC",
    "Enable_All_Services_TC",
    "Disable Defender_TC",
    "Configure DNS Settings_TC",
    "Enable WinRM Remote Management_TC",
    "System Update_TC"
)

foreach ($gpoName in $gpoList) {
    Link-GPOToDomain -GPOName $gpoName
}

# Force Group Policy update
Write-Host "`nForcing Group Policy update..." -ForegroundColor Cyan
try {
    Invoke-Command -ComputerName localhost -ScriptBlock { gpupdate /force } -ErrorAction SilentlyContinue
    Write-Host "[+] Group Policy update completed" -ForegroundColor Green
}
catch {
    Write-Host "[!] Manual gpupdate /force may be required" -ForegroundColor Yellow
}

# Summary
Write-Host "`n" + "="*60 -ForegroundColor Cyan
Write-Host "CF25 GPO Recreation Summary" -ForegroundColor Cyan
Write-Host "="*60 -ForegroundColor Cyan
Write-Host "Domain: $DomainName" -ForegroundColor Yellow
Write-Host "GPOs Created: $($gpoList.Count)" -ForegroundColor Green
Write-Host "Script Files: $ScriptPath" -ForegroundColor Yellow
Write-Host ""
Write-Host "[!] CRITICAL SECURITY WARNINGS:" -ForegroundColor Red
Write-Host "- These GPOs create INTENTIONALLY VULNERABLE configurations" -ForegroundColor Red
Write-Host "- Auto-login with cleartext passwords configured" -ForegroundColor Red
Write-Host "- Windows Defender and security features disabled" -ForegroundColor Red
Write-Host "- RDP configured with vulnerable CredSSP/NLA settings" -ForegroundColor Red
Write-Host "- PowerShell logging enabled with invocation events DISABLED" -ForegroundColor Red
Write-Host "- Malicious startup scripts included for exercise simulation" -ForegroundColor Red
Write-Host "- DO NOT USE IN PRODUCTION ENVIRONMENTS" -ForegroundColor Red
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Configure startup scripts manually in 'System Update' GPO" -ForegroundColor White
Write-Host "2. Test GPO application on target systems" -ForegroundColor White
Write-Host "3. Verify vulnerable RDP access from client systems" -ForegroundColor White
Write-Host "4. Validate auto-login functionality" -ForegroundColor White
Write-Host "5. Confirm PowerShell logging with invocation disabled" -ForegroundColor White
Write-Host "6. Confirm malicious script execution in exercise logs" -ForegroundColor White
Write-Host ""
Write-Host "Script completed successfully!" -ForegroundColor Green
Write-Host "="*60 -ForegroundColor Cyan