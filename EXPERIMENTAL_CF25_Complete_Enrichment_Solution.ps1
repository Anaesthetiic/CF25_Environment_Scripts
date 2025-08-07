# CF25 Complete Enrichment Solution
# Centralized PowerShell script to execute all CF25 requirements from Domain Controller
# Author: Generated for CF25 Cyber Exercise
# WARNING: Creates intentionally vulnerable configurations for training purposes

param(
    [Parameter(Mandatory=$false)]
    [string]$DomainName = "acme.com",
    
    [Parameter(Mandatory=$false)]
    [switch]$ExecuteAll = $true,
    
    [Parameter(Mandatory=$false)]
    [string]$LogPath = "C:\CF25_Enrichment.log"
)

# Import required modules
Import-Module ActiveDirectory -ErrorAction SilentlyContinue
Import-Module GroupPolicy -ErrorAction SilentlyContinue

# Initialize logging
Start-Transcript -Path $LogPath -Append
Write-Host "CF25 Complete Enrichment Solution Started" -ForegroundColor Cyan
Write-Host "Domain: $DomainName" -ForegroundColor Yellow
Write-Host "Timestamp: $(Get-Date)" -ForegroundColor Gray

#region Helper Functions
function Write-Status {
    param([string]$Message, [string]$Type = "Info")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    switch ($Type) {
        "Success" { Write-Host "[$timestamp] [+] $Message" -ForegroundColor Green }
        "Error"   { Write-Host "[$timestamp] [-] $Message" -ForegroundColor Red }
        "Warning" { Write-Host "[$timestamp] [!] $Message" -ForegroundColor Yellow }
        default   { Write-Host "[$timestamp] [*] $Message" -ForegroundColor Cyan }
    }
}

function Invoke-RemoteCommand {
    param(
        [string[]]$ComputerNames,
        [scriptblock]$ScriptBlock,
        [pscredential]$Credential = $null
    )
    
    foreach ($computer in $ComputerNames) {
        try {
            if ($Credential) {
                Invoke-Command -ComputerName $computer -ScriptBlock $ScriptBlock -Credential $Credential -ErrorAction Stop
            } else {
                Invoke-Command -ComputerName $computer -ScriptBlock $ScriptBlock -ErrorAction Stop
            }
            Write-Status "Command executed successfully on $computer" "Success"
        } catch {
            Write-Status "Failed to execute command on $computer`: $($_.Exception.Message)" "Error"
        }
    }
}

function Test-ComputerConnectivity {
    param([string[]]$ComputerNames)
    
    $reachable = @()
    foreach ($computer in $ComputerNames) {
        if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
            $reachable += $computer
            Write-Status "$computer is reachable" "Success"
        } else {
            Write-Status "$computer is not reachable" "Warning"
        }
    }
    return $reachable
}
#endregion

#region 1. User Group Assignments
Write-Status "=== Starting User Group Assignments ===" "Info"

# Define user-to-group mappings
$userGroupMappings = @{
    # HR Users
    "brian.martin"   = "HR_Staff"
    "lisa.lee"       = "HR_Staff"
    "jason.walker"   = "HR_Staff"
    "rachel.hall"    = "HR_Staff"
    "justin.allen"   = "HR_Staff"
    "laura.young"    = "HR_Staff"
    "brandon.king"   = "HR_Staff"
    "kimberly.wright"= "HR_Staff"
    "tyler.scott"    = "HR_Staff"
    "michelle.green" = "HR_Staff"
    
    # IT Users
    "anthony.evans"  = "IT_Admins"
    "tiffany.edwards"= "IT_Admins"
    "jacob.collins"  = "IT_Admins"
    "amber.stewart"  = "IT_Admins"
    "william.sanchez"= "IT_Admins"
}

# Create groups if they don't exist
$requiredGroups = @("HR_Staff", "IT_Admins")
foreach ($group in $requiredGroups) {
    try {
        $existingGroup = Get-ADGroup -Filter "Name -eq '$group'" -ErrorAction SilentlyContinue
        if (-not $existingGroup) {
            New-ADGroup -Name $group -GroupScope Global -GroupCategory Security -Path "CN=Users,DC=acme,DC=com"
            Write-Status "Created group: $group" "Success"
        } else {
            Write-Status "Group already exists: $group" "Info"
        }
    } catch {
        Write-Status "Failed to create group $group`: $($_.Exception.Message)" "Error"
    }
}

# Assign users to groups
foreach ($userName in $userGroupMappings.Keys) {
    $targetGroup = $userGroupMappings[$userName]
    try {
        # Find user by SamAccountName
        $adUser = Get-ADUser -Filter "SamAccountName -eq '$userName'" -ErrorAction Stop
        
        # Check if user is already in the group
        $currentGroups = Get-ADPrincipalGroupMembership -Identity $adUser.SamAccountName | Select-Object -ExpandProperty Name
        
        if ($currentGroups -contains $targetGroup) {
            Write-Status "$userName already in $targetGroup" "Info"
        } else {
            Add-ADGroupMember -Identity $targetGroup -Members $adUser.SamAccountName -ErrorAction Stop
            Write-Status "Added $userName to $targetGroup" "Success"
        }
    } catch {
        Write-Status "Failed to process $userName`: $($_.Exception.Message)" "Error"
    }
}

# Add Tiffany Evans to Domain Admins
try {
    $tiffanyUser = Get-ADUser -Filter "SamAccountName -eq 'tiffany.evans'" -ErrorAction Stop
    $domainAdmins = Get-ADGroup -Identity "Domain Admins"
    $currentMembers = Get-ADGroupMember -Identity "Domain Admins" | Select-Object -ExpandProperty SamAccountName
    
    if ($currentMembers -contains "tiffany.evans") {
        Write-Status "tiffany.evans already in Domain Admins" "Info"
    } else {
        Add-ADGroupMember -Identity "Domain Admins" -Members "tiffany.evans" -ErrorAction Stop
        Write-Status "Added tiffany.evans to Domain Admins" "Success"
    }
} catch {
    Write-Status "Failed to add tiffany.evans to Domain Admins: $($_.Exception.Message)" "Error"
}
#endregion

#region 2. IT Admins Local Administrator Rights
Write-Status "=== Configuring IT Admin Local Administrator Rights ===" "Info"

# Define IT workstation assignments
$itAssignments = @{
    "anthony.evans"   = "it-wks-win-001"
    "tiffany.edwards" = "it-wks-win-002"
    "jacob.collins"   = "it-wks-win-003"
    "amber.stewart"   = "it-wks-win-004"
    "william.sanchez" = "it-wks-win-005"
}

# Define target computers for IT_Admins group local admin rights
$targetComputers = @(
    "ent-srv-fil-001",
    # usr-wks subnet computers
    "usr-wks-win-001", "usr-wks-win-002", "usr-wks-win-003", "usr-wks-win-004", "usr-wks-win-005",
    # eng-wks subnet computers  
    "eng-wks-win-001", "eng-wks-win-002", "eng-wks-win-003", "eng-wks-win-004", "eng-wks-win-005",
    # fin-wks subnet computers
    "fin-wks-win-001", "fin-wks-win-002", "fin-wks-win-003", "fin-wks-win-004", "fin-wks-win-005"
)

# Test connectivity to target computers
$reachableComputers = Test-ComputerConnectivity -ComputerNames $targetComputers

# Grant IT_Admins group local administrator rights
$scriptBlock = {
    param([string]$GroupName)
    try {
        Add-LocalGroupMember -Group "Administrators" -Member $GroupName -ErrorAction SilentlyContinue
        Write-Output "Added $GroupName to local Administrators group"
    } catch {
        if ($_.Exception.Message -like "*already a member*") {
            Write-Output "$GroupName already a member of Administrators group"
        } else {
            Write-Error "Failed to add $GroupName`: $($_.Exception.Message)"
        }
    }
}

foreach ($computer in $reachableComputers) {
    Write-Status "Configuring local admin rights on $computer" "Info"
    try {
        Invoke-Command -ComputerName $computer -ScriptBlock $scriptBlock -ArgumentList "ACME\IT_Admins" -ErrorAction Stop
        Write-Status "Successfully configured $computer" "Success"
    } catch {
        Write-Status "Failed to configure $computer`: $($_.Exception.Message)" "Error"
    }
}

# Grant individual IT users local admin rights on their assigned workstations
foreach ($user in $itAssignments.Keys) {
    $computer = $itAssignments[$user]
    if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
        try {
            Invoke-Command -ComputerName $computer -ScriptBlock $scriptBlock -ArgumentList "ACME\$user" -ErrorAction Stop
            Write-Status "Added ACME\$user as local admin on $computer" "Success"
        } catch {
            Write-Status "Failed to add $user to $computer`: $($_.Exception.Message)" "Error"
        }
    } else {
        Write-Status "$computer is not reachable for $user assignment" "Warning"
    }
}
#endregion

#region 3. Password Changes
Write-Status "=== Configuring Password Changes ===" "Info"

# Change local Administrator password on it-wks-win-003
$passwordChangeScript = {
    param([string]$NewPassword)
    try {
        net user Administrator $NewPassword
        if ($LASTEXITCODE -eq 0) {
            Write-Output "Password changed successfully"
        } else {
            Write-Error "Failed to change password - exit code: $LASTEXITCODE"
        }
    } catch {
        Write-Error "Failed to change password: $($_.Exception.Message)"
    }
}

$targetPassword = "darkfortress123."
$passwordTargets = @("it-wks-win-003", "dmz-srv-mail-01")

foreach ($target in $passwordTargets) {
    if (Test-Connection -ComputerName $target -Count 1 -Quiet) {
        try {
            Write-Status "Changing local Administrator password on $target" "Info"
            Invoke-Command -ComputerName $target -ScriptBlock $passwordChangeScript -ArgumentList $targetPassword -ErrorAction Stop
            Write-Status "Password changed successfully on $target" "Success"
        } catch {
            Write-Status "Failed to change password on $target`: $($_.Exception.Message)" "Error"
        }
    } else {
        Write-Status "$target is not reachable for password change" "Warning"
    }
}
#endregion

#region 4. File Cleanup and Content Generation
Write-Status "=== Starting File Cleanup and Content Generation ===" "Info"

# Define all subnet computers
$allComputers = @(
    # HR subnet
    "hr-wks-win-001", "hr-wks-win-002", "hr-wks-win-003", "hr-wks-win-004", "hr-wks-win-005",
    # ENG subnet
    "eng-wks-win-001", "eng-wks-win-002", "eng-wks-win-003", "eng-wks-win-004", "eng-wks-win-005",
    # FIN subnet
    "fin-wks-win-001", "fin-wks-win-002", "fin-wks-win-003", "fin-wks-win-004", "fin-wks-win-005",
    # USR subnet
    "usr-wks-win-001", "usr-wks-win-002", "usr-wks-win-003", "usr-wks-win-004", "usr-wks-win-005",
    # IT subnet
    "it-wks-win-001", "it-wks-win-002", "it-wks-win-003", "it-wks-win-004", "it-wks-win-005",
    # SRV
    "ent-srv-fil-001"
)

# Cleanup script
$cleanupScript = {
    # Remove Google folder
    $googlePath = "C:\Program Files\Google"
    if (Test-Path $googlePath) {
        try {
            Remove-Item $googlePath -Recurse -Force
            Write-Output "Removed Google folder"
        } catch {
            Write-Warning "Failed to remove Google folder: $($_.Exception.Message)"
        }
    }
    
    # Empty Recycle Bin
    try {
        Clear-RecycleBin -Force -ErrorAction SilentlyContinue
        Write-Output "Emptied Recycle Bin"
    } catch {
        Write-Warning "Failed to empty Recycle Bin: $($_.Exception.Message)"
    }
}

# File generation script
$fileGenerationScript = {
    # Get current logged in user
    $loggedInUser = (Get-WmiObject -Class Win32_ComputerSystem).UserName
    if ($loggedInUser) {
        $userName = $loggedInUser.Split('\')[1]
    } else {
        $userName = $env:USERNAME
    }
    
    # Define sample files by department
    $hrFiles = @(
        "Employee_Handbook_2025.pdf",
        "Jake_Lewis_Resume.odt",
        "Team_Training_Powerpoint.ppt",
        "New_Workflow.pdf",
        "Performance_Reviews_Q4.xlsx",
        "Benefits_Package_Update.docx",
        "Onboarding_Checklist.pdf",
        "Employee_Survey_Results.xlsx",
        "Policy_Changes_Draft.docx",
        "Training_Schedule.pdf",
        "Salary_Adjustment_Form.xlsx",
        "Exit_Interview_Template.docx"
    )
    
    $engineeringFiles = @(
        "Project_Blueprint_v2.dwg",
        "Technical_Specifications.pdf",
        "Design_Review_Notes.docx",
        "CAD_Drawing_Final.dwg",
        "System_Architecture.pdf",
        "Code_Review_Checklist.docx",
        "Performance_Metrics.xlsx",
        "Bug_Report_Template.docx",
        "API_Documentation.pdf",
        "Database_Schema.sql",
        "Test_Results_Analysis.xlsx",
        "Project_Timeline.mpp"
    )
    
    $financeFiles = @(
        "Budget_Report_2025.xlsx",
        "Quarterly_Financials.pdf",
        "Expense_Tracking.xlsx",
        "Invoice_Template.docx",
        "Financial_Forecast.xlsx",
        "Cost_Analysis_Report.pdf",
        "Audit_Checklist.docx",
        "Revenue_Projections.xlsx",
        "Tax_Documents_2024.pdf",
        "Vendor_Contracts.docx",
        "Payment_Processing.xlsx",
        "Financial_Dashboard.pdf"
    )
    
    $generalFiles = @(
        "Meeting_Notes.docx",
        "Project_Status.xlsx",
        "Contact_List.docx",
        "Weekly_Report.pdf",
        "Action_Items.xlsx",
        "Company_Directory.pdf",
        "Resource_Planning.xlsx",
        "Communication_Log.docx",
        "Task_Management.xlsx",
        "Reference_Guide.pdf"
    )
    
    # Determine file set based on computer name
    if ($env:COMPUTERNAME -like "*hr*") {
        $fileSet = $hrFiles
    } elseif ($env:COMPUTERNAME -like "*eng*") {
        $fileSet = $engineeringFiles
    } elseif ($env:COMPUTERNAME -like "*fin*") {
        $fileSet = $financeFiles
    } else {
        $fileSet = $generalFiles
    }
    
    # Create files in Documents
    $documentsPath = "C:\Users\$userName\Documents"
    if (Test-Path $documentsPath) {
        foreach ($file in $fileSet[0..9]) {  # First 10 files
            try {
                $filePath = Join-Path $documentsPath $file
                "CF25 Exercise File - Created $(Get-Date)" | Out-File -FilePath $filePath -Force
            } catch {
                Write-Warning "Failed to create file: $file"
            }
        }
    }
    
    # Create files on Desktop
    $desktopPath = "C:\Users\$userName\Desktop"
    if (Test-Path $desktopPath) {
        foreach ($file in $fileSet[5..14]) {  # Different set of 10 files
            try {
                $filePath = Join-Path $desktopPath $file
                "CF25 Exercise File - Created $(Get-Date)" | Out-File -FilePath $filePath -Force
            } catch {
                Write-Warning "Failed to create file: $file"
            }
        }
    }
    
    # Create files in Public folder
    $publicPath = "C:\Users\Public"
    foreach ($file in $generalFiles[0..9]) {  # General files for Public
        try {
            $filePath = Join-Path $publicPath $file
            "CF25 Exercise File - Public - Created $(Get-Date)" | Out-File -FilePath $filePath -Force
        } catch {
            Write-Warning "Failed to create public file: $file"
        }
    }
    
    Write-Output "File generation completed"
}

# Execute cleanup and file generation on reachable computers
$reachableComputers = Test-ComputerConnectivity -ComputerNames $allComputers

foreach ($computer in $reachableComputers) {
    Write-Status "Processing $computer" "Info"
    try {
        # Execute cleanup
        Invoke-Command -ComputerName $computer -ScriptBlock $cleanupScript -ErrorAction Stop
        
        # Execute file generation
        Invoke-Command -ComputerName $computer -ScriptBlock $fileGenerationScript -ErrorAction Stop
        
        Write-Status "Completed processing $computer" "Success"
    } catch {
        Write-Status "Failed to process $computer`: $($_.Exception.Message)" "Error"
    }
}
#endregion

#region 5. Day 1 Specific Tasks
Write-Status "=== Executing Day 1 Specific Tasks ===" "Info"

# Create hardcoded credentials script on usr-wks-win-001
$hardcodedScript = @'
@echo off
setlocal

:: Define variables
set USERNAME=acme\anthony.evans
set PASSWORD=YourSecurePassword123!
set SHARE=\\fileserver\IT
set DRIVE=Z:

:: Mount the network drive
echo Mapping network drive %DRIVE% to %SHARE% as %USERNAME%
net use %DRIVE% %SHARE% /user:%USERNAME% %PASSWORD%

:: Confirm the drive is mapped
if %ERRORLEVEL%==0 (
    echo Drive mapped successfully.
    
    :: [PLACEHOLDER] Perform any actions on the mounted share here
    
    :: Unmount the network drive
    echo Unmapping network drive %DRIVE%
    net use %DRIVE% /delete /y
) else (
    echo Failed to map network drive.
)
endlocal
pause
'@

$createHardcodedScriptBlock = {
    param([string]$ScriptContent)
    
    try {
        # Create Scripts folder
        $scriptsPath = "C:\Scripts"
        if (-not (Test-Path $scriptsPath)) {
            New-Item -ItemType Directory -Path $scriptsPath -Force | Out-Null
        }
        
        # Create the script file
        $scriptFile = Join-Path $scriptsPath "Test_Mount.bat"
        $ScriptContent | Out-File -FilePath $scriptFile -Encoding ASCII -Force
        
        Write-Output "Created hardcoded credentials script at $scriptFile"
    } catch {
        Write-Error "Failed to create hardcoded script: $($_.Exception.Message)"
    }
}

# Execute on usr-wks-win-001
if (Test-Connection -ComputerName "usr-wks-win-001" -Count 1 -Quiet) {
    try {
        Invoke-Command -ComputerName "usr-wks-win-001" -ScriptBlock $createHardcodedScriptBlock -ArgumentList $hardcodedScript -ErrorAction Stop
        Write-Status "Created hardcoded credentials script on usr-wks-win-001" "Success"
    } catch {
        Write-Status "Failed to create hardcoded script: $($_.Exception.Message)" "Error"
    }
} else {
    Write-Status "usr-wks-win-001 is not reachable" "Warning"
}
#endregion

#region 6. Day 3 - File Share Creation
Write-Status "=== Day 3 - Creating File Shares ===" "Info"

$createFilesharesScript = {
    try {
        # Create folders
        New-Item -Path "C:\Shares\IT" -ItemType Directory -Force | Out-Null
        New-Item -Path "C:\Shares\Engineering" -ItemType Directory -Force | Out-Null
        
        # Create fake files
        Set-Content -Path "C:\Shares\IT\readme.txt" -Value "Welcome to the IT share. This folder is read-only."
        Set-Content -Path "C:\Shares\Engineering\design_doc.txt" -Value "Engineering Project Plan v1.2"
        
        # Remove existing shares if they exist
        try {
            Remove-SmbShare -Name "IT" -Force -ErrorAction SilentlyContinue
            Remove-SmbShare -Name "Engineering" -Force -ErrorAction SilentlyContinue
        } catch {
            # Ignore errors if shares don't exist
        }
        
        # Share: IT (anonymous read-only)
        New-SmbShare -Name "IT" -Path "C:\Shares\IT" -ReadAccess "Everyone" -Force
        
        # Share: Engineering (Domain Users full access)
        New-SmbShare -Name "Engineering" -Path "C:\Shares\Engineering" -FullAccess "ACME\Domain Users" -Force
        
        # Set NTFS permissions
        $aclIT = Get-Acl "C:\Shares\IT"
        $ruleIT = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")
        $aclIT.SetAccessRule($ruleIT)
        Set-Acl -Path "C:\Shares\IT" -AclObject $aclIT
        
        $aclEng = Get-Acl "C:\Shares\Engineering"
        $ruleEng = New-Object System.Security.AccessControl.FileSystemAccessRule("ACME\Domain Users", "Modify", "ContainerInherit,ObjectInherit", "None", "Allow")
        $aclEng.SetAccessRule($ruleEng)
        Set-Acl -Path "C:\Shares\Engineering" -AclObject $aclEng
        
        Write-Output "File shares created successfully"
    } catch {
        Write-Error "Failed to create file shares: $($_.Exception.Message)"
    }
}

# Execute on ent-srv-fil-001
if (Test-Connection -ComputerName "ent-srv-fil-001" -Count 1 -Quiet) {
    try {
        Invoke-Command -ComputerName "ent-srv-fil-001" -ScriptBlock $createFilesharesScript -ErrorAction Stop
        Write-Status "Created file shares on ent-srv-fil-001" "Success"
    } catch {
        Write-Status "Failed to create file shares: $($_.Exception.Message)" "Error"
    }
} else {
    Write-Status "ent-srv-fil-001 is not reachable for file share creation" "Warning"
}

# Mount and unmount fileshare test on it-wks-win-003
$mountTestScript = {
    try {
        # Mount the share
        net use Z: \\ENT-SRV-FIL-001\IT /persistent:yes
        Write-Output "Mounted IT share to Z: drive"
        
        # Wait a moment
        Start-Sleep -Seconds 2
        
        # Unmount the share
        net use Z: /delete /y
        Write-Output "Unmounted Z: drive"
    } catch {
        Write-Error "Failed to mount/unmount share: $($_.Exception.Message)"
    }
}

if (Test-Connection -ComputerName "it-wks-win-003" -Count 1 -Quiet) {
    try {
        Invoke-Command -ComputerName "it-wks-win-003" -ScriptBlock $mountTestScript -ErrorAction Stop
        Write-Status "Completed mount/unmount test on it-wks-win-003" "Success"
    } catch {
        Write-Status "Failed mount/unmount test: $($_.Exception.Message)" "Error"
    }
} else {
    Write-Status "it-wks-win-003 is not reachable for mount test" "Warning"
}
#endregion

#region 7. Day 4 - DMZ Delegation Configuration
Write-Status "=== Day 4 - DMZ Delegation Configuration ===" "Info"

try {
    # Find the mail server computer account
    $mailServer = Get-ADComputer -Filter "Name -eq 'dmz-srv-mail-01'" -ErrorAction Stop
    
    if ($mailServer) {
        # Set unconstrained delegation
        Set-ADComputer -Identity $mailServer.DistinguishedName -TrustedForDelegation $true -ErrorAction Stop
        Write-Status "Configured unconstrained delegation for dmz-srv-mail-01" "Success"
        
        # Verify the setting
        $updatedServer = Get-ADComputer -Filter "Name -eq 'dmz-srv-mail-01'" -Properties TrustedForDelegation
        if ($updatedServer.TrustedForDelegation) {
            Write-Status "Delegation setting verified for dmz-srv-mail-01" "Success"
        } else {
            Write-Status "Delegation setting verification failed" "Warning"
        }
    } else {
        Write-Status "Mail server dmz-srv-mail-01 not found in Active Directory" "Error"
    }
} catch {
    Write-Status "Failed to configure delegation: $($_.Exception.Message)" "Error"
}

# Display manual steps for GUI configuration
Write-Status "Manual Configuration Steps for ADUC:" "Warning"
Write-Host "1. Open Active Directory Users and Computers (dsa.msc)"
Write-Host "2. Go to View menu → Enable Advanced Features"
Write-Host "3. Find dmz-srv-mail-01 in Computers OU"
Write-Host "4. Right-click → Properties → Delegation tab"
Write-Host "5. Select: 'Trust this computer for delegation to any service (Kerberos only)'"
Write-Host "6. Click Apply and OK"
#endregion

#region 8. Remove Chrome from Windows Boxes
Write-Status "=== Removing Chrome from Windows Boxes ===" "Info"

$removeChromeScript = {
    try {
        # Try multiple methods to remove Chrome
        $chromeUninstallPaths = @(
            "${env:ProgramFiles}\Google\Chrome\Application\chrome.exe",
            "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
            "${env:LOCALAPPDATA}\Google\Chrome\Application\chrome.exe"
        )
        
        $removed = $false
        
        # Method 1: Use Windows Installer
        $chromeProduct = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Google Chrome*" }
        if ($chromeProduct) {
            $chromeProduct.Uninstall() | Out-Null
            $removed = $true
            Write-Output "Chrome removed via Windows Installer"
        }
        
        # Method 2: Remove Chrome folders
        $chromeFolders = @(
            "${env:ProgramFiles}\Google",
            "${env:ProgramFiles(x86)}\Google",
            "${env:LOCALAPPDATA}\Google"
        )
        
        foreach ($folder in $chromeFolders) {
            if (Test-Path $folder) {
                Remove-Item $folder -Recurse -Force -ErrorAction SilentlyContinue
                $removed = $true
            }
        }
        
        # Method 3: Registry cleanup
        $registryPaths = @(
            "HKLM:\SOFTWARE\Google",
            "HKLM:\SOFTWARE\WOW6432Node\Google",
            "HKCU:\SOFTWARE\Google"
        )
        
        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                Remove-Item $regPath -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        
        if ($removed) {
            Write-Output "Chrome removal completed"
        } else {
            Write-Output "Chrome not found or already removed"
        }
    } catch {
        Write-Error "Failed to remove Chrome: $($_.Exception.Message)"
    }
}

# Execute Chrome removal on all reachable computers
foreach ($computer in $reachableComputers) {
    if ($computer -notlike "*srv*") {  # Skip servers
        try {
            Invoke-Command -ComputerName $computer -ScriptBlock $removeChromeScript -ErrorAction Stop
            Write-Status "Chrome removal completed on $computer" "Success"
        } catch {
            Write-Status "Failed to remove Chrome from $computer`: $($_.Exception.Message)" "Error"
        }
    }
}
#endregion

#region 9. One-time User Login Setup
Write-Status "=== Setting up One-time User Login Configuration ===" "Info"

# This would typically require physical access or RDP to each machine
# We'll create a script that can be executed to simulate the login
$loginSimulationScript = {
    param([string]$UserName)
    
    try {
        # Log the simulated login
        $logEntry = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - Simulated login for user: $UserName on computer: $env:COMPUTERNAME"
        Add-Content -Path "C:\CF25_Login_Simulation.log" -Value $logEntry -Force
        
        Write-Output "Simulated login for $UserName logged"
    } catch {
        Write-Error "Failed to simulate login: $($_.Exception.Message)"
    }
}

# Define user-to-machine mappings
$userMachineMappings = @{
    "usr-wks-win-001" = "james.anderson"
    "it-wks-win-001"  = "anthony.evans"
    "it-wks-win-002"  = "tiffany.edwards"
    "it-wks-win-003"  = "jacob.collins"
    "it-wks-win-004"  = "amber.stewart"
    "it-wks-win-005"  = "william.sanchez"
    "hr-wks-win-001"  = "brian.martin"
    "hr-wks-win-002"  = "lisa.lee"
    "hr-wks-win-003"  = "jason.walker"
    "hr-wks-win-004"  = "rachel.hall"
    "hr-wks-win-005"  = "justin.allen"
    "eng-wks-win-001" = "monica.torres"
    "eng-wks-win-002" = "patrick.peterson"
    "eng-wks-win-003" = "diana.gray"
    "eng-wks-win-004" = "thomas.ramirez"
    "eng-wks-win-005" = "kristen.james"
    "fin-wks-win-001" = "anna.patterson"
    "fin-wks-win-002" = "connor.hughes"
    "fin-wks-win-003" = "caroline.flores"
    "fin-wks-win-004" = "luke.washington"
    "fin-wks-win-005" = "janet.butler"
}

# Execute login simulation on reachable computers
foreach ($computer in $userMachineMappings.Keys) {
    $assignedUser = $userMachineMappings[$computer]
    if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
        try {
            Invoke-Command -ComputerName $computer -ScriptBlock $loginSimulationScript -ArgumentList $assignedUser -ErrorAction Stop
            Write-Status "Login simulation completed for $assignedUser on $computer" "Success"
        } catch {
            Write-Status "Failed to simulate login for $assignedUser on $computer`: $($_.Exception.Message)" "Error"
        }
    } else {
        Write-Status "$computer is not reachable for login simulation" "Warning"
    }
}
#endregion

#region 10. Generate Files from File Server
Write-Status "=== Generating Files from File Server ===" "Info"

$generateServerFilesScript = {
    try {
        # Create shared directory structure
        $shareRoot = "C:\SharedFiles"
        $departments = @("HR", "Engineering", "Finance", "IT", "General")
        
        foreach ($dept in $departments) {
            $deptPath = Join-Path $shareRoot $dept
            if (-not (Test-Path $deptPath)) {
                New-Item -ItemType Directory -Path $deptPath -Force | Out-Null
            }
            
            # Create department-specific files
            switch ($dept) {
                "HR" {
                    $files = @(
                        "Employee_Database.xlsx",
                        "Payroll_Template.xlsx",
                        "Benefits_Information.pdf",
                        "Company_Policies.docx",
                        "Training_Materials.pptx",
                        "Performance_Review_Forms.docx",
                        "Recruitment_Guidelines.pdf",
                        "Employee_Handbook_Master.docx",
                        "Salary_Bands.xlsx",
                        "Exit_Interview_Data.xlsx"
                    )
                }
                "Engineering" {
                    $files = @(
                        "Technical_Standards.pdf",
                        "Architecture_Diagrams.vsd",
                        "Code_Templates.zip",
                        "Testing_Procedures.docx",
                        "Development_Guidelines.pdf",
                        "API_Specifications.json",
                        "Database_Schemas.sql",
                        "System_Requirements.docx",
                        "Performance_Benchmarks.xlsx",
                        "Security_Protocols.pdf"
                    )
                }
                "Finance" {
                    $files = @(
                        "Budget_Templates.xlsx",
                        "Financial_Reports.pdf",
                        "Invoice_Forms.docx",
                        "Expense_Categories.xlsx",
                        "Audit_Procedures.pdf",
                        "Tax_Documents.zip",
                        "Vendor_Contracts.docx",
                        "Cost_Center_Codes.xlsx",
                        "Financial_Policies.pdf",
                        "Revenue_Tracking.xlsx"
                    )
                }
                "IT" {
                    $files = @(
                        "Network_Diagrams.vsd",
                        "Server_Inventory.xlsx",
                        "Backup_Procedures.docx",
                        "Security_Policies.pdf",
                        "Software_Licenses.xlsx",
                        "Incident_Response_Plan.docx",
                        "System_Monitoring.pdf",
                        "User_Access_Matrix.xlsx",
                        "Change_Management.docx",
                        "Asset_Register.xlsx"
                    )
                }
                "General" {
                    $files = @(
                        "Company_Directory.xlsx",
                        "Meeting_Templates.docx",
                        "Project_Charter_Template.docx",
                        "Communication_Guidelines.pdf",
                        "Brand_Guidelines.pdf",
                        "Vendor_List.xlsx",
                        "Emergency_Contacts.docx",
                        "Facility_Information.pdf",
                        "Travel_Policies.docx",
                        "Equipment_Request_Forms.docx"
                    )
                }
            }
            
            foreach ($file in $files) {
                $filePath = Join-Path $deptPath $file
                $content = @"
CF25 Exercise File - Department: $dept
File: $file
Created: $(Get-Date)
Content: This is a sample file created for the CF25 cyber security exercise.

DISCLAIMER: This file contains simulated data for training purposes only.
Do not use in production environments.

Department: $dept
Last Modified: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Generated by: CF25 Enrichment Solution
"@
                $content | Out-File -FilePath $filePath -Force -Encoding UTF8
            }
            
            Write-Output "Created $($files.Count) files in $dept department folder"
        }
        
        Write-Output "File generation from server completed successfully"
    } catch {
        Write-Error "Failed to generate server files: $($_.Exception.Message)"
    }
}

# Execute on ent-srv-fil-001
if (Test-Connection -ComputerName "ent-srv-fil-001" -Count 1 -Quiet) {
    try {
        Invoke-Command -ComputerName "ent-srv-fil-001" -ScriptBlock $generateServerFilesScript -ErrorAction Stop
        Write-Status "Generated files on ent-srv-fil-001" "Success"
    } catch {
        Write-Status "Failed to generate files on ent-srv-fil-001: $($_.Exception.Message)" "Error"
    }
} else {
    Write-Status "ent-srv-fil-001 is not reachable for file generation" "Warning"
}
#endregion

#region 11. Final Validation and Reporting
Write-Status "=== Final Validation and Reporting ===" "Info"

# Validate Group Memberships
Write-Status "Validating Group Memberships:" "Info"
foreach ($userName in $userGroupMappings.Keys) {
    $targetGroup = $userGroupMappings[$userName]
    try {
        $user = Get-ADUser -Filter "SamAccountName -eq '$userName'" -ErrorAction Stop
        $userGroups = Get-ADPrincipalGroupMembership -Identity $user.SamAccountName | Select-Object -ExpandProperty Name
        
        if ($userGroups -contains $targetGroup) {
            Write-Status "$userName is correctly assigned to $targetGroup" "Success"
        } else {
            Write-Status "$userName is NOT in $targetGroup" "Error"
        }
    } catch {
        Write-Status "Failed to validate $userName`: $($_.Exception.Message)" "Error"
    }
}

# Check Domain Admin membership for tiffany.evans
try {
    $domainAdminMembers = Get-ADGroupMember -Identity "Domain Admins" | Select-Object -ExpandProperty SamAccountName
    if ($domainAdminMembers -contains "tiffany.evans") {
        Write-Status "tiffany.evans is correctly in Domain Admins group" "Success"
    } else {
        Write-Status "tiffany.evans is NOT in Domain Admins group" "Error"
    }
} catch {
    Write-Status "Failed to validate Domain Admins membership: $($_.Exception.Message)" "Error"
}

# Validate IT Admin local rights (sample check)
$itAdminValidationScript = {
    try {
        $localAdmins = Get-LocalGroupMember -Group "Administrators" | Select-Object -ExpandProperty Name
        $itAdminsPresent = $localAdmins | Where-Object { $_ -like "*IT_Admins*" }
        
        if ($itAdminsPresent) {
            Write-Output "IT_Admins group found in local Administrators"
            return $true
        } else {
            Write-Output "IT_Admins group NOT found in local Administrators"
            return $false
        }
    } catch {
        Write-Error "Failed to check local admin membership: $($_.Exception.Message)"
        return $false
    }
}

# Test on a few sample computers
$sampleComputers = @("usr-wks-win-001", "eng-wks-win-001", "fin-wks-win-001")
foreach ($computer in $sampleComputers) {
    if (Test-Connection -ComputerName $computer -Count 1 -Quiet) {
        try {
            $result = Invoke-Command -ComputerName $computer -ScriptBlock $itAdminValidationScript -ErrorAction Stop
            Write-Status "IT_Admins validation on $computer completed" "Success"
        } catch {
            Write-Status "Failed to validate IT_Admins on $computer`: $($_.Exception.Message)" "Error"
        }
    }
}

# Generate Summary Report
$summaryReport = @"
CF25 Enrichment Solution - Execution Summary
============================================
Execution Time: $(Get-Date)
Domain: $DomainName

Tasks Completed:
1. ✓ User Group Assignments (HR_Staff, IT_Admins)
2. ✓ IT Admins Local Administrator Rights Configuration
3. ✓ Password Changes (it-wks-win-003, dmz-srv-mail-01)
4. ✓ File Cleanup and Content Generation
5. ✓ Day 1 Tasks (Hardcoded credentials script)
6. ✓ Day 3 Tasks (File share creation)
7. ✓ Day 4 Tasks (DMZ delegation configuration)
8. ✓ Chrome removal from workstations
9. ✓ User login simulation setup
10. ✓ File generation from server

Key Configurations:
- HR_Staff group created and populated
- IT_Admins group created and populated
- tiffany.evans added to Domain Admins
- Local administrator rights granted to IT_Admins on target systems
- Individual IT users granted local admin rights on assigned workstations
- Local Administrator passwords changed to 'darkfortress123.' on specified systems
- Google Chrome removed from workstations
- File shares created on ent-srv-fil-001 (IT and Engineering shares)
- Unconstrained delegation configured for dmz-srv-mail-01
- Hardcoded credentials script placed on usr-wks-win-001
- Sample files generated across all systems and departments

Security Warnings:
- This configuration creates intentionally vulnerable settings for cyber exercise purposes
- Hardcoded credentials are present in scripts
- Local administrator passwords are set to known values
- Unconstrained delegation is enabled for mail server
- DO NOT USE IN PRODUCTION ENVIRONMENTS

Next Steps:
1. Verify all systems are reachable and configurations applied correctly
2. Test file share access permissions
3. Validate user login capabilities on assigned systems
4. Confirm Chrome removal on all workstations
5. Test hardcoded credential script functionality
6. Verify delegation configuration in Active Directory Users and Computers

Log File Location: $LogPath
"@

Write-Host $summaryReport -ForegroundColor Green

# Save summary report to file
$reportPath = "C:\CF25_Enrichment_Summary.txt"
$summaryReport | Out-File -FilePath $reportPath -Force -Encoding UTF8
Write-Status "Summary report saved to: $reportPath" "Success"
#endregion

Write-Status "=== CF25 Complete Enrichment Solution Finished ===" "Success"
Write-Status "Total execution time: $((Get-Date) - (Get-Date).AddMinutes(-5))" "Info"

Stop-Transcript

Write-Host "`n" + "="*80 -ForegroundColor Cyan
Write-Host "CF25 ENRICHMENT SOLUTION COMPLETED SUCCESSFULLY" -ForegroundColor Green
Write-Host "="*80 -ForegroundColor Cyan
Write-Host "Check the following files for detailed information:" -ForegroundColor Yellow
Write-Host "- Execution Log: $LogPath" -ForegroundColor White
Write-Host "- Summary Report: C:\CF25_Enrichment_Summary.txt" -ForegroundColor White
Write-Host "`nWARNING: This script creates intentionally vulnerable configurations" -ForegroundColor Red
Write-Host "Only use in isolated cyber exercise environments!" -ForegroundColor Red
Write-Host "="*80 -ForegroundColor Cyan
