# Import Active Directory Module
Import-Module ActiveDirectory -ErrorAction SilentlyContinue

# Get Current Domain
$domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
Write-Output "Detected Domain: $domain"

# Define user-to-group mappings based on your data
$userGroupMappings = @{
    # Engineering Users
    "Monica Torres" = "Engineer-User"
    "Patrick Peterson" = "Engineer-User" 
    "Diana Gray" = "Engineer-User"
    "Thomas Ramirez" = "Engineer-User"
    "Kristen James" = "Engineer-User"
    
    # Finance Users
    "Anna Patterson" = "Finance-User"
    "Connor Hughes" = "Finance-User"
    "Caroline Flores" = "Finance-User"
    "Luke Washington" = "Finance-User"
    "Janet Butler" = "Finance-User"
    
    # HR Users
    "Brian Martin" = "HR-User"
    "Lisa Lee" = "HR-User"
    "Jason Walker" = "HR-User"
    "Rachel Hall" = "HR-User"
    "Justin Allen" = "HR-User"
    
    # IT Users
    "Anthony Evans" = "IT-User"
    "Tiffany Edwards" = "IT-User"
    "Jacob Collins" = "IT-User"
    "Amber Stewart" = "IT-User"
    "William Sanchez" = "IT-User"
    
    # Regular Users
    "James Anderson" = "Reg-Users"
    "Sarah Mitchell" = "Reg-Users"
    "David Rodriguez" = "Reg-Users"
    "Emily Thompson" = "Reg-Users"
    "Michael Johnson" = "Reg-Users"
}

# Define group list
$requiredGroups = @("Engineer-User", "Finance-User", "HR-User", "IT-User", "Reg-Users")

# Function to validate or create AD groups
function Validate-OrCreate-Group {
    param ([string]$groupName)
    
    $existing = Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction SilentlyContinue
    if (!$existing) {
        try {
            $groupPath = "CN=Users,DC=$($domain.Replace('.', ',DC='))"
            New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Path $groupPath
            Write-Host "✓ Created group: $groupName" -ForegroundColor Green
        } catch {
            Write-Host "✗ Failed to create group $groupName`: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "✓ Group exists: $groupName" -ForegroundColor Yellow
    }
}

# Function to find and assign users to groups
function Assign-UsersToGroups {
    Write-Host "`nStarting user-to-group assignment process..." -ForegroundColor Cyan
    
    # First, ensure all required groups exist
    Write-Host "Validating/Creating required groups..." -ForegroundColor Yellow
    foreach ($group in $requiredGroups) {
        Validate-OrCreate-Group -groupName $group
    }
    
    # Find and assign users
    $assignmentResults = @()
    
    foreach ($userName in $userGroupMappings.Keys) {
        $targetGroup = $userGroupMappings[$userName]
        
        try {
            # Find the user in AD
            $adUser = Get-ADUser -Filter "Name -eq '$userName'" -ErrorAction Stop
            
            # Check if user is already in the group
            $currentGroups = Get-ADPrincipalGroupMembership -Identity $adUser.SamAccountName | Select-Object -ExpandProperty Name
            
            if ($currentGroups -contains $targetGroup) {
                Write-Host "  → $userName already in $targetGroup" -ForegroundColor Gray
                $status = "Already Member"
            } else {
                # Add user to group
                Add-ADGroupMember -Identity $targetGroup -Members $adUser.SamAccountName -ErrorAction Stop
                Write-Host "  ✓ Added $userName to $targetGroup" -ForegroundColor Green
                $status = "Added"
            }
            
            $assignmentResults += [PSCustomObject]@{
                UserName = $userName
                SamAccountName = $adUser.SamAccountName
                TargetGroup = $targetGroup
                Status = $status
                DistinguishedName = $adUser.DistinguishedName
            }
            
        } catch {
            Write-Host "  ✗ Failed to process $userName`: $($_.Exception.Message)" -ForegroundColor Red
            $assignmentResults += [PSCustomObject]@{
                UserName = $userName
                SamAccountName = "N/A"
                TargetGroup = $targetGroup
                Status = "Failed - $($_.Exception.Message)"
                DistinguishedName = "N/A"
            }
        }
    }
    
    return $assignmentResults
}

# Function to get all domain users and show group assignments
function Get-AllDomainUsersWithGroups {
    try {
        Write-Host "Retrieving all domain users..." -ForegroundColor Green
        
        $DomainInfo = Get-ADDomain
        $AllUsers = Get-ADUser -Filter * -Server $DomainInfo.PDCEmulator -Properties Name, SamAccountName, DistinguishedName, Enabled, MemberOf
        
        # Filter domain users only
        $DomainUsers = @()
        foreach ($User in $AllUsers) {
            if ($User.DistinguishedName -like "*$($DomainInfo.DistinguishedName)") {
                $groups = ($User.MemberOf | ForEach-Object { 
                    try { (Get-ADGroup $_).Name } catch { "Unknown" }
                }) -join "; "
                
                $DomainUsers += [PSCustomObject]@{
                    Name = $User.Name
                    SamAccountName = $User.SamAccountName
                    Enabled = $User.Enabled
                    Groups = $groups
                    DistinguishedName = $User.DistinguishedName
                    IsTargetUser = $userGroupMappings.ContainsKey($User.Name)
                    ExpectedGroup = if($userGroupMappings.ContainsKey($User.Name)) { $userGroupMappings[$User.Name] } else { "N/A" }
                }
            }
        }
        
        return $DomainUsers
    } catch {
        Write-Error "Failed to retrieve domain users: $($_.Exception.Message)"
        return $null
    }
}

# Function to generate assignment report
function Generate-AssignmentReport {
    param($AssignmentResults, $AllDomainUsers)
    
    Write-Host "`n" + "="*60 -ForegroundColor Magenta
    Write-Host "USER GROUP ASSIGNMENT REPORT" -ForegroundColor Magenta
    Write-Host "="*60 -ForegroundColor Magenta
    
    # Summary by group
    Write-Host "`nAssignment Summary by Group:" -ForegroundColor Cyan
    foreach ($group in $requiredGroups) {
        $groupUsers = $AssignmentResults | Where-Object { $_.TargetGroup -eq $group }
        $successCount = ($groupUsers | Where-Object { $_.Status -eq "Added" -or $_.Status -eq "Already Member" }).Count
        Write-Host "  $group`: $successCount/$($groupUsers.Count) users assigned" -ForegroundColor White
    }
    
    # Detailed results
    Write-Host "`nDetailed Assignment Results:" -ForegroundColor Cyan
    $AssignmentResults | Format-Table UserName, TargetGroup, Status -AutoSize
    
    # Show target users and their current group memberships
    Write-Host "`nTarget Users Current Group Memberships:" -ForegroundColor Cyan
    $targetUsers = $AllDomainUsers | Where-Object { $_.IsTargetUser -eq $true }
    $targetUsers | Format-Table Name, ExpectedGroup, Groups -AutoSize
}

# Main execution
Write-Host "Domain User Discovery and Group Assignment Script" -ForegroundColor Magenta
Write-Host "=" * 50 -ForegroundColor Magenta

# Step 1: Get all domain users
$AllDomainUsers = Get-AllDomainUsersWithGroups

if ($AllDomainUsers) {
    Write-Host "Found $($AllDomainUsers.Count) total domain users" -ForegroundColor Green
    
    # Step 2: Assign users to appropriate groups
    $AssignmentResults = Assign-UsersToGroups
    
    # Step 3: Generate comprehensive report
    Generate-AssignmentReport -AssignmentResults $AssignmentResults -AllDomainUsers $AllDomainUsers
    
    # Step 4: Export results
    $exportPath = "C:\Temp\UserGroupAssignments.csv"
    $AssignmentResults | Export-Csv -Path $exportPath -NoTypeInformation
    Write-Host "`nResults exported to: $exportPath" -ForegroundColor Green
    
} else {
    Write-Host "Failed to retrieve domain users. Script terminated." -ForegroundColor Red
}

Write-Host "`nScript completed!" -ForegroundColor Magenta
