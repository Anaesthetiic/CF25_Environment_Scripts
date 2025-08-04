# Get Current Domain
$domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
Write-Output "Detected Domain: $domain"

# ------------------- FILE SHARE PERMISSION CONFIGURATION -------------------

# Define Root Share Path
$rootShare = "\\ent-srv-fil-001\fileshare"
$subDirs = @("Engineering", "Finance", "HR", "IT", "RND", "Sysinternals", "Test", "Users")

# Ensure root exists
if (!(Test-Path $rootShare)) {
    New-Item -ItemType Directory -Path $rootShare | Out-Null
    Write-Output "Created root share: $rootShare"
} else {
    Write-Output "Root share already exists: $rootShare"
}

# Restrict root share to Read for Domain Users
icacls $rootShare /grant "$domain\Domain Users:R" /T | Out-Null
Write-Output "Granted Domain Users read-only access to $rootShare"

# Create subdirectories and set permissions
foreach ($dir in $subDirs) {
    $fullPath = Join-Path $rootShare $dir
    if (!(Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath | Out-Null
        Write-Output "Created subdirectory: $fullPath"
    }
}

# Permission Mapping
$permMap = @{
    "Engineering"   = @{ RW = @("Engineer-User", "Domain Admins"); R = @("IT-User") }
    "Finance"       = @{ RW = @("Finance-User", "Domain Admins"); R = @("IT-User") }
    "HR"            = @{ RW = @("HR-User", "Domain Admins"); R = @("IT-User") }
    "IT"            = @{ RW = @("IT-User", "Domain Admins"); R = @() }
    "Users"         = @{ RW = @("Reg-Users", "Domain Admins"); R = @("IT-User") }
    "RND"           = @{ RW = @("Engineer-User", "Domain Admins"); R = @("IT-User") }
    "Sysinternals" = @{ RW = @("Domain Admins"); R = @("Domain Users") }
    "Test"          = @{ RW = @("Domain Admins"); R = @() }}

# Take ownership if current user is not the owner
foreach ($dir in $permMap.Keys) {
    $path = Join-Path $rootShare $dir
    $currentOwner = (Get-Acl $path).Owner
    $adminUser = "$env:USERDOMAIN\$env:USERNAME"

    if ($currentOwner -ne $adminUser -and $currentOwner -ne "$domain\Domain Admins") {
        try {
            takeown /F $path /R /D Y | Out-Null
            icacls $path /setowner "$adminUser" /T | Out-Null
            Write-Output "Ownership of $path transferred to $adminUser (previously owned by $currentOwner)"
        } catch {
            Write-Warning ('Failed to take ownership of ' + $path + ': ' + $_)
        }
    } else {
        Write-Output "$path is already owned by $currentOwner"
    }
}

# Break inheritance and remove explicit group grants before setting new ones
foreach ($dir in $permMap.Keys) {
    $path = Join-Path $rootShare $dir

    # Disable inheritance but retain existing permissions
    icacls $path /inheritance:d | Out-Null
    Write-Output "Disabled inheritance on $path"

    # Remove known group permissions
    icacls $path /remove:g "${domain}\Domain Users" "${domain}\HR-User" "${domain}\IT-User" `
                        "${domain}\Engineer-User" "${domain}\Finance-User" "${domain}\Reg-Users" `
                        "${domain}\Domain Admins" | Out-Null
    Write-Output "Stripped existing group permissions on $path"
}


# Apply Permissions
foreach ($dir in $permMap.Keys) {
    $path = Join-Path $rootShare $dir
    $rwGroups = $permMap[$dir].RW
    $rGroups  = $permMap[$dir].R

    foreach ($group in $rwGroups) {
        icacls $path /grant:r "${domain}\${group}:(OI)(CI)M" /T | Out-Null
        Write-Output "Granted Modify access to $group on $path"
    }

    foreach ($group in $rGroups) {
        icacls $path /grant:r "${domain}\${group}:(OI)(CI)R" /T | Out-Null
        Write-Output "Granted Read access to $group on $path"
    }
}
# Force Group Policy update
Write-Output "Forcing Group Policy Update..."
gpupdate /force | Out-Null
Write-Output "Group Policy refreshed."
# Configure share-level permissions
$shareName = "fileshare"

$shareGroups = @{
    "Engineer-User" = "Change"
    "Finance-User"  = "Change"
    "HR-User"       = "Change"
    "IT-User"       = "Change"
    "Reg-Users"     = "Change"
    "Domain Admins" = "Full"
    "Domain Users"  = "Read"
}

foreach ($group in $shareGroups.Keys) {
    $access = $shareGroups[$group]
    Grant-SmbShareAccess -Name $shareName -AccountName "${domain}\$group" -AccessRight $access -Force -ErrorAction Stop
    Write-Output "Granted $access share access to $group on \$shareName"
}

Write-Output "File share permissions applied successfully."
