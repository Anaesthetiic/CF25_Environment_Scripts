# Define Root Share Directory
$rootShare = "\\ent-srv-fil-001\fileshare"
$subDirs = @("Engineering", "Finance", "HR", "IT", "RND", "Sysinternals", "Test", "Users")

# Get Current Domain
$domain = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).Name
Write-Output "Detected Domain: $domain"

# Define OU Mappings
$ouMap = @{
    "Engineer-User" = "OU=ESM,OU=Tier 2"
    "Finance-User"  = "OU=FIN,OU=Tier 2"
    "HR-User"       = "OU=HRE,OU=Tier 2"
    "IT-User"       = "OU=Tier 2"
    "Reg-Users"     = "OU=Tier 2"
}

# Define Group Users
$users = @{
    "Engineer-User" = @("Monica Torres", "Patrick Peterson", "Diana Gray", "Thomas Ramirez", "Kristen James")
    "Finance-User"  = @("Anna Patterson", "Connor Hughes", "Caroline Flores", "Luke Washington", "Janet Butler")
    "HR-User"       = @("Brian Martin", "Lisa Lee", "Jason Walker", "Rachel Hall", "Justin Allen")
    "IT-User"       = @("Anthony Evans", "Tiffany Edwards", "Jacob Collins", "Amber Stewart", "William Sanchez")
    "Reg-Users"     = @("James Anderson", "Sarah Mitchell", "David Rodriguez", "Emily Thompson", "Michael Johnson")
}

# Create Directories and Preserve Existing Permissions
foreach ($dir in $subDirs) {
    $fullPath = Join-Path $rootShare $dir
    if (!(Test-Path $fullPath)) {
        New-Item -ItemType Directory -Path $fullPath | Out-Null
        Write-Output "Created directory: $fullPath"
    } else {
        Write-Output "Directory already exists: $fullPath"
    }
}

# Function to grant access
function Grant-Access {
    param (
        [string]$path,
        [string]$user,
        [string]$perm
    )
    icacls $path /grant "${user}:$perm" /T | Out-Null
    Write-Output "Granted $perm access to $user on $path"
}

# Verify User Exists
function Validate-User {
    param ([string]$fullName)
    $user = Get-ADUser -Filter "Name -eq '$fullName'" -ErrorAction SilentlyContinue
    if (!$user) {
        throw "ERROR: User '$fullName' does not exist in domain $domain"
    }
}

# Verify or Create Group
function Validate-OrCreate-Group {
    param ([string]$groupName)
    $existing = Get-ADGroup -Filter { Name -eq $groupName } -ErrorAction SilentlyContinue
    if (!$existing) {
        $groupPath = "OU=Groups,DC=$($domain.Split('.')[0]),DC=$($domain.Split('.')[1])"
        New-ADGroup -Name $groupName -GroupScope Global -GroupCategory Security -Path $groupPath | Out-Null
        Write-Output "Created missing group: $groupName"
    } else {
        Write-Output "Group already exists: $groupName"
    }
}

# Assign user group permissions
foreach ($group in $users.Keys) {
    $groupUsers = $users[$group]

    $dirName = switch ($group) {
        "Engineer-User" { "Engineering" }
        "Finance-User"  { "Finance" }
        "HR-User"       { "HR" }
        "IT-User"       { "IT" }
        "Reg-Users"     { "Users" }
    }
    $dirPath = Join-Path $rootShare $dirName

    # Validate groups
    Validate-OrCreate-Group "$group"
    $computerGroup = "$group-Computer"
    Validate-OrCreate-Group "$computerGroup"

    foreach ($user in $groupUsers) {
        Validate-User $user
        Grant-Access -path $dirPath -user "$domain\$user" -perm "M"
    }

    # Grant Computer group read access
    Grant-Access -path $dirPath -user "$domain\$computerGroup" -perm "R"
}

# Assign IT Read access to all folders, Modify to IT folder
$itUsers = $users["IT-User"]
foreach ($itUser in $itUsers) {
    Validate-User $itUser
    foreach ($dir in $subDirs) {
        $perm = if ($dir -eq "IT") { "M" } else { "R" }
        $path = Join-Path $rootShare $dir
        Grant-Access -path $path -user "$domain\$itUser" -perm $perm
    }
}

Write-Output "Permission assignment complete."
