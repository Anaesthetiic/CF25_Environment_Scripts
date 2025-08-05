# CF25_Environment_Scripts
SetGPO and Validator Scripts for CF25 CASTLE Environment

# **WIP Last updated: 05 Aug 25**

# Notes
- GPO names are suffixed "TC" for test purposes but can be removed so long as all instances of GPO name is updated UPDATE: This only applies to certain scripts. This is not the case for the validator, and the brute force method script.
- Expect Validator Script output to fail for GPOs: "Map Network Drives_TC" and "System Update_TC" until requirements below are fulfilled

# Additional Requirements
- SetGPO Script
  - GPO: "Map Network Drives_TC". Integrate "CF25_Fileshare_Permission_Group_Handler.ps1" into SetGPO Script to fulfill GPO Creation Function #5 (removed due to bugs)
  - GPO: "System Update_TC". Resolve GPO Creation Function #13 which properly instatiates scripts but does not "add" it to GPO in Group Policy Management Module
- Validator Script
  - GPO: "Map Network Drives_TC". Must align with GPO Creation Function #5 and verifies the permissions of each group in fileshare
  - GPO: "System Update_TC". For GPO Creation Function #13, verify it identifies launch_wiper.bat in Computer Configuration > Windows Settings > Scripts > Startup
    and  super_wiper.ps1 in Computer Configuration > Windows Settings > Scripts > Startup

 # Instructions
- CF25_UserAssign & CF25_Fileshare_Permission_Group_Handler
  - Discover and hook into the VPC's Domain.
  - Discover/Create User Domain Groups:
    - Engineer-User
    - Finance-User
    - HR-User
    - IT-User
    - Reg-User
  - Finds the user list provided in the excel sheet, issues these users their appropriate group.
  - Sets these groups to be sub-groups of their respected Computer group.
  - Locates \\ent-srv-fil-001\fileshare (usually already configured) and creates all the Directories after it takes ownership over the fileshare:
    - Engineering, Finance, HR, IT, RND, Sysinternals (usually already installed), Test, Users
  - Sets appropriate domain groups to the directories, with RW for members of the respected directory (eg. Finance-User to Finance) and all types of admins, and R permission to IT.
