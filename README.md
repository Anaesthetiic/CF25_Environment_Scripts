# CF25_Environment_Scripts
SetGPO and Validator Scripts for CF25 CASTLE Environment

# **WIP Last updated: 01 Aug 25**

# Notes
- GPO names are suffixed "TC" for test purposes but can be removed so long as all instances of GPO name is updated
- Expect Validator Script output to fail for GPOs: "Map Network Drives_TC" and "System Update_TC" until requirements below are fulfilled

Additional Requirements:
- SetGPO Script
  - GPO: "Map Network Drives_TC". Integrate filesharePermission&GroupHandler.ps1 into SetGPO Script to fulfill GPO Creation Function #5 (removed due to bugs)
  - GPO: "System Update_TC". Resolve GPO Creation Function #13 which properly instatiates scripts but does not "add" it to GPO in Group Policy Management Module
- Validator Script
  - GPO: "Map Network Drives_TC". Must align with GPO Creation Function #5 and verifies the permissions of each group in fileshare
  - GPO: "System Update_TC". For GPO Creation Function #13, verify it identifies launch_wiper.bat in Computer Configuration > Windows Settings > Scripts > Startup
    and  super_wiper.ps1 in Computer Configuration > Windows Settings > Scripts > Startup
 
  
