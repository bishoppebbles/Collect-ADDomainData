# Collect-ADDomainData (aka FakeHyena)
This is a collection of commands to pull a variety of datasets in an Active Directory (AD) domain environment or on standalone systems.  If you're familiar with the tool Hyena, this reproduces some of its collection capability but can pull data exponentially faster due to the parallel operation of PowerShell's `Invoke-Command`.  Credit for the `FakeHyena` name goes to Kennon Lee.

## Usage
```powershell
# Collects datasets for domain systems using the AD domain distinguished name of the script host system.
Collect-ADDomainData.ps1

# Collects all datasets for domain systems using the AD domain distinguished name of the script host system.  This includes server specific features plus Active Directory and DHCP data.
Collect-ADDomainData.ps1 -DHCPServer dhcpsvr01 -IncludeServerFeatures -IncludeActiveDirectory

# Collects datasets for domain systems using the AD domain distinguished name of the script host and the specified Organization Unit (OU).
Collect-ADDomainData.ps1 -OUName 'Finance'

# Collects datasets for domain systems using the AD domain distinguished name of the script host and the specified Organization Unit (OU).  It also collects Windows DHCP server scopes and leases, Windows Server feature and roles information, and Active Directory datasets.
Collect-ADDomainData.ps1 -OUName 'Finance' -DHCPServer dhcpsvr01 -IncludeServerFeatures -IncludeActiveDirectory

# Collects only Windows DHCP server scope and lease information.
Collect-ADDomainData.ps1 -DHCPServer dhcpsvr01 -DHCPOnly

# Collects only Windows Active Directory domain user object and group memberships datasets using the AD domain distinguished name of the script host.
Collect-ADDomainData.ps1 -ActiveDirectoryOnly

# Collects only Windows Active Directory domain user object and group memberships datasets using the AD domain distinguished name of the script host and the specified Organization Unit (OU).
Collect-ADDomainData.ps1 -OUName 'Detroit' -ActiveDirectoryOnly

# Collects the datasets for the local system on the script host.
Collect-ADDomainData.ps1 -LocalCollectionOnly

# Run with the OUName parameter and the Migrated switch to target a specific OU location of interest.  You must also specify the Region, SearchBase, and Server paramters for any query with the Migrated switch.
Collect-ADDomainData.ps1 -OUName Manila -Migrated -Region Asia -SearchBase 'ou=location,dc=company,dc=org' -Server company.org

# The same as the last example but only try collection for systems that previously failed their WinRM connection for PS Remoting
Collect-ADDomainData.ps1 -OUName Manila -Migrated -Region Asia -SearchBase 'ou=location,dc=company,dc=org' -Server company.org -FailedWinRM

# Run collection for all applicable datasets using the Migrated switch.
Collect-ADDomainData.ps1 -OUName Manila -Migrated -Region Asia -SearchBase 'ou=location,dc=company,dc=org' -Server company.org -DHCPServer dhcpsvr01 -IncludeServerFeatures -IncludeActiveDirectory

# Run collection with the Migrated switch and only pull server specific collection (ServerFeaturesOnly) that previously failed (FailedWinRM).
Collect-ADDomainData.ps1 -OUName Manila -Migrated -Region Asia -SearchBase 'ou=location,dc=company,dc=org' -Server company.org -FailedWinRM -ServerFeaturesOnly

# Run Active Directory only collection with the Migrated switch.
Collect-ADDomainData.ps1 -OUName Manila -Migrated -Region Asia -SearchBase 'ou=location,dc=company,dc=org' -Server company.org -ActiveDirectoryOnly
```

### Requirements
This code requires the use of PowerShell (PS) Remoting so this must be enabled and accessible in your target environment.  Check *Appendix A* below for a detailed walkthrough on doing this.  I also wrote code to run these commands locally as well.  This can be used if PS Remoting isn't an option or to ensure you capture the dataset of the host system.

#### Enabling PS Remoting with Group Policy (GUI walkthrough in *Appendix A*)
1) Enable the WinRM service
  * `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service > Allow remote server management through WinRM`
    * Set `IPv4/IPv6 filters to all (*)`

2) Set the WS-Management service to automatic startup
  * `Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Windows Remote Management (WS-Management)`

3) Allow Windows Remote Management in the Firewall
  * Navigate to the following folder in the Group Policy Management Console (GPMC), right-click `Inbound Rules`, and click `New Rule`.
    * `Computer Configuration > Policies > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall with Advanced Security`
      * In the `Predefined` field, select `Windows Remote Management` and then follow the wizard to add the new firewall rule.

#### Enable PS Remoting with WMI
There may be circumstances where you have local admin in your target environment but no access to a domain controller or server with the Group Policy Management MMC console.  In those cases it may be possible to enable PS Remoting using the PowerShell CIM cmdlets with DCOM.  Since you need WinRM to use PS Remoting you can't use that here if it hasn't been enabled.  If it was, this wouldn't be necessary.

```powershell
# Attempt to enable WinRM/PS remoting via WMI for systems that don't have it configured
$comps = <computer_name_array>
$cimSessOption = New-CimSessionOption -Protocol Dcom

foreach($c in $comps) {
    if(Test-Connection $c -Count 2) {          
        $cimSession = New-CimSession -ComputerName $c -SessionOption $cimSessOption
        Invoke-CimMethod -ClassName 'Win32_Process' `
                         -MethodName 'Create' `
                         -CimSession $cimSession `
                         -Arguments @{CommandLine = "powershell Start-Process powershell -ArgumentList 'Enable-PSRemoting -Force'"} |
            Out-Null
        $cimSession | Remove-CimSession

        if(Test-WSMan -ComputerName $c) {
            Write-Output "PS Remoting was enabled on $c"
        } else {
            Write-Output "PS Remoting was not enabled on $c"
        }
    } else {
        Write-Output "$c is not reach able"
    }
}
```

## Workstation and Server Datasets
* **Local group Memberships**
    * Output fields: GroupName, Name, Domain, SID, PrincipalSource, ObjectClass
* **Local user accounts**
    * Output fields: Name, SID, RID (calculated), Enabled, PasswordRequired, PasswordChangeable (calculated), PrincipalSource, Description, PasswordLastSet, LastLogon
* **Processes**
    * Output fields: Name, Id, Path, Hash (calculated), UserName, Company, Description, ProductVersion, StartTime
* **Scheduled tasks**
    * Output fields: TaskName (unique suffixes removed), State, Author, TaskPath, Description
* **Services**
    * Output fields: Name (unique suffixes removed), DisplayName (unique suffixes removed), Status, StartType, ServiceType
* **Network connections**
    * Output fields: Date, Time, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess , ProcessName (calculated)
* **File names** from the `Documents`, `Downloads`, or `Desktop` directories (recursively) for any user profile in `C:\Users`
    * Output fields: Name, Extension, Directory, CreationTime, LastAccessTime, LastWriteTime, Attributes
* **Program names** (i.e., directories) in `C:\Program Files` and `C:\Program Files (x86)`
    * Output fields: Name, CreationTime, LastAccessTime, LastWriteTime, Attributes, ProgramType (calculated 32/64 bit)
* **General system information**
    * Output fields: WindowsCurrentVersion, WindowsEditionId, WindowsVersion,	BiosManufacturer,	BiosSMBIOS, BIOSVersion,	BiosFirmwareType,	BiosReleaseDate,	BiosSeralNumber,	BiosCurrentLanguage,	CsDomain,	CsDomainRole,	CsManufacturer,	CsModel,	CsProcessors,	CsNumberOfProcessors,	CsNumberOfCores,	CsNumberOfLogicalProcessors,	CsPartOfDomain,	CsTotalPhysicalMemory (GB),	CsMaxClockSpeed,	OsName,	OsType,	OsVersion,	OsBuildNumber,	OsLocale,	OsManufacturer,	OsArchitecture,	OsLanguage,	KeyboardLayout,	TimeZone,	LogonServer,	PowerPlatformRole
* **System hot fix information**
    * Output fields: HotFixID, Description, InstalledOn
* **BitLocker information**
    * MountPoint, EncryptionMethod, AutoUnlockEnabled, AutoUnlockKeyStored, MetadataVersion, VolumeStatus, ProtectionStatus, LockStatus, EncryptionPercentage, WipePercentage, VolumeType, Capacity (GB), KeyProtector
* **Physical drive information**
    * OperationalStatus, HealthStatus, BusType, MediaType, SpindleSpeed, Manufacturer, Model, FirmwareVersion, IsPartial, LogicalSectorSize, PhysicalSectorSize, AllocatedSize (GB), Size (GB)
* **Hard drive volume storage information**
    * Name, Root, Description, Used (GB), Free (GB), DisplayRoot 
* **Shares**
    * Output fields: Name, Path, Description, EncryptData, CurrentUsers, ShareType
* **Share permissions**
    * Output fields: Name, AccountName, AccessControlType, AccessRight

## Server Specific Datasets
* **Windows installed features**
    * Name, DisplayName, Description, InstallState, Parent, Depth, Path, FeatureType
* **DHCP scopes**
    * ScopeId, SubnetMask, StartRange, EndRange, ActivatePolicies, LeaseDuration, Name, State, Type
* **DHCP leases**
    * IPAddress, ScopeId, AddressState, ClientId, ClientType, Description, HostName, LeaseExpiryTime, ServerIP

## Active Directory Datasets
* **AD computer objects**
    * DistinguishedName, Enabled, IPv4Address, LastLogonDate, Name, OperatingSystem, SamAccountName
* **AD user objects**
    * AccountExpirationDate, AccountNotDelegated, AllowReversiblePasswordEncryption, CannotChangePassword, DisplayName, Name, Enabled, LastLogonDate, LockedOut, PasswordExpired, PasswordNeverExpires, PasswordNotRequired, SamAccountName, SmartcardLogonRequired
* **AD group memberships**
    * UserSamAccountName, UserDN, UserName, GroupSamAccountName, GroupDN

### TODO
- [x] Fix local group member issues
- [x] Switch to run local collection
- [ ] Check if PS Remoting is enabled (maybe a switch)
- [ ] Check if the local PowerShell process is running elevated
- [x] Rerun a datapull for failed system checks

## Appendix A - PowerShell Remoting Group Policy Walkthrough
I’ve deployed the below group policy before and it also hasn’t worked as described.  Can’t say why but I assume there were other settings either in the domain or on the network that were blocking it and my sys/network admin skillz were too weak to sort it out.  Regardless, even if you create the policy but don’t link it to the domain’s computer objects it won’t do anything.  You can also try enforcing it too and maybe that will help override other conflicting settings, if applicable.

The default Group Policy background replication time is supposed to be 90 minutes with a randomized offset of up to 30 minutes.  With my math that means it can take up to 2 hours.  It’s also supposed to be updated when a domain computer reboots, a user logs on, or if you run the `gpupdate /force` command from the command prompt.

1. To view group policy settings, open the Group Policy Management console MMC (`gpmc.msc`).  If it’s not installed, with the right permissions or access you have options for Windows workstation or server.

2. Group Policy Management Windows 10 workstation installation.
    * Go to `Apps & features > Optional Features > Add a feature (click +)`
      * Install the `RSAT: Group Policy Management Tools`

       ![](/img/01a_rsat_gp_install.PNG)
 
    * To launch the tool you can find it in the Start menu or run `gpmc.msc`.

4. Group Policy Management Server installation.
    * Go to `Server Manager > Manage > Add Roles and Features`
      * Select 'Role-based or feature-based installation'
      * Select the server for installation under 'Server Selection'
      * Server Roles (click 'Next')
      * Select 'Group Policy Management' and click 'Next'
      * Click 'Install' (reboot is not required)

      ![](/img/01b_gp_feature_install.PNG)

    * To launch the tool you can run `gpmc.msc` go to `Server Manager > Tools > Group Policy Management`.

      ![](/img/01c_gp_tool.PNG)

4. The easiest potential approach is to link a new Group Policy Object (GPO) at the domain level.  If you have computer objects organized within an OU (or OUs) you can link at that granularity level as well.  You can’t link Group Policy (GP) to an Active Directory container.

    ![](/img/01d_create_gp.PNG)

5. Name your GPO.  I used ‘PowerShell Remoting’ for that.

    ![](/img/02_powershell_remoting.PNG)

6. If you link at the domain level you should see the new object there.  Otherwise it should be wherever you linked it.  

    ![](/img/03a_gp_linked.PNG)

7. Note that all GPOs are also stored in the “Group Policy Objects” container which is a second location that holds all GPOs, even ones that are not linked.  This is the “main” GPO repository I gather and the location where you can delete the GPO (more on that at the end).

    ![](/img/03b_gpo_locations.PNG)

8. Since I linked the GPO at the domain level I used ‘Security Filtering’ to ensure the security group holding all the domain computer objects (i.e., Domain Computers) would apply the linked policy.  If you link the policy directly to an OU with those computer objects instead then maybe/probably this isn’t necessary?  By default Authenticated Users group are already in this list.  I’d think if you remove that group it doesn’t matter in this regard but you get a big warning message so I kept it here.

    ![](/img/03c_security_filtering_add.PNG)

9. Search for Domain Computers to add to the ‘Security Filtering’ list.

    ![](/img/04_add_domain_computers_group.PNG)

10. Domain Computers added.

    ![](/img/04a_security_filtering.PNG)

11. Now it’s time to edit or actually create the policy.  Right click on the GPO and select ‘Edit’.  This opens the Group Policy Management Editor MMC (gpme.msc).

    ![](/img/05_edit_gp.PNG)

12. **Policy 1)** Enable the WinRM Service.  Navigate to:
    * `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service > Allow remote server management through WinRM`

      ![](/img/06_gp_winrm_service.PNG)

13. ‘Enable’ the policy and set `IPv4/IPv6 filters to all (*)`.

    ![](/img/07_gp_winrm_service_enabled.PNG)

14. **Policy 2)** Set the WS-Management service to automatic startup.  Navigate to:
    * `Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Windows Remote Management (WS-Management)`

      ![](/img/08_gp_ws-management.PNG)
    
15. Check ‘Define this policy setting’ and select ‘Automatic’.
  
    ![](/img/09_gp_ws-management_automatic.PNG)

16. **Policy 3)** Allow Windows Remote Management in the Firewall.  Navigate to:
    * `Computer Configuration > Policies > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Windows Defender Firewall with Advanced Security`
      * Right click on ‘Inbound Rules’ and select ‘New Rule’.

     ![](/img/10_gp_win_defender_new_rule.PNG)
      
17. Select ‘Predefined’ and select the ‘Windows Remote Management’ rule.

    ![](/img/11_gp_win_defender_predefined.PNG)
  
18. Keep both rules selected and click ‘Next’ (though the ‘Domain’ profile is what should be active).

    ![](/img/12_gp_win_defender_next.PNG)
  
19. Keep ‘Allow the connection’ selected and click ‘Finish’.

    ![](/img/13_gp_win_defender_finish.PNG)
  
20. After exiting the GPO editing window you can check the status under the ‘Settings’ tab.  This shows object ‘Links’ and ‘Security Filtering’ settings.

    ![](/img/14_settings_general.PNG)
  
21. This shows the confirmation for **Policy 2** (WSMan automatic service startup).

    ![](/img/15_settings_system_services.PNG)
  
22. This shows the confirmation for **Policy 3** (firewall rules).

    ![](/img/16_settings_firewall.PNG)
  
23. This shows the confirmation for **Policy 1** (enabling WinRM).

    ![](/img/17_settings_winrm_remote_service.PNG)
  
24. GPO precedence (from lowest to highest): `Local Group Policy > Site Level > Domain Level > Organization Unit Level`
    * Nested OUs have high precedence than their parent OU.
    * GPO enforcement ensures Group Policy linked with a lower-level precedence at a higher-level container (e.g., at the domain or parent OU level) will take precedence over the GPOs linked at a lower-level container with a higher precedence (e.g., the OU level).  Using enforcement will also override a lower-level container that is blocking inheritance.  You can optionally enforce a GPO by right clicking on it and selecting ‘Enforced’.

    ![](/img/17a_enforced.PNG)
  
25. Unless post wants to keep PowerShell remoting enabled at the end of the CSA it’s a good idea to clean up after yourself and delete the GPO from their AD environment (*additional note/thought on this below).  If you right click on a GPO at it’s linked location and select ‘Delete’ that will only delete the link, not the actual Group Policy Object from AD.

    ![](/img/18a_delete_gpo_link_only_right_click.PNG)
  
26. A warning message is provided notifying you that only the link will be deleted.  Click ‘OK’ to proceed.

    ![](/img/18b_delete_gpo_link_only.PNG)
  
27. Instead, you should right click and select ‘Delete’ on the GPO listed in the ‘Group Policy Objects’ container as that will delete the Group Policy Object as well as any associated links within the domain.

    ![](/img/18c_delete_gpo_and_links_right_click.PNG)
  
28. A warning message is provided notifying you that the object as well as any associated domain links will be deleted.  Click ‘Yes’ to proceed.

    ![](/img/19_delete_gpo_and_links.PNG)
  
29. One thing I don’t know and need to test/research is that just because you delete a GPO doesn’t mean it reverts the changes it made.  I think sometimes yes and sometimes no.  In this instance I believe any system that took this GPO will remain in the current state (i.e., PS remoting is still enabled).  Any new systems added to the domain after the point that the GPO was removed will not have these features enabled.  Thinking about this I guess if you wanted to “turn off” PS remoting you’d have to rewrite the policy to undo the changes and wait for it to replicate and/or use an alternate method of doing so (e.g., WMI with DCOM vice WinRM).
