<#
.SYNOPSIS
    Collects various Windows workstation and server and/or domain datasets: local user accounts, local group memberships, processes, scheduled tasks, services, network connections, locally saved files, 32/64-bit installed programs, general system information, installed hot fixes, shares, share permissions, Active Directory users|computers|group memberships, Windows DHCP server scopes and leases, and Windows Server installed roles and features.
.DESCRIPTION
    By default this script collects various system datasets from workstations and servers in a Windows Active Directory (AD) domain environment as well as some AD datasets.  It also has an option to collect the same datasets for the local system.  This can be useful for non-domain joined (i.e., "standalone") systems.
.PARAMETER OUName
    The specific OU name of interest.  Can be used to limit the collection scope in a domain environment.
.PARAMETER Migrated
    Switch to use if computer objects have migrated to a different domain.
.PARAMETER Region
    The specific target region.
.PARAMETER SearchBase
    The top level distinguished name path to use for computer object searching.
.PARAMETER Server
    The server to use for the target domain.
.PARAMETER DHCPServer
    Specify the server name if collecting Windows DHCP server scope and lease information with other domain data.
.PARAMETER IncludeServerFeatures
    Collect installed Windows Server feature and role information with other domain data.
.PARAMETER IncludeActiveDirectory
    Collect AD database user object and group membership information with other domain data.
.PARAMETER DHCPOnly
    Only collect Windows DHCP server scope and lease information.  The DHCP server name must also be provided with the -DHCPServer option.
.PARAMETER ServerFeaturesOnly
    Only collect installed Windows Server feature and role information.
.PARAMETER ActiveDirectoryOnly
    Only collect AD database user object and group membership information.
.PARAMETER LocalCollectionOnly
    Collect the datasets on the local system (does not use PowerShell remoting functionality).
.PARAMETER FailedWinRM
    Try to collection systems that previously failed the WinRM connection attempt.
.EXAMPLE
    .\Collect-ADDomainData.ps1
    Collects datasets for domain systems using the AD domain distinguished name of the script host.
.EXAMPLE
    .\Collect-ADDomainData.ps1 -DHCPServer dhcpsvr01 -IncludeServerFeatures -IncludeActiveDirectory
    Collects all datasets for domain systems using the AD domain distinguished name of the script host system.  This includes server specific features plus Active Directory and DHCP data.
.EXAMPLE
    .\Collect-ADDomainData.ps1 -OUName 'Finance'
    Collects datasets for domain systems using the AD domain distinguished name of the script host and the specified Organization Unit (OU).
.EXAMPLE
    .\Collect-ADDomainData.ps1 -OUName 'Finance' -DHCPServer dhcpsvr01 -IncludeServerFeatures -IncludeActiveDirectory
    Collects datasets for domain systems using the AD domain distinguished name of the script host and the specified Organization Unit (OU).  It also collects Windows DHCP server scopes and leases, Windows Server feature and roles information, and Active Directory datasets.
.EXAMPLE
    .\Collect-ADDomainData.ps1 -DHCPServer dhcpsvr01,dhcpsvr02 -DHCPOnly
    Collects only Windows DHCP server scope and lease information.
.EXAMPLE
    .\Collect-ADDomainData.ps1 -ActiveDirectoryOnly
    Collects only Windows Active Directory domain user object and group memberships datasets using the AD domain distinguished name of the script host.
.EXAMPLE
    .\Collect-ADDomainData.ps1 -OUName 'Detroit' -ActiveDirectoryOnly
    Collects only Windows Active Directory domain user object and group memberships datasets using the AD domain distinguished name of the script host and the specified Organization Unit (OU).
.EXAMPLE
    .\Collect-ADDomainData.ps1 -LocalCollectionOnly
    Collects the datasets for the local system on the script host.
.EXAMPLE
	.\Collect-ADDomainData.ps1 -OUName Manila -Migrated -Region Asia -SearchBase 'ou=location,dc=company,dc=org' -Server company.org
    Run with the OUName parameter and the Migrated switch to target a specific OU location of interest.  You must also specify the Region, SearchBase, and Server paramters for any query with the Migrated switch.
.EXAMPLE
	.\Collect-ADDomainData.ps1 -OUName Manila -Migrated -Region Asia -SearchBase 'ou=location,dc=company,dc=org' -Server company.org -FailedWinRM
    The same as the last example but only try collection for systems that previously failed their WinRM connection for PS Remoting
.EXAMPLE
    .\Collect-ADDomainData.ps1 -OUName Manila -Migrated -Region Asia -SearchBase 'ou=location,dc=company,dc=org' -Server company.org -DHCPServer dhcpsvr01 -IncludeServerFeatures -IncludeActiveDirectory
    Run collection for all applicable datasets using the Migrated switch.
.EXAMPLE
    .\Collect-ADDomainData.ps1 -OUName Manila -Migrated -Region Asia -SearchBase 'ou=location,dc=company,dc=org' -Server company.org -FailedWinRM -ServerFeaturesOnly
    Run collection with the Migrated switch and only pull server specific collection (ServerFeaturesOnly) that previously failed (FailedWinRM).
.EXAMPLE
    Collect-ADDomainData.ps1 -OUName Manila -Migrated -Region Asia -SearchBase 'ou=location,dc=company,dc=org' -Server company.org -ActiveDirectoryOnly
    Run Active Directory only collection with the Migrated switch.
.NOTES
    Version 1.0.37
    Author: Sam Pursglove
    Last modified: 31 October 2024

    FakeHyena name credit goes to Kennon Lee.

    **Steps to enable PS Remoting via Group Policy**

    1) Enable the WinRM service (set IPv4/IPv6 filters to all (*))
	    Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service > Allow remote server management through WinRM

    2) Set the WS-Management service to automatic startup
	    Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Windows Remote Management (WS-Management)

    3) Allow Windows Remote Management in the Firewall
	    Navigate to the following folder in the Group Policy Management Console (GPMC), right-click Inbound Rules, and click New Rule.

		    Computer Configuration > Policies > Windows Settings > Security Settings > Windows (Defender) Firewall with Advanced Security

		    In the Predefined field, select Windows Remote Management and then follow the wizard to add the new firewall rule.
#>

[CmdletBinding(DefaultParameterSetName='Domain')]
param (
    [Parameter(ParameterSetName='Domain', Mandatory=$False, Position=0, HelpMessage='Target OU name')]
    [Parameter(ParameterSetName='Migrated', Mandatory=$True, Position=0, HelpMessage='Target OU name')]
    [Parameter(ParameterSetName='ServerFeaturesOnly', Mandatory=$False, Position=0, HelpMessage='Target OU name')]
    [Parameter(ParameterSetName='ServerFeaturesOnlyMigrated', Mandatory=$True, Position=0, HelpMessage='Target OU name')]
    [Parameter(ParameterSetName='ADOnly', Mandatory=$False, Position=0, HelpMessage='Target OU name')]
    [Parameter(ParameterSetName='ADOnlyMigrated', Mandatory=$True, Position=0, HelpMessage='Target OU name')]
    [string]$OUName = '',

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Switch to change the search type for AD migrated systems')]
    [Parameter(ParameterSetName='ServerFeaturesOnlyMigrated', Mandatory=$True, HelpMessage='Switch to change the search type for AD migrated systems')]
    [Parameter(ParameterSetName='ADOnlyMigrated', Mandatory=$True, HelpMessage='Switch to change the search type for AD migrated systems')]
    [Switch]$Migrated,

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Target region name')]
    [Parameter(ParameterSetName='ServerFeaturesOnlyMigrated', Mandatory=$True, HelpMessage='Target region name')]
    [Parameter(ParameterSetName='ADOnlyMigrated', Mandatory=$True, HelpMessage='Target region name')]
    [string]$Region = '',

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Domain searchbase')]
    [Parameter(ParameterSetName='ServerFeaturesOnlyMigrated', Mandatory=$True, HelpMessage='Domain searchbase')]
    [Parameter(ParameterSetName='ADOnlyMigrated', Mandatory=$True, HelpMessage='Domain searchbase')]
    [string]$SearchBase = '',

    [Parameter(ParameterSetName='Migrated', Mandatory=$True, HelpMessage='Domain controller server')]
    [Parameter(ParameterSetName='ServerFeaturesOnlyMigrated', Mandatory=$True, HelpMessage='Domain controller server')]
    [Parameter(ParameterSetName='ADOnlyMigrated', Mandatory=$True, HelpMessage='Domain controller server')]
    [string]$Server = '',
    
    [Parameter(ParameterSetName='Domain', Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Collect DHCP server scope and lease data')]
    [Parameter(ParameterSetName='Migrated', Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Collect DHCP server scope and lease data')]
    [Parameter(ParameterSetName='DHCPOnly', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Collect DHCP server scope and lease data')]
    $DHCPServer = @(),

    [Parameter(ParameterSetName='Domain', Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Collect Windows Server Feature data')]
    [Parameter(ParameterSetName='Migrated', Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Collect Windows Server Feature data')]
    [Parameter(ParameterSetName='Local', Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Collect Windows Server Feature data')]
    [Switch]$IncludeServerFeatures,

    [Parameter(ParameterSetName='Domain', Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Collect AD user and group membership data')]
    [Parameter(ParameterSetName='Migrated', Mandatory=$False, ValueFromPipeline=$False, HelpMessage='Collect AD user and group membership data')]
    [Switch]$IncludeActiveDirectory,

    [Parameter(ParameterSetName='DHCPOnly', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Collect DHCP server scope and lease data')]
    [Switch]$DHCPOnly,
    
    [Parameter(ParameterSetName='ServerFeaturesOnly', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Collect Windows Server Feature data')]
    [Parameter(ParameterSetName='ServerFeaturesOnlyMigrated', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Collect Windows Server Feature data')]
    [Switch]$ServerFeaturesOnly,

    [Parameter(ParameterSetName='ADOnly', Mandatory=$False, ValueFromPipeline=$True, HelpMessage='Collect AD user and group membership data')]
    [Parameter(ParameterSetName='ADOnlyMigrated', Mandatory=$False, ValueFromPipeline=$True, HelpMessage='Collect AD user and group membership data')]
    [Switch]$ActiveDirectoryOnly,

    [Parameter(ParameterSetName='Local', Mandatory=$True, ValueFromPipeline=$False, HelpMessage='Collects local system data, not domain systems')]
    [Switch]$LocalCollectionOnly,

    [Parameter(ParameterSetName='Domain', Mandatory=$False, HelpMessage='Try to collection systems that previous failed the WinRM connection attempt')]
    [Parameter(ParameterSetName='Migrated', Mandatory=$False, HelpMessage='Try to collection systems that previous failed the WinRM connection attempt')]
    [Parameter(ParameterSetName='ServerFeaturesOnly', Mandatory=$False, HelpMessage='Try to collection systems that previous failed the WinRM connection attempt')]
    [Parameter(ParameterSetName='ServerFeaturesOnlyMigrated', Mandatory=$False, HelpMessage='Try to collection systems that previous failed the WinRM connection attempt')]
    [switch]$FailedWinRM
)


### Functions ###

# Get system TCP session and related process information
function netConnects {
    $hashtable = @{}
    $date = Get-Date -Format "MM/dd/yyyy"
    $time = Get-Date -Format "HH:mm"
    
    # used to map to the process name to the TCP connection process ID
    Get-Process | 
        ForEach-Object { 
            $hashtable.$($_.Id) = $_.ProcessName
        }

    Get-NetTCPConnection -State Listen,Established |
        Select-Object @{Name='Date'; Expression={$date}},@{Name='Time'; Expression={$time}},LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,@{Name='ProcessName'; Expression={$hashtable[[int]$_.OwningProcess]}}
}



# Try to first get local user account info using the PS cmdlet but if that is unavailable use WMI to get the data
function getLocalUsers {
    $date = Get-Date

    try {
        Get-LocalUser |
            Select-Object Name,
                          SID,
                          @{Name='RID'; Expression={[regex]::Match($_.SID, '\d+$').Value}},
                          Enabled,
                          PasswordRequired,
                          @{Name='PasswordChangeable'; Expression={$_.UserMayChangePassword}},
                          PrincipalSource,
                          Description,
                          PasswordLastSet,
                          @{Name='PasswordLastSetDays'; Expression={if($_.PasswordLastSet -ne $null) {($date - $_.PasswordLastSet).TotalDays} else {''}}},
                          LastLogon
    } catch [System.Management.Automation.RuntimeException] {       
        Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" -Property * | 
            Select-Object Name,
                          SID,
                          @{Name='RID'; Expression={[regex]::Match($_.SID, '\d+$').Value}},
                          @{Name='Enabled'; Expression={if([bool]$_.Disabled) {'False'} else {'True'}}},
                          PasswordRequired,
                          PasswordChangeable,
                          @{Name='PrincipalSource';Expression={if([bool]$_.LocalAccount) {'Local'}}},
                          Description,
                          @{Name='PasswordLastSet'; Expression={''}},
                          @{Name='PasswordLastSetDays'; Expression={''}},
                          @{Name='LastLogon'; Expression={''}}
    }
}



# Try to first get the group membership of all local groups using PS cmdlets but if that is unavailable use ADSI
# note: attempts to query WMI data via the CIM cmdlets would not work in my domain environment locally or remotely and it's unknown why
#   1) Get-CimInstance -Query "Associators of {Win32_Group.Domain='$env:COMPUTERNAME',Name='Administrators'} where Role=GroupComponent"
#   2) Get-CimInstance -ClassName Win32_Group -Filter "Name='Administrators'" | Get-CimAssociatedInstance -Association Win32_GroupUser
function getLocalGroupMembers {
    $sidRegex = "S-1-5-21-.+-(\d+$)"
    
    try {
        # get all local groups
        $groups = Get-LocalGroup

        # get the membership for all local groups
	    # NOTE!!!! cannot use [pscustomobject] in remoting b/c of constrained language mode limits of core types
        
        foreach ($group in $groups) {
    	    try {
                $localGroupMem = Get-LocalGroupMember $group -ErrorAction Stop
                foreach($member in $localGroupMem) {
                    
                    # parse the RID from the SID
                    if ($member.SID -match $sidRegex) {
                        $RID = $Matches[1]
                    } else {
                        $RID = ''
                    }                    

                    @{
                        GroupName       = $group.Name
                        Name            = $member.Name.split('\')[1]
                        Domain          = $member.Name.split('\')[0]
                        SID             = $member.SID
                        RID             = $RID
                        PrincipalSource = $member.PrincipalSource
                        ObjectClass     = $member.ObjectClass
                    } 
                }
            } catch [System.InvalidOperationException] {
                @{
                    GroupName       = $group.Name
                    Name            = 'Get-LocalGroupMember InvalidOperationException'
                    Domain          = 'Get-LocalGroupMember InvalidOperationException'
                    SID             = 'Get-LocalGroupMember InvalidOperationException'
                    RID             = 'Get-LocalGroupMember InvalidOperationException'
                    PrincipalSource = 'Get-LocalGroupMember InvalidOperationException'
                    ObjectClass     = 'Get-LocalGroupMember InvalidOperationException'
                }
            }
        }        
    
    # run if the Get-Local* cmdlets are not installed on the remote systems
    } catch [System.Management.Automation.RuntimeException] {
       
        # convert the provided value to a readable SID
        function ConvertTo-SID {
            Param([byte[]]$BinarySID)
            
            (New-Object System.Security.Principal.SecurityIdentifier($BinarySID,0)).Value
        }

        # get and parse the group member data points of interest
        function localGroupMember {
            Param($Group)
            
            $Group.Invoke('members') | ForEach-Object {
                # parse the ADSPath to get the domain and determine if it's a local object or from AD
                $_.GetType().InvokeMember("ADSPath", 'GetProperty', $null, $_, $null) -match "WinNT:\/\/(\w+)\/(.+)\/" | Out-Null
            
                if($Matches.Count -gt 2) {
                    $domain = $Matches[2]
                    $source = 'Local'
                    $Matches.Clear()
                } elseif($Matches) {
                    $_.GetType().InvokeMember("ADSPath", 'GetProperty', $null, $_, $null) -match "WinNT:\/\/(\w+)\/" | Out-Null
                    $domain = $Matches[1]
                    $source = 'ActiveDirectory'
                    $Matches.Clear()
                }        

                $SID = ConvertTo-SID $_.GetType().InvokeMember("ObjectSID", 'GetProperty', $null, $_, $null)

                # parse the RID from the SID
                if ($SID -match $sidRegex) {
                        $RID = $Matches[1]
                    } else {
                        $RID = ''
                    } 

                @{
                    Name            = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                    ObjectClass     = $_.GetType().InvokeMember("Class", 'GetProperty', $null, $_, $null)    
                    SID             = $SID
                    RID             = $RID
                    Domain          = $domain
                    PrincipalSource = $source
                }
            }
        }

        # get local groups using ADSI
        $adsi   = [ADSI]"WinNT://$env:COMPUTERNAME"
        $groups = $adsi.Children | Where-Object {$_.SchemaClassName -eq 'group'}

        # get group members for each local group
        $groupMembers = foreach($g in $groups) { 
            @{
                GroupName    = $g.Name[0]
                GroupMembers = (localGroupMember -Group $g)
            }
        } 
        # ignore groups with no members
        $groupMembers = $groupMembers | Where-Object {$_.GroupMembers -notlike ''}
        
        # output the combined group and individual group member data
        foreach($group in $groupMembers) {
            foreach($member in $group.GroupMembers) {
                @{
                    GroupName       = $group.GroupName
                    Name            = $member.Name
                    Domain          = $member.Domain
                    SID             = $member.SID
                    RID             = $member.RID
                    PrincipalSource = $member.PrincipalSource
                    ObjectClass     = $member.ObjectClass            
                }
            }
        }
    }
}


# With PS remoting the numeric codes for OperationalStatus, HealthStatus, BusType, and MediaType 
# are returned instead of their text-friendly variants.  By using Select-Object this somehow forces
# the lookup and returns the desired results.  Wrapped the call in a function for a cleaner look.
function getPhysicalDiskInfo {
    
    Get-PhysicalDisk | 
        Select-Object OperationalStatus,
                      HealthStatus,
                      BusType,
                      MediaType,
                      SpindleSpeed,
                      Manufacturer,
                      Model,
                      FirmwareVersion,
                      IsPartial,
                      LogicalSectorSize,
                      PhysicalSectorSize,
                      AllocatedSize,
                      Size
}


# Determine all AD computer objects that did not connect with WinRM
function Get-FailedWinRMSessions {
    param(
        $comps
    )    
    
    $compSessions = @{}
    
    $comps.Name | 
        ForEach-Object {$compSessions.Add($_, $false)}
    
    (Get-PSSession).ComputerName | 
        ForEach-Object {$compSessions[$_] = $true}
    
    $compSessions.GetEnumerator().Where({$_.Value -eq $false})
}



# Check for broken PowerShell remoting sessions before collection
function Get-BrokenPSSessions {
    param(
        [string]$failure
    )

    Get-PSSession | Where-Object {$_.State -ne 'Opened'} | 
        Select-Object @{Name='Name'; Expression={$_.ComputerName}},@{Name='Failure'; Expression={$failure}} |
        Export-Csv -Path failed_collection.csv -Append -NoTypeInformation
}



# Only connect to PowerShell remoting sessions that are open
function Get-OpenPSSessions {
    Get-PSSession | 
        Where-Object{$_.State -eq 'Opened'}
}



# Pull data from the local system and append to the existing CSV files
function Collect-LocalSystemData {
    # Local Administrators group membership
    Write-Output "Local: Getting local group memberships."
    getLocalGroupMembers |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},
                      @{Name='GroupName'; Expression={$_.GroupName}},
                      @{Name='Name'; Expression={$_.Name}},
                      @{Name='Domain'; Expression={$_.Domain}},
                      @{Name='SID'; Expression={$_.SID}},
                      @{Name='RID'; Expression={$_.RID}},
                      @{Name='PrincipalSource'; Expression={$_.PrincipalSource}},
                      @{Name='ObjectClass'; Expression={$_.ObjectClass}} |
	    Export-Csv -Path local_groups.csv -Append -NoTypeInformation


    # Local user accounts
    Write-Output "Local: Getting local user accounts."
    getLocalUsers | 
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},
					  Name,
   					  SID,
		  			  RID,
		 			  Enabled,
					  PasswordRequired,
	                  PasswordChangeable,
				      PrincipalSource,
		              Description,
				      PasswordLastSet,
		              @{Name='PasswordLastSetDays'; Expression={if($_.PasswordLastSetDays -ne '') {[math]::Round($_.PasswordLastSetDays, 0)}}},
					  LastLogon |
	    Export-Csv -Path local_users.csv -Append -NoTypeInformation

    
    # Processes
    # Check if the local session is running with elevated privileges
    Write-Output "Local: Getting processes."
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $localProcesses = Get-Process -IncludeUserName -ErrorAction SilentlyContinue
    } else {
        $localProcesses = Get-Process -ErrorAction SilentlyContinue
    }

    $localProcesses |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,Id,Path,@{Name='Hash'; Expression={if($_.Path -notlike '') {(Get-FileHash $_.Path).Hash}}},UserName,Company,Description,ProductVersion,StartTime |
	    Export-Csv -Path processes.csv -Append -NoTypeInformation

    
    # Scheduled tasks
    Write-Output "Local: Getting scheduled tasks."
    $guidRegex = "([a-zA-Z0-9_. ]+)-?\{([0-9A-F]+-?){5}\}"
    $sidRegex  = "([a-zA-Z0-9_. ]+)((_|-)S-1-5-21)((-\d+){4})"
    
    Get-ScheduledTask |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},
                      @{Name='TaskName'; Expression={if( $_.TaskName -match $guidRegex ) { $Matches[1] } elseif ($_.TaskName -match $sidRegex ) { $Matches[1] } else {$_.TaskName}}},
                      State,
                      Author,
                      TaskPath,
                      Description |
	    Export-Csv -Path scheduled_tasks.csv -Append -NoTypeInformation

    
    # Services
    Write-Output "Local: Getting services."
    Get-Service |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},
                      @{Name='Name'; Expression={$_.Name.Split('_')[0]}}, # remove unique service name suffix
                      @{Name='DisplayName'; Expression={$_.DisplayName.Split('_')[0]}}, # remove unique service display name suffix
                      Status,
                      StartType,
                      ServiceType |
	    Export-Csv -Path services.csv -Append -NoTypeInformation


    # Network connections
    Write-Output "Local: Getting network connections."
    netConnects | 
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Date,Time,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,ProcessName |
        Export-Csv -Path net.csv -Append -NoTypeInformation

    
    # Downloads, Documents, and Desktop files
    Write-Output "Local: Getting Documents, Desktop, and Downloads file information."
    Get-ChildItem -Path 'C:\Users\*\Downloads\','C:\Users\*\Documents\','C:\Users\*\Desktop\' -Recurse |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes |
	    Export-Csv -Path files.csv -Append -NoTypeInformation

    
    # 64 bit programs
    Write-Output "Local: Getting 64-bit programs."
    Get-ChildItem -Path 'C:\Program Files' |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'64-bit'}} |
	    Export-Csv -Path programs.csv -Append -NoTypeInformation

    
    # 32 bit programs
    Write-Output "Local: Getting 32-bit programs."
    Get-ChildItem -Path 'C:\Program Files (x86)' |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'32-bit'}} |
	    Export-Csv -Path programs.csv -Append -NoTypeInformation


    # Local system information
    Write-Output "Local: Getting system information."
    Get-ComputerInfo -OutVariable hotFixes |
        Select-Object @{Name='PSComputerName'; Expression={$_.CsName}},
                      WindowsCurrentVersion,
                      WindowsEditionId,
                      WindowsVersion,
                      BiosManufacturer,
                      BiosSMBIOSBIOSVersion,
                      BiosFirmwareType,
                      BiosReleaseDate,
                      BiosSeralNumber,
                      BiosCurrentLanguage,
                      CsDomain,
                      CsDomainRole,
                      CsManufacturer,
                      CsModel,
                      @{name='CsProcessors'; expression={$_.CsProcessors.Name}},
                      CsNumberOfProcessors,
                      @{name='CsNumberOfCores'; expression={$_.CsProcessors.NumberOfCores}},
                      CsNumberofLogicalProcessors,
                      CsPartOfDomain,
                      @{name='CsTotalPhysicalMemory (GB)'; expression={[math]::Round($_.CsTotalPhysicalMemory/1GB, 1)}},
                      @{name='CsMaxClockSpeed'; expression={$_.CsProcessors.MaxClockSpeed}},
                      OsName,
                      OsType,
                      OsVersion,
                      OsBuildNumber,
                      OsLocale,
                      OsManufacturer,
                      OsArchitecture,
                      OsLanguage,
                      KeyboardLayout,
                      TimeZone,
                      LogonServer,
                      PowerPlatformRole |
        Export-Csv -Path system_info.csv -Append -NoTypeInformation

    
    # Local system hot fix information
    Write-Output "Local: Getting system hot fix information."
    $hotFixes.OsHotFixes | 
        ForEach-Object {
            [pscustomobject]@{
                HotFixID       = $_.HotFixID
                Description    = $_.Description
                InstalledOn    = $_.InstalledOn
                PSComputerName = $hotFixes.CsName
            }
        } | 
        Select-Object PSComputerName,HotFixID,Description,InstalledOn | 
        Export-Csv -Path hotfixes.csv -Append -NoTypeInformation

    # BitLocker information
    Write-Output "Local: Getting BitLocker information."
    Get-BitLockerVolume |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},
                      MountPoint,
                      EncryptionMethod,
                      AutoUnlockEnabled,
                      AutoUnlockKeyStored,
                      MetadataVersion,
                      VolumeStatus,
                      ProtectionStatus,
                      LockStatus,
                      EncryptionPercentage,
                      WipePercentage,
                      VolumeType,
                      @{name='CapacityGB'; expression={[math]::Round($_.CapacityGB, 1)}},
                      @{Name='KeyProtector'; Expression={$_.KeyProtector -join '|'}} |
        Export-Csv -Path bitlocker.csv -Append -NoTypeInformation


    # Physical disk information
    Write-Output "Local: Getting physical disk information."
    Get-PhysicalDisk |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},
                      OperationalStatus,
                      HealthStatus,
                      BusType,
                      MediaType,
                      SpindleSpeed,
                      Manufacturer,
                      Model,
                      FirmwareVersion,
                      IsPartial,
                      LogicalSectorSize,
                      PhysicalSectorSize,
                      @{name='AllocatedSizeGB'; expression={[math]::Round($_.AllocatedSize/1GB, 1)}},
                      @{name='SizeGB'; expression={[math]::Round($_.Size/1GB, 1)}} |
        Export-Csv -Path physical_disk.csv -Append -NoTypeInformation


    # Hard drive volume storage information
    Write-Output "Local: Getting hard drive storage information."
    Get-PSDrive -PSProvider FileSystem | 
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},
                      Name,
                      Root,
                      Description,
                      @{name='Used (GB)'; expression={[math]::Round($_.Used/1GB, 2)}},
                      @{name='Free (GB)'; expression={[math]::Round($_.Free/1GB, 2)}},
                      DisplayRoot |
        Export-Csv -Path hard_drive_storage.csv -Append -NoTypeInformation

    
    # Shares
    Write-Output "Local: Getting shares."
    Get-SmbShare | 
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,Path,Description,EncryptData,CurrentUsers,ShareType |
        Export-Csv -Path shares.csv -Append -NoTypeInformation

    
    # Share permissions
    Write-Output "Local: Getting share permissions."
    Get-SmbShare | 
        Get-SmbShareAccess | 
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,AccountName,AccessControlType,AccessRight |
        Export-Csv -Path share_permissions.csv -Append -NoTypeInformation
}


function Get-DomainComputerObjects {
    Param(
        [string]$DN,
        [switch]$ServersOnly
    )

    if($Migrated) {
        $groupArgs = @{
            Filter     = "Name -like '*Computers_$($Region)_$($OUName)'"
            SearchBase = "ou=groups,$DN"
            Server     = $Server
        }

        if($ServersOnly) {
            $comps = Get-ADGroup @groupArgs | 
                Get-ADGroupMember |
                ForEach-Object {
                    Get-ADComputer -Filter "name -like '$($_.name)' -and OperatingSystem -like 'Windows Server*'" -Properties IPv4Address,LastLogonDate,OperatingSystem -SearchBase "ou=workstations,$DN" -Server $Server
                }
        } else {
            $comps = Get-ADGroup @groupArgs | 
                Get-ADGroupMember |
                ForEach-Object {
                    Get-ADComputer -Filter "name -like '$($_.name)'" -Properties IPv4Address,LastLogonDate,OperatingSystem -SearchBase "ou=workstations,$DN" -Server $Server
                }
        }

    } else {
        # Pull all Windows computer objects listed in the Directory for the designated DN (will exclude domain joined Linux or Mac systems)
        
        if($ServersOnly) {
            $filt = "OperatingSystem -like 'Windows Server*'"
        } else {
            $filt = "*"
        }
            
        $computersArgs = @{
            Filter     = $filt
            Properties = 'IPv4Address','LastLogonDate','OperatingSystem'
            SearchBase = $DN
        }

        # return the computer objects
        $comps = Get-ADComputer @computersArgs
    }

    $comps
}


function Try-FailedWinRM {
    Param(
        [string]$DN,
        [switch]$ServersOnly
    )

    if(Test-Path .\failed_collection.csv) {
        $failed = Import-Csv .\failed_collection.csv
    } else {
        Write-Output 'File not found: failed_collection.csv is not in the current working directory.'
        exit
    }
    
    # get the list of systems that failed to connect via WinRM for either the general system datasets or the server specific collection
    if($ServersOnly) {
        $failedWinRMComps = $failed | Where-Object {$_.Failure -eq 'WinRMServer'} | Sort-Object Name -Unique
    } else {
        $failedWinRMComps = $failed | Where-Object {$_.Failure -eq 'WinRM'} | Sort-Object Name -Unique
    }

    # get the AD computer objects for the systems that failed to connect via WinRM
    if($Migrated) {
        $comps = $failedWinRMComps | 
            ForEach-Object {
                Get-ADComputer -Filter "Name -like '$($_.Name)'" -Properties IPv4Address,LastLogonDate,OperatingSystem -SearchBase "ou=workstations,$DN" -Server $Server
            }
    } else {
        $comps = $failedWinRMComps |
            ForEach-Object {
                Get-ADComputer -Filter "Name -like '$($_.Name)'" -Properties IPv4Address,LastLogonDate,OperatingSystem -SearchBase $DN
            }
    }

    # update the failed_collection.csv log file to reflect the attempted reconnection (with a 'r_' prefix), the new
    # WinRM connection attempt will update the log records for any connections that fail again
    if($ServersOnly) {
        $failed | 
            ForEach-Object {
                if($_.Failure -eq 'WinRMServer') {
                    [pscustomobject]@{
                        Name=   $_.Name
                        Failure='r_WinRMServer'
                    }
                } else {
                    $_
                }
            } |
            Export-Csv -Path .\failed_collection.csv -NoTypeInformation
    } else {
        $failed | 
            ForEach-Object {
                if($_.Failure -eq 'WinRM') {
                    [pscustomobject]@{
                        Name=   $_.Name
                        Failure='r_WinRM'
                    }
                } else {
                    $_
                }
            } |
            Export-Csv -Path .\failed_collection.csv -NoTypeInformation
    }

    # return the computer objects
    $comps
}


function Collect-RemoteSystemData {
    Param($DN)
    
    # Collect domain computer objects or retry systems that previously failed WinRM connection attempts
    if($FailedWinRM) {
        Write-Output "Active Directory: Getting previously failed PSRemoting domain computer objects."
        $computers = Try-FailedWinRM $DN
    } else {
        Write-Output "Active Directory: Getting domain computer objects."
        $computers = Get-DomainComputerObjects $DN

        # Only export domain computer account info on the first collection
        $computers | Export-Csv -Path domain_computers.csv -Append -NoTypeInformation
    }    

    # Create PS sessions for Windows only systems
    $computers = $computers | Where-Object {$_.OperatingSystem -like "Windows*"}
    
    # Using the $computers.Name array method to create PS remoting sessions due to speed (compared to foreach)
    Write-Output "Remoting: Creating PowerShell sessions."
    $sessionOpt = New-PSSessionOption -NoMachineProfile # Minimize your presence and don't create a user profile on every system (e.g., C:\Users\<username>)
    New-PSSession -ComputerName $computers.Name -SessionOption $sessionOpt -ErrorAction SilentlyContinue | Out-Null # Create reusable PS Sessions

    # Determine the systems where PS remoting failed
    Get-FailedWinRMSessions $computers | 
        Select-Object Name,@{Name='Failure'; Expression={'WinRM'}} |
        Export-Csv -Path failed_collection.csv -Append -NoTypeInformation


    ### Removing data pull ###
    # Local group memberships
    Write-Output "Remoting: Getting local group memberships."
    Get-BrokenPSSessions 'LocalGroupMembers'

    Invoke-Command -Session (Get-OpenPSSessions) -ScriptBlock ${function:getLocalGroupMembers} |
        Select-Object PSComputerName,
                      @{Name='GroupName'; Expression={$_.GroupName}},
                      @{Name='Name'; Expression={$_.Name}},
                      @{Name='Domain'; Expression={$_.Domain}},
                      @{Name='SID'; Expression={$_.SID}},
                      @{Name='RID'; Expression={$_.RID}},
                      @{Name='PrincipalSource'; Expression={$_.PrincipalSource}},
                      @{Name='ObjectClass'; Expression={$_.ObjectClass}} |
        Export-Csv -Path local_groups.csv -Append -NoTypeInformation


    # Local user accounts
    Write-Output "Remoting: Getting local user accounts."
    Get-BrokenPSSessions 'LocalUsers'

    Invoke-Command -Session (Get-OpenPSSessions) -ScriptBlock ${function:getLocalUsers} |
        Select-Object PSComputerName,
					  Name,
	   				  SID,
		  			  RID,
		 			  Enabled,
					  PasswordRequired,
	   				  PasswordChangeable,
		  			  PrincipalSource,
		 			  Description,
					  PasswordLastSet,
	   				  @{Name='PasswordLastSetDays'; Expression={if($_.PasswordLastSetDays -ne '') {[math]::Round($_.PasswordLastSetDays, 0)}}},
		  			  LastLogon |
	    Export-Csv -Path local_users.csv -Append -NoTypeInformation


    # Processes
    Write-Output "Remoting: Getting processes."
    Get-BrokenPSSessions 'Process'

    Invoke-Command -Session (Get-OpenPSSessions) `
                   -ScriptBlock {
                        Get-Process -IncludeUserName | 
                        Select-Object Name,
                                      Id,
                                      Path,
                                      @{Name='Hash'; Expression={if($_.Path -notlike '') {(Get-FileHash $_.Path -ErrorAction SilentlyContinue).Hash}}},
                                      UserName,
                                      Company,
                                      Description,
                                      ProductVersion,
                                      StartTime
                   } |
        Select-Object PSComputerName,Name,Id,Path,Hash,UserName,Company,Description,ProductVersion,StartTime |
	    Export-Csv -Path processes.csv -Append -NoTypeInformation


    # Scheduled tasks
    Write-Output "Remoting: Getting scheduled tasks."
    Get-BrokenPSSessions 'ScheduledTask'

    Invoke-Command -Session (Get-OpenPSSessions) `
                   -ScriptBlock {
                        $guidRegex = "([a-zA-Z0-9_. ]+)-?\{([0-9A-F]+-?){5}\}"
                        $sidRegex  = "([a-zA-Z0-9_. ]+)((_|-)S-1-5-21)((-\d+){4})"
                        Get-ScheduledTask | 
                        Select-Object @{Name='TaskName'; Expression={if( $_.TaskName -match $guidRegex ) { $Matches[1] } elseif ($_.TaskName -match $sidRegex ) { $Matches[1] } else {$_.TaskName}}},
                                        State,
                                        Author,
                                        TaskPath,
                                        Description
                    } |
        Select-Object PSComputerName,TaskName,State,Author,TaskPath,Description |
	    Export-Csv -Path scheduled_tasks.csv -Append -NoTypeInformation


    # Services
    Write-Output "Remoting: Getting services."
    Get-BrokenPSSessions 'Services'

    Invoke-Command -Session (Get-OpenPSSessions) `
                   -ScriptBlock {
                        Get-Service | 
                        Select-Object @{Name='Name'; Expression={$_.Name.Split('_')[0]}}, # remove unique service name suffix
                                      @{Name='DisplayName'; Expression={$_.DisplayName.Split('_')[0]}}, # remove unique service display name suffix
                                      Status,
                                      StartType,
                                      ServiceType
                   } |
        Select-Object PSComputerName,Name,DisplayName,Status,StartType,ServiceType |
        Export-Csv -Path services.csv -Append -NoTypeInformation


    # Network connections
    Write-Output "Remoting: Getting network connections."
    Get-BrokenPSSessions 'Network'

    Invoke-Command -Session (Get-OpenPSSessions) -ScriptBlock ${function:netConnects} |
        Select-Object PSComputerName,Date,Time,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,ProcessName |
        Export-Csv -Path net.csv -Append -NoTypeInformation


    # Downloads, Documents, and Desktop files
    Write-Output "Remoting: Getting Documents, Desktop, and Downloads file information."
    Get-BrokenPSSessions 'Files'

    Invoke-Command -Session (Get-OpenPSSessions) `
                   -ScriptBlock {
                        Get-ChildItem -Path 'C:\Users\*\Downloads\','C:\Users\*\Documents\','C:\Users\*\Desktop\' -Recurse | 
                        Select-Object Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes
                   } |
	    Select-Object PSComputerName,Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes |
        Export-Csv -Path files.csv -Append -NoTypeInformation


    # 64 bit programs
    Write-Output "Remoting: Getting 64-bit programs."
    Get-BrokenPSSessions 'Programs64'

    Invoke-Command -Session (Get-OpenPSSessions) `
                   -ScriptBlock {
                        Get-ChildItem -Path 'C:\Program Files' | 
                        Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'64-bit'}}
                   } |
	    Select-Object PSComputerName,Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,ProgramType |
        Export-Csv -Path programs.csv -Append -NoTypeInformation


    # 32 bit programs
    Write-Output "Remoting: Getting 32-bit programs."
    Get-BrokenPSSessions 'Programs32'

    Invoke-Command -Session (Get-OpenPSSessions) `
                   -ScriptBlock {
                        Get-ChildItem -Path 'C:\Program Files (x86)' | 
                        Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'32-bit'}}
                   } |
	    Select-Object PSComputerName,Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,ProgramType |
        Export-Csv -Path programs.csv -Append -NoTypeInformation


    # System information
    Write-Output "Remoting: Getting system information."
    Get-BrokenPSSessions 'SystemInformation'

    Invoke-Command -Session (Get-OpenPSSessions) -ScriptBlock {Get-ComputerInfo} |
        Select-Object PSComputerName,
                      WindowsCurrentVersion,
                      WindowsEditionId,
                      WindowsVersion,
                      BiosManufacturer,
                      BiosSMBIOSBIOSVersion,
                      BiosFirmwareType,
                      BiosReleaseDate,
                      BiosSeralNumber,
                      BiosCurrentLanguage,
                      CsDomain,
                      CsDomainRole,
                      CsManufacturer,
                      CsModel,
                      @{name='CsProcessors'; expression={$_.CsProcessors.Name}},
                      CsNumberOfProcessors,
                      @{name='CsNumberOfCores'; expression={$_.CsProcessors.NumberOfCores}},
                      CsNumberofLogicalProcessors,
                      CsPartOfDomain,
                      @{name='CsTotalPhysicalMemory (GB)'; expression={[math]::Round($_.CsTotalPhysicalMemory/1GB, 1)}},
                      @{name='CsMaxClockSpeed'; expression={$_.CsProcessors.MaxClockSpeed}},
                      OsName,
                      OsType,
                      OsVersion,
                      OsBuildNumber,
                      OsLocale,
                      OsManufacturer,
                      OsArchitecture,
                      OsLanguage,
                      KeyboardLayout,
                      TimeZone,
                      LogonServer,
                      PowerPlatformRole |
        Export-Csv -Path system_info.csv -Append -NoTypeInformation


    # System hot fix information
    Write-Output "Remoting: Getting system hot fix information."
    Get-BrokenPSSessions 'SystemHotFix'
    
    Invoke-Command -Session (Get-OpenPSSessions) `
                   -ScriptBlock {
                        (Get-ComputerInfo).OsHotFixes | 
                            ForEach-Object {
                              @{
                                    HotFixID    = $_.HotFixID
                                    Description = $_.Description
                                    InstalledOn = $_.InstalledOn
                                }
                             }
                   } | 
        Select-Object PSComputerName,
                      @{Name='HotFixID'; Expression={$_.HotFixID}},
                      @{Name='Description'; Expression={$_.Description}},
                      @{Name='InstalledOn'; Expression={$_.InstalledOn}} | 
        Export-Csv -Path hotfixes.csv -Append -NoTypeInformation

    
    # BitLocker information
    Write-Output "Remoting: Getting BitLocker information."
    Get-BrokenPSSessions 'BitLocker'

    Invoke-Command -Session (Get-OpenPSSessions) -ScriptBlock {Get-BitLockerVolume} |
        Select-Object PSComputerName,
                      MountPoint,
                      EncryptionMethod,
                      AutoUnlockEnabled,
                      AutoUnlockKeyStored,
                      MetadataVersion,
                      VolumeStatus,
                      ProtectionStatus,
                      LockStatus,
                      EncryptionPercentage,
                      WipePercentage,
                      VolumeType,
                      @{name='CapacityGB'; expression={[math]::Round($_.CapacityGB, 1)}},
                      @{Name='KeyProtector'; Expression={$_.KeyProtector -join '|'}} |
        Export-Csv -Path bitlocker.csv -Append -NoTypeInformation


    # Physical disk information
    Write-Output "Remoting: Getting physical disk information."
    Get-BrokenPSSessions 'PhysicalDisk'
        
    Invoke-Command -Session (Get-OpenPSSessions) -ScriptBlock ${function:getPhysicalDiskInfo} |
        Select-Object PSComputerName,
                      OperationalStatus,
                      HealthStatus,
                      BusType,
                      MediaType,
                      SpindleSpeed,
                      Manufacturer,
                      Model,
                      FirmwareVersion,
                      IsPartial,
                      LogicalSectorSize,
                      PhysicalSectorSize,
                      @{name='AllocatedSizeGB'; expression={[math]::Round($_.AllocatedSize/1GB, 1)}},
                      @{name='SizeGB'; expression={[math]::Round($_.Size/1GB, 1)}} |
        Export-Csv -Path physical_disk.csv -Append -NoTypeInformation


    # Hard drive volume storage information
    Write-Output "Remoting: Getting hard drive storage information."
    Get-BrokenPSSessions 'HardDriveInformation'

    Invoke-Command -Session (Get-OpenPSSessions) -ScriptBlock {Get-PSDrive -PSProvider FileSystem} |
        Select-Object PSComputerName,
                      Name,
                      Root,
                      Description,
                      @{name='Used (GB)'; expression={[math]::Round($_.Used/1GB, 2)}},
                      @{name='Free (GB)'; expression={[math]::Round($_.Free/1GB, 2)}},
                      DisplayRoot |
        Export-Csv -Path hard_drive_storage.csv -Append -NoTypeInformation


    # Shares
    Write-Output "Remoting: Getting shares."
    Get-BrokenPSSessions 'Shares'

    Invoke-Command -Session (Get-OpenPSSessions) `
                   -ScriptBlock {
                        Get-SmbShare | 
                        Select-Object Name,Path,Description,EncryptData,CurrentUsers,ShareType
                   } |
        Select-Object PSComputerName,Name,Path,Description,EncryptData,CurrentUsers,ShareType |
        Export-Csv -Path shares.csv -Append -NoTypeInformation


    # Share permissions
    Write-Output "Remoting: Getting share permissions."
    Get-BrokenPSSessions 'SharePermissions'

    Invoke-Command -Session (Get-OpenPSSessions) `
                   -ScriptBlock {
                        Get-SmbShare | 
                        Get-SmbShareAccess | 
                        Select-Object Name,AccountName,AccessControlType,AccessRight
                   } |
	    Select-Object PSComputerName,Name,AccountName,AccessControlType,AccessRight |
        Export-Csv -Path share_permissions.csv -Append -NoTypeInformation

    Write-Output "Remoting: Removing PowerShell sessions."
    Get-PSSession | Remove-PSSession
}


function Collect-ServerFeatures {
    Param($DN)

    if (-not $LocalCollectionOnly) {
        # Collect server domain computer objects or retry systems that previously failed WinRM connection attempts
        if($FailedWinRM) {
            Write-Output "Active Directory: Getting previously failed PSRemoting domain computer objects."
            $winServers = Try-FailedWinRM $DN -ServersOnly
        } else {
            Write-Output "Active Directory: Getting server OS domain computer objects."
            $winServers = Get-DomainComputerObjects $DN -ServersOnly
        }
    
        # Using the $computers.Name array method to create PS remoting sessions due to speed (compared to foreach)
        Write-Output "Remoting: Creating PowerShell server sessions."
        $sessionOpt = New-PSSessionOption -NoMachineProfile # Minimize your presence and don't create a user profile on every system (e.g., C:\Users\<username>)
        $serverSessions = New-PSSession -ComputerName $winServers.Name -SessionOption $sessionOpt -ErrorAction SilentlyContinue # Create reusable PS Sessions

        # Determine the systems where PS remoting failed
        Get-FailedWinRMSessions $winServers | 
            Select-Object Name,@{Name='Failure'; Expression={'WinRMServer'}} |
            Export-Csv -Path failed_collection.csv -Append -NoTypeInformation

        # Windows Server installed features
        Write-Output "Server: Getting installed features."
        Invoke-Command -Session $serverSessions -ScriptBlock {Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed'} | Select-Object Name,DisplayName,Description,InstallState,Parent,Depth,Path,FeatureType} | 
            Select-Object PSComputerName,Name,DisplayName,Description,InstallState,Parent,Depth,Path,FeatureType |
	        Export-Csv -Path windows_server_features.csv -Append -NoTypeInformation

        Get-PSSession | Remove-PSSession
    
    # server features local collection
    } else {
        Get-WindowsFeature | 
            Where-Object {$_.InstallState -eq 'Installed'} | 
            Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,DisplayName,Description,InstallState,Parent,Depth,Path,FeatureType | 
	        Export-Csv -Path windows_server_features.csv -Append -NoTypeInformation
    }
}


function Collect-DHCPLeases {
    Param($server)
    Write-Output "Server: Getting DHCP leases."
#        $dhcp = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled=$true" | 
#                    Where-Object {$_.DHCPServer -like "10.*" -or $_.DHCPServer -like "172.*" -or $_.DHCPServer -like "192.168.*"}
    
    if(Get-Command Get-DhcpServerv4Scope -ErrorAction SilentlyContinue) {    
		foreach($s in $server) {
            Get-DHCPServerv4Scope -ComputerName $s -OutVariable scope |
	    	    Select-Object ScopeId,SubnetMask,StartRange,EndRange,ActivatePolicies,LeaseDuration,Name,State,Type |
	    	    Export-Csv dhcp_scopes.csv -Append -NoTypeInformation
	     
		    $scope | 
			    Get-DHCPServerv4Lease -ComputerName $s -AllLeases | 
			    Select-Object IPAddress,ScopeId,AddressState,ClientId,ClientType,Description,HostName,LeaseExpiryTime,ServerIP |
	 		    Export-Csv dhcp_leases.csv -Append -NoTypeInformation
        }
   	} else { 
   		Write-Output 'DHCP cmdlets are not available.  Skipping DHCP data queries.' 
	}
}


function Collect-ActiveDirectoryDatasets {
    param($DN)

    # Get domain user account information
    Write-Output "Active Directory: Getting domain user objects."
    
    if ($Migrated) {
        $adUsersArgs = @{
            Filter = "Name -like `"*Users_$($Region)_$($OUName)`""
            SearchBase = "ou=groups,$DN"
            Server = $Server
        }

        $adUsers = Get-ADGroup @adUsersArgs |
            Get-ADGroupMember |
            ForEach-Object {
                Get-ADUser -Filter "SamAccountName -like `"$($_.SamAccountName)`"" -Properties AccountExpirationDate,AccountNotDelegated,AllowReversiblePasswordEncryption,CannotChangePassword,LastLogonDate,LockedOut,PasswordExpired,PasswordNeverExpires,PasswordNotRequired,SmartcardLogonRequired -SearchBase "ou=users,$DN" -Server $Server
            }

    } else {
        $adUsersArgs = @{
            Filter = "*"
            Properties = 'AccountExpirationDate','AccountNotDelegated','AllowReversiblePasswordEncryption','CannotChangePassword','LastLogonDate','LockedOut','PasswordExpired','PasswordNeverExpires','PasswordNotRequired','SmartcardLogonRequired'
            SearchBase = $DN
        }

        $adUsers = Get-ADUser @adUsersArgs
    }

    $adUsers | Export-Csv -Path domain_users.csv -Append -NoTypeInformation
       
    # Get all OU groups and their members (does not work recursively)
    if($Migrated) {
        Write-Output "Active Directory: Getting domain group memberships."
        $groups = Get-ADGroup -Filter * -Properties Members,msExchExtensionCustomAttribute1 -SearchBase $('OU=' + $OUName + ',' + (Get-ADDomain).DistinguishedName)

        foreach($group in $groups) {
            $members = $group.Members

            # if a group is empty document it
            if($members.Count -eq 0) {
                [pscustomobject]@{
                    Name=             $($group.Name)
                    DistinguishedName=$($group.DistinguishedName)
                 } | 
                 Export-Csv ad_empty_groups.csv -Append -NoTypeInformation
            }

            Write-Output "In group: $($group)"

            # export data about each group member using the Get-ADObject cmdlet while looking in the specified
            # $Server domain and then in the GC if that fails; does not look up group memberships recursively
            foreach($mem in $members) {
                try {
                    Get-ADObject $mem -Properties msExchExtensionCustomAttribute1,SamAccountName -Server $Server | 
                        Where-Object {$_.ObjectClass -notlike 'computer'} |
                        Select-Object @{Name='GroupDistinguishedName'; Expression={$group.DistinguishedName}},
                                      @{Name='GroupSamAccountName'; Expression={$group.SamAccountName}},
                                      @{Name='Name'; Expression={$_.Name}},
                                      @{Name='SamAccountName'; Expression={$_.SamAccountName}},
                                      @{Name='Location'; Expression={
                                                            $_.msExchExtensionCustomAttribute1 | 
                                                                ForEach-Object {
                                                                    if($_.ToString() -match "iPostSite\|(.*)") {
                                                                        $Matches[1]
                                                                    }
                                                                }
                                                         }},
                                      @{Name='DistinguishedName'; Expression={$_.DistinguishedName}},
                                      @{Name='ObjectClass'; Expression={$_.ObjectClass}} |
                        Export-Csv -Path ad_group_members.csv -Append -NoTypeInformation
                } catch {
                    try {
                        Get-ADObject $mem -Properties msExchExtensionCustomAttribute1,SamAccountName -Server :3268 | 
                            Where-Object {$_.ObjectClass -notlike 'computer'} |
                            Select-Object @{Name='GroupDistinguishedName'; Expression={$group.DistinguishedName}},
                                          @{Name='GroupSamAccountName'; Expression={$group.SamAccountName}},
                                          @{Name='Name'; Expression={$_.Name}},
                                          @{Name='SamAccountName'; Expression={$_.SamAccountName}},
                                          @{Name='Location'; Expression={
                                                            $_.msExchExtensionCustomAttribute1 | 
                                                                ForEach-Object {
                                                                    if($_.ToString() -match "iPostSite\|(.*)") {
                                                                        $Matches[1]
                                                                    }
                                                                }
                                                         }},
                                          @{Name='DistinguishedName'; Expression={$_.DistinguishedName}},
                                          @{Name='ObjectClass'; Expression={$_.ObjectClass}} |
                            Export-Csv -Path ad_group_members.csv -Append -NoTypeInformation
                    } catch {
                        Write-Output "`tCould not located object: $($mem)"
                    }   
                }    
            }
        }
    } else {
        Write-Output "Active Directory: Getting domain group memberships."
        $groups = Get-ADGroup -Filter * -SearchBase $DN

        # export data and search recursively in the current domain for each
        # group member using the Get-ADGroup and Get-ADGroupMember cmdlets
        foreach($group in $groups) {
            try {
                Get-ADGroupMember -Identity $group.SamAccountName -Recursive -ErrorAction SilentlyContinue | 
	                Where-Object {$_.ObjectClass -like "user"} |
                    Select-Object @{Name='GroupDistinguishedName'; Expression={$group.DistinguishedName}},
                                  @{Name='GroupSamAccountName'; Expression={$group.SamAccountName}},
                                  @{Name='Name'; Expression={$_.Name}},
                                  @{Name='SamAccountName'; Expression={$_.SamAccountName}},
                                  @{Name='Location'; Expression={}},
                                  @{Name='DistinguishedName'; Expression={$_.DistinguishedName}},
                                  @{Name='ObjectClass'; Expression={$_.ObjectClass}} |
                    Export-Csv -Path ad_group_members.csv -Append -NoTypeInformation
            } catch [Microsoft.ActiveDirectory.Management.ADException] {
                Write-Output "$($group.SamAccountName): AD error recursing group (likely out of domain)"
            }
        }
    }
}


# Cmdlet main()
if (-not $LocalCollectionOnly) {
    
    # confirm the AD module is available, otherwise exit
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
    } catch {
        Write-Output 'Cannot load the ActiveDirectory Module, exiting.'
        Break
    }
    
    ### Build PowerShell sessions for Invoke-Command query reuse ###
    
    if($Migrated) {
        $distinguishedName = $SearchBase
    } elseif($OUName) {
        $distinguishedName = 'OU=' + $OUName + ',' + (Get-ADDomain).DistinguishedName
    } else {
        $distinguishedName = (Get-ADDomain).DistinguishedName
    }


    if ($DHCPOnly) {
        Collect-DHCPLeases $DHCPServer

    } elseif ($ServerFeaturesOnly) {
        Collect-ServerFeatures $distinguishedName

    } elseif ($ActiveDirectoryOnly) {
        Collect-ActiveDirectoryDatasets $distinguishedName

    } else {
        Collect-RemoteSystemData $distinguishedName

        ### DHCP scope and lease records
        if ($DHCPServer) {
            Collect-DHCPLeases $DHCPServer
        }

        ### Server features ###
        if ($IncludeServerFeatures) {
            Collect-ServerFeatures $distinguishedName
        }    

        ### Pull Active Directory datasets ###
        if ($IncludeActiveDirectory) {
            Collect-ActiveDirectoryDatasets $distinguishedName
        }
    }

} else {
    # Perform local system collection
    Collect-LocalSystemData

    ### Server features ###
    if ($IncludeServerFeatures) {
        Collect-ServerFeatures
    }  
}