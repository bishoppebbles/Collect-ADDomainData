<#
.SYNOPSIS
    Queries various datasets on systems in a domain environment.
.DESCRIPTION
    
.PARAMETER OUName
    The OU name of interest
.EXAMPLE
    .\Collect-ADDomainData.ps1 -OUName <ou_name>
.NOTES
    Version 1.0.13
    Author: Sam Pursglove
    Last modified: 27 October 2023

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

[alias("FakeHyena")]
[alias("fh")]
param (
    [Parameter(Position=0, HelpMessage='Target OU name')]
    [string]$OUName
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
    try {
        Get-LocalUser |
            Select-Object Name,SID,@{Name='RID'; Expression={[regex]::Match($_.SID, '\d+$').Value}},Enabled,PasswordRequired,@{Name='PasswordChangeable'; Expression={$_.UserMayChangePassword}},PrincipalSource,Description,PasswordLastSet,LastLogon
    } catch [System.Management.Automation.RuntimeException] {       
        Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" -Property * | 
            Select-Object Name,SID,@{Name='RID'; Expression={[regex]::Match($_.SID, '\d+$').Value}},@{Name='Enabled'; Expression={if([bool]$_.Disabled) {'False'} else {'True'}}},PasswordRequired,PasswordChangeable,@{Name='PrincipalSource';Expression={if([bool]$_.LocalAccount) {'Local'}}},Description,@{Name='PasswordLastSet'; Expression={'Unavailable'}},@{Name='LastLogon'; Expression={'Unavailable'}}
    }
}



# Try to first get the group membership of all local groups using PS cmdlets but if that is unavailable use ADSI
# note: attempts to query WMI data via the CIM cmdlets would not work in my domain environment locally or remotely and it's unknown why
#   1) Get-CimInstance -Query "Associators of {Win32_Group.Domain='$env:COMPUTERNAME',Name='Administrators'} where Role=GroupComponent"
#   2) Get-CimInstance -ClassName Win32_Group -Filter "Name='Administrators'" | Get-CimAssociatedInstance -Association Win32_GroupUser
function getLocalGroupMembers {
    try {
        # get all local groups
        $groups = Get-LocalGroup

        # get the membership for all local groups
	    # NOTE!!!! cannot use [pscustomobject] in remoting b/c of constrained language mode limits to core types
        
        foreach ($group in $groups) {
    	    try {
                $localGroupMem = Get-LocalGroupMember $group -ErrorAction Stop
                foreach($member in $localGroupMem) {
                    @{
                        GroupName       = $group.Name
                        Name            = $member.Name.split('\')[1]
                        Domain          = $member.Name.split('\')[0]
                        SID             = $member.SID
                        PrincipalSource = $member.PrincipalSource
                        ObjectClass     = $member.ObjectClass
                    } 
                }
            } catch [System.InvalidOperationException] {
                @{
                    GroupName       = $group.Name
                    Name            = 'Get-LocalGroupMember InvalidOperationException - data not pulled'
                    Domain          = 'Get-LocalGroupMember InvalidOperationException - data not pulled'
                    SID             = 'Get-LocalGroupMember InvalidOperationException - data not pulled'
                    PrincipalSource = 'Get-LocalGroupMember InvalidOperationException - data not pulled'
                    ObjectClass     = 'Get-LocalGroupMember InvalidOperationException - data not pulled'
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

                @{
                    Name            = $_.GetType().InvokeMember("Name", 'GetProperty', $null, $_, $null)
                    ObjectClass     = $_.GetType().InvokeMember("Class", 'GetProperty', $null, $_, $null)    
                    SID             = ConvertTo-SID $_.GetType().InvokeMember("ObjectSID", 'GetProperty', $null, $_, $null)
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
            #    Computername = $env:COMPUTERNAME
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
                    PrincipalSource = $member.PrincipalSource
                    ObjectClass     = $member.ObjectClass            
                }
            }
        }
    }
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
                      @{Name='PrincipalSource'; Expression={$_.PrincipalSource}},
                      @{Name='ObjectClass'; Expression={$_.ObjectClass}} |
	    Export-Csv -Path local_groups.csv -Append -NoTypeInformation

    # Local system information
    Write-Output "Local: Getting system information"
    Get-ComputerInfo -OutVariable hotFixes |
        Select-Object CsName,
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

    $hotFixes.OsHotFixes | 
        ForEach-Object {
            [pscustomobject]@{
                HotFixID    = $_.HotFixID
                Description = $_.Description
                InstalledOn = $_.InstalledOn
                CsName      = $hotFixes.CsName
            }
        } | 
        Select-Object CsName,HotFixID,Description,InstalledOn | 
        Export-Csv -Path hotfixes.csv -Append -NoTypeInformation


    # Local user accounts
    Write-Output "Local: Getting local user accounts."
    getLocalUsers | 
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,SID,RID,Enabled,PasswordRequired,PasswordChangeable,PrincipalSource,Description,PasswordLastSet,LastLogon |
	    Export-Csv -Path local_users.csv -Append -NoTypeInformation

    # Processes
    # Check if the local session is running with elevated privileges
    Write-Output "Local: Getting processes."
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object System.Security.Principal.WindowsPrincipal($id)
    if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
        $localProcesses = Get-Process -IncludeUserName
    } else {
        $localProcesses = Get-Process
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

    # Network connections
    Write-Output "Local: Getting network connections."
    netConnects | 
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Date,Time,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,ProcessName |
        Export-Csv -Path net.csv -Append -NoTypeInformation

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




### Build PowerShell sessions for Invoke-Command query reuse ###

if($OUName) {
    $distinguishedName = 'OU=' + $OUName + ',' + (Get-ADDomain).DistinguishedName
} else {
    $distinguishedName = (Get-ADDomain).DistinguishedName
}

# Pull all computer objects listed in the Directory for the designated DN
$computers = Get-ADComputer -Filter * -Properties DistinguishedName,Enabled,IPv4Address,LastLogonDate,Name,OperatingSystem,SamAccountName -SearchBase $distinguishedName

# Export domain computer account info
Write-Output "Active Directory: Getting domain computer objects."
$computers | Export-Csv -Path domain_computers.csv -NoTypeInformation

# Create PS sessions for Windows only systems
$computers = $computers | Where-Object {$_.OperatingSystem -like "Windows*"}
$sessionOpt = New-PSSessionOption -NoMachineProfile # Minimize your presence and don't create a user profile on every system (e.g., C:\Users\<username>)

# Using the $computers.Name array method to create PS remoting sessions due to speed (compared to foreach)
Write-Output "Remoting: Creating PowerShell sessions."
New-PSSession -ComputerName $computers.Name -SessionOption $sessionOpt -ErrorAction SilentlyContinue | Out-Null # Create reusable PS Sessions

# Determine the systems where PS remoting failed
Get-FailedWinRMSessions $computers | 
    Select-Object Name,@{Name='Failure'; Expression={'WinRM'}} |
    Export-Csv -Path failed_collection.csv -Append -NoTypeInformation


### Removing data pull ###
# Local Administrators group membership
Write-Output "Remoting: Getting local group memberships."

Get-BrokenPSSessions 'LocalGroupMembers'

Invoke-Command -Session (Get-OpenPSSessions) -ScriptBlock ${function:getLocalGroupMembers} |
    Select-Object PSComputerName,
                  @{Name='GroupName'; Expression={$_.GroupName}},
                  @{Name='Name'; Expression={$_.Name}},
                  @{Name='Domain'; Expression={$_.Domain}},
                  @{Name='SID'; Expression={$_.SID}},
                  @{Name='PrincipalSource'; Expression={$_.PrincipalSource}},
                  @{Name='ObjectClass'; Expression={$_.ObjectClass}} |
    Export-Csv -Path local_groups.csv -Append -NoTypeInformation


# Local user accounts
Write-Output "Remoting: Getting local user accounts."
Get-BrokenPSSessions 'LocalUsers'

Invoke-Command -Session (Get-OpenPSSessions) -ScriptBlock ${function:getLocalUsers} |
    Select-Object PSComputerName,Name,SID,RID,Enabled,PasswordRequired,PasswordChangeable,PrincipalSource,Description,PasswordLastSet,LastLogon |
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
                                  @{Name='Hash'; Expression={if($_.Path -notlike '') {(Get-FileHash $_.Path).Hash}}},
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


# Network connections
Write-Output "Remoting: Getting network connections."
Get-BrokenPSSessions 'Network'

Invoke-Command -Session (Get-OpenPSSessions) -ScriptBlock ${function:netConnects} |
    Select-Object PSComputerName,Date,Time,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,ProcessName |
    Export-Csv -Path net.csv -Append -NoTypeInformation


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



### Servers ###
$winServers = $computers | Where-Object {$_.OperatingSystem -like "Windows Server*"}

# Using the $computers.Name array method to create PS remoting sessions due to speed (compared to foreach)
Write-Output "Remoting: Creating PowerShell server sessions."
$serverSessions = New-PSSession -ComputerName $winServers.Name -SessionOption $sessionOpt

# Windows Server installed features
Write-Output "Server: Getting installed features."
Invoke-Command -Session $serverSessions -ScriptBlock {Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed'} | Select-Object Name,DisplayName,Description,InstallState,Parent,Depth,Path,FeatureType} | 
    Select-Object PSComputerName,Name,DisplayName,Description,InstallState,Parent,Depth,Path,FeatureType |
	Export-Csv -Path windows_server_features.csv -Append -NoTypeInformation

# DHCP scope and lease records
Write-Output "Server: Getting DHCP leases."
$dhcp = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled=$true" | 
            Where-Object {$_.DHCPServer -like "10.*" -or $_.DHCPServer -like "172.*" -or $_.DHCPServer -like "192.168.*"}

Get-DHCPServerv4Scope -ComputerName $dhcp.DHCPServer | 
	Get-DHCPServerv4Lease -ComputerName $dhcp.DHCPServer -AllLeases | 
    Select-Object IPAddress,ScopeId,AddressState,ClientId,ClientType,Description,HostName,LeaseExpiryTime,ServerIP |
	Export-Csv dhcp_leases.csv -Append -NoTypeInformation



### Pull Active Directory datasets ###

# Get domain user account information
Write-Output "Active Directory: Getting domain user objects."
Get-ADUser -Filter * -Properties AccountExpirationDate,AccountNotDelegated,AllowReversiblePasswordEncryption,CannotChangePassword,DisplayName,Name,Enabled,LastLogonDate,LockedOut,PasswordExpired,PasswordNeverExpires,PasswordNotRequired,SamAccountName,SmartcardLogonRequired -SearchBase $distinguishedName |
	Export-Csv -Path domain_users.csv -NoTypeInformation

# Get all OU groups and their members
#$adGroupMembers = New-Object System.Collections.ArrayList
Write-Output "Active Directory: Getting domain group memberships."
$groups = Get-ADGroup -Filter * -Properties * -SearchBase $distinguishedName

foreach($group in $groups) {
    try {
        Get-ADGroupMember -Identity $group.SamAccountName -Recursive -ErrorAction SilentlyContinue | 
	        Where-Object {$_.objectClass -like "user"} |
            ForEach-Object {
                @{
                    UserSamAccountName  = $_.SamAccountName
                    UserDN              = $_.distinguishedName
                    UserName            = $_.name
                    GroupSamAccountName = $group.SamAccountName
                    GroupDN             = $group.DistinguishedName
                }
            } | 
        Select-Object @{Name='UserName'; Expression={$_.UserName}},
                      @{Name='UserSamAccountName'; Expression={$_.UserSamAccountName}},
                      @{Name='UserDN'; Expression={$_.UserDN}},
                      @{Name='GroupDN'; Expression={$_.GroupDN}},
                      @{Name='GroupSamAccountName'; Expression={$_.GroupSamAccountName}} | 
        Export-Csv -Path ad_group_members.csv -Append -NoTypeInformation
    } catch [Microsoft.ActiveDirectory.Management.ADException] {
        Write-Output "$($group.SamAccountName): AD error recursing group (likely out of domain)"
    }
}