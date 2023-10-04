<#
.SYNOPSIS
    Queries various datasets on systems in a domain environment.
.DESCRIPTION
    
.PARAMETER OUName
    The OU name of interest
.EXAMPLE
    .\Collect-ADDomainData.ps1 -OUName <ou_name>
.NOTES
    Version 1.0.9
    Author: Sam Pursglove
    Last modified: 04 October 2023

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

<#
Functions
#>

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


<#
Build PowerShell sessions for query reuse
#>
if($OUName) {
    $distinguishedName = 'OU=' + $OUName + ',' + (Get-ADDomain).DistinguishedName
} else {
    $distinguishedName = (Get-ADDomain).DistinguishedName
}

# Pull all computer objects listed in the Directory for the designated DN
$computers = Get-ADComputer -Filter * -Properties DistinguishedName,Enabled,IPv4Address,LastLogonDate,Name,OperatingSystem,SamAccountName -SearchBase $distinguishedName

# Export domain computer account info
$computers | Export-Csv -Path domain_computers.csv -NoTypeInformation

# Create PS sessions for Windows only systems
$computers = $computers | Where-Object {$_.OperatingSystem -like "Windows*"}
$sessionOpt = New-PSSessionOption -NoMachineProfile # Minimize your presence and don't create a user profile on every system (e.g., C:\Users\<username>)

#try {
    $sessions = New-PSSession -ComputerName $computers.Name -SessionOption $sessionOpt # Create reusable PS Sessions
#} catch [System.Management.Automation.Remoting.PSRemotingTransportException] {
#    Write-Output "$(($_.ErrorDetails.ToString().Split('] ')[0]).Split('[')[1]): WinRM error"
#}


<#
# Attempt to enable WinRM/PS remoting via WMI for systems that don't have it configured
$comps = <comp_name_array>
$cimSessOption = New-CimSessionOption -Protocol Dcom

foreach($c in $comps) {
    if(Test-Connection $c -Count 2) {          
        $cimSession = New-CimSession -ComputerName $c -SessionOption $cimSessOption
        Invoke-CimMethod -ClassName 'Win32_Process' -MethodName 'Create' -CimSession $cimSession -Arguments @{CommandLine = "powershell Start-Process powershell -ArgumentList 'Enable-PSRemoting -Force'"} | Out-Null
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
#>


<#
Pull remote system data
#>

# Local Administrators group membership
Invoke-Command -Session $sessions -ScriptBlock ${function:getLocalGroupMembers} |
    Select-Object PSComputerName,
                  @{Name='GroupName'; Expression={$_.GroupName}},
                  @{Name='Name'; Expression={$_.Name}},
                  @{Name='Domain'; Expression={$_.Domain}},
                  @{Name='SID'; Expression={$_.SID}},
                  @{Name='PrincipalSource'; Expression={$_.PrincipalSource}},
                  @{Name='ObjectClass'; Expression={$_.ObjectClass}} |
    Export-Csv -Path local_groups.csv -NoTypeInformation


# Local user accounts
Invoke-Command -Session $sessions -ScriptBlock ${function:getLocalUsers} |
    Select-Object PSComputerName,Name,SID,RID,Enabled,PasswordRequired,PasswordChangeable,PrincipalSource,Description,PasswordLastSet,LastLogon |
	Export-Csv -Path local_users.csv -NoTypeInformation


# Processes
Invoke-Command -Session $sessions `
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
	Export-Csv -Path processes.csv -NoTypeInformation


# Scheduled tasks
Invoke-Command -Session $sessions `
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
	Export-Csv -Path scheduled_tasks.csv -NoTypeInformation

# Services
Invoke-Command -Session $sessions `
               -ScriptBlock {
                    Get-Service | 
                    Select-Object @{Name='Name'; Expression={$_.Name.Split('_')[0]}}, # remove unique service name suffix
                                  @{Name='DisplayName'; Expression={$_.DisplayName.Split('_')[0]}}, # remove unique service display name suffix
                                  Status,
                                  StartType,
                                  ServiceType
               } |
    Select-Object PSComputerName,Name,DisplayName,Status,StartType,ServiceType |
    Export-Csv -Path services.csv -NoTypeInformation


# Downloads, Documents, and Desktop files
Invoke-Command -Session $sessions `
               -ScriptBlock {
                    Get-ChildItem -Path 'C:\Users\*\Downloads\','C:\Users\*\Documents\','C:\Users\*\Desktop\' -Recurse | 
                    Select-Object Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes
               } |
	Select-Object PSComputerName,Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes |
    Export-Csv -Path files.csv -NoTypeInformation


# 64 bit programs
Invoke-Command -Session $sessions `
               -ScriptBlock {
                    Get-ChildItem -Path 'C:\Program Files' | 
                    Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'64-bit'}}
               } |
	Select-Object PSComputerName,Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,ProgramType |
    Export-Csv -Path programs.csv -NoTypeInformation


# 32 bit programs
Invoke-Command -Session $sessions `
               -ScriptBlock {
                    Get-ChildItem -Path 'C:\Program Files (x86)' | 
                    Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'32-bit'}}
               } |
	Select-Object PSComputerName,Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,ProgramType |
    Export-Csv -Path programs.csv -Append -NoTypeInformation


# Network connections
Invoke-Command -Session $sessions -ScriptBlock ${function:netConnects} |
    Select-Object PSComputerName,Date,Time,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,ProcessName |
    Export-Csv -Path net.csv -NoTypeInformation


# Shares
Invoke-Command -Session $sessions `
               -ScriptBlock {
                    Get-SmbShare | 
                    Select-Object Name,Path,Description,EncryptData,CurrentUsers,ShareType
               } |
    Select-Object PSComputerName,Name,Path,Description,EncryptData,CurrentUsers,ShareType |
    Export-Csv -Path shares.csv -NoTypeInformation


# Share permissions
Invoke-Command -Session $sessions `
               -ScriptBlock {
                    Get-SmbShare | 
                    Get-SmbShareAccess | 
                    Select-Object Name,AccountName,AccessControlType,AccessRight
               } |
	Select-Object PSComputerName,Name,AccountName,AccessControlType,AccessRight |
    Export-Csv -Path share_permissions.csv -NoTypeInformation
    
Get-PSSession | Remove-PSSession


<#
    Pull data from the local system and append to the existing CSV files
#>
function Collect-LocalSystemData {
    # Local Administrators group membership
    getLocalGroupMembers |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},
                      @{Name='GroupName'; Expression={$_.GroupName}},
                      @{Name='Name'; Expression={$_.Name}},
                      @{Name='Domain'; Expression={$_.Domain}},
                      @{Name='SID'; Expression={$_.SID}},
                      @{Name='PrincipalSource'; Expression={$_.PrincipalSource}},
                      @{Name='ObjectClass'; Expression={$_.ObjectClass}} |
	    Export-Csv -Path local_groups.csv -Append -NoTypeInformation

    # Local user accounts
    getLocalUsers | 
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,SID,Enabled,PasswordRequired,PasswordChangeable,PrincipalSource,Description,PasswordLastSet,LastLogon |
	    Export-Csv -Path local_users.csv -Append -NoTypeInformation

    # Processes
    # Check if the local session is running with elevated privileges
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
    Get-ScheduledTask |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},TaskName,State,Author,TaskPath,Description |
	    Export-Csv -Path scheduled_tasks.csv -Append -NoTypeInformation

    # Services
    Get-Service |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,DisplayName,Status,StartType,ServiceType |
	    Export-Csv -Path services.csv -Append -NoTypeInformation

    # Downloads, Documents, and Desktop files
    Get-ChildItem -Path 'C:\Users\*\Downloads\','C:\Users\*\Documents\','C:\Users\*\Desktop\' -Recurse |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes |
	    Export-Csv -Path files.csv -Append -NoTypeInformation

    # 64 bit programs
    Get-ChildItem -Path 'C:\Program Files' |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'64-bit'}} |
	    Export-Csv -Path programs.csv -Append -NoTypeInformation

    # 32 bit programs
    Get-ChildItem -Path 'C:\Program Files (x86)' |
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'32-bit'}} |
	    Export-Csv -Path programs.csv -Append -NoTypeInformation

    # Network connections
    netConnects | 
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Date,Time,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,ProcessName |
        Export-Csv -Path net.csv -Append -NoTypeInformation

    # Shares
    Get-SmbShare | 
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,Path,Description,EncryptData,CurrentUsers,ShareType |
        Export-Csv -Path shares.csv -Append -NoTypeInformation

    # Share permissions
    Get-SmbShare | 
        Get-SmbShareAccess | 
        Select-Object @{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},Name,AccountName,AccessControlType,AccessRight |
        Export-Csv -Path share_permissions.csv -Append -NoTypeInformation
}

<#
Servers
#>

$serverSessions = Get-PSSession |  Where-Object {$_.ComputerName -like "$($ouname)*"}

# Windows Server installed features
Invoke-Command -Session $serverSessions -ScriptBlock {Get-WindowsFeature | Where-Object {$_.InstallState -eq 'Installed'} | Select-Object Name,DisplayName,Description,InstallState,Parent,Depth,Path,FeatureType} | 
	Export-Csv -Path windows_server_features.csv -NoTypeInformation

# DHCP scope and lease records
$dhcp = Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "DHCPEnabled=$true" | 
            Where-Object {$_.DHCPServer -like "10.*" -or $_.DHCPServer -like "172.*" -or $_.DHCPServer -like "192.168.*"}

Get-DHCPServerv4Scope -ComputerName $dhcp.DHCPServer | 
	Get-DHCPServerv4Lease -ComputerName $dhcp.DHCPServer -AllLeases | 
    Select-Object IPAddress,ScopeId,AddressState,ClientId,ClientType,Description,HostName,LeaseExpiryTime,ServerIP |
	Export-Csv dhcp_leases.csv -NoTypeInformation


<#
Pull Active Directory datasets
#>

# Get domain user account information
Get-ADUser -Filter * -Properties AccountExpirationDate,AccountNotDelegated,AllowReversiblePasswordEncryption,CannotChangePassword,DisplayName,Name,Enabled,LastLogonDate,LockedOut,PasswordExpired,PasswordNeverExpires,PasswordNotRequired,SamAccountName,SmartcardLogonRequired -SearchBase $distinguishedName |
	Export-Csv -Path domain_users.csv -NoTypeInformation

# Get all OU groups and their members
#$adGroupMembers = New-Object System.Collections.ArrayList
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