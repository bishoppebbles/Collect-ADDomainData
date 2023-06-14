<#
.SYNOPSIS
    Queries various datasets on systems in a domain environment.
.DESCRIPTION
    
.PARAMETER OUName
    The OU name of interest
.EXAMPLE
    .\Collect-ADDomainData.ps1 -OUName <ou_name>
.NOTES
    Version 1.0.1
    Author: Sam Pursglove
    Last modified: 09 JUN 2023

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
            Select-Object Name,SID,Enabled,PasswordRequired,@{Name='PasswordChangeable'; Expression={$_.UserMayChangePassword}},PrincipalSource,Description,PasswordLastSet,LastLogon
    } catch [System.Management.Automation.RuntimeException] {       
        Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount='True'" -Property * | 
            Select-Object Name,SID,@{Name='Enabled'; Expression={if([bool]$_.Disabled) {'False'} else {'True'}}},PasswordRequired,PasswordChangeable,@{Name='PrincipalSource';Expression={if([bool]$_.LocalAccount) {'Local'}}},Description,@{Name='PasswordLastSet'; Expression={'Unavailable'}},@{Name='LastLogon'; Expression={'Unavailable'}}
    }
}


# Try to first get the group membership of all local groups using PS cmdlets but if that is unavailable use ADSI
# note: attempts to use the CIM WMI cmdlets would not work in my domain environment locally or remotely and it's unknown why
#   1) Get-CimInstance -Query "Associators of {Win32_Group.Domain='$env:COMPUTERNAME',Name='Administrators'} where Role=GroupComponent"
#   2) Get-CimInstance -ClassName Win32_Group -Filter "Name='Administrators'" | Get-CimAssociatedInstance -Association Win32_GroupUser
function getLocalGroupMembers {
    try {
        # get all local groups
        $groups = Get-LocalGroup

        # get the membership for all local groups
	    # NOTE!!!! cannot use [pscustomobject] in remoting b/c of constrained language mode limits to core types
        foreach ($group in $groups) {
    	    $localGroupMem = Get-LocalGroupMember $group
            foreach($member in $localGroupMem) {
                [pscustomobject]@{
                    GroupName       = $group.Name
                    Name            = $member.Name.split('\')[1]
                    Domain          = $member.Name.split('\')[0]
                    SID             = $member.SID
                    PrincipalSource = $member.PrincipalSource
                    ObjectClass     = $member.ObjectClass
                } 
            }
        }

        <# ***DRAFT*** code to use core data types (arrays and hashtables) instead of a pscustom object
           Returns an array of hashtables
        
        $groups = Get-LocalGroup

        # get the membership for all local groups
        # NOTE!!!! cannot use [pscustomobject] in remoting b/c of constrained language mode limits to core types
        foreach ($group in $groups) {
            $localGroupMem = Get-LocalGroupMember $group
            foreach($member in $localGroupMem) {
                @( @{GroupName=$group.Name}
                   @{Name=$member.Name.split('\')[1]}
                   @{Domain=$member.Name.split('\')[0]}
                   @{SID=$member.SID}
                   @{PrincipalSource=$member.PrincipalSource}
                   @{ObjectClass=$member.ObjectClass}
                )
            }
        }

        #>
    
    # run if the Get-Local* cmdlets are not installed on the remote systems
    } catch [System.Management.Automation.RuntimeException] {
        Write-Output "In the CATCH!"

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

                [pscustomobject]@{
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
            [pscustomobject]@{
                Computername = $env:COMPUTERNAME
                GroupName    = $g.Name[0]
                GroupMembers = (localGroupMember -Group $g)
            } 
        } 
        # ignore groups with no members
        $groupMembers | Where-Object {$_.GroupMembers -notlike ''}
        
        # output the combined group and individual group member data
        foreach($group in $groupMembers) {
            foreach($member in $group.GroupMembers) {
                [pscustomobject]@{
                    #Computername    = $group.ComputerName
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
$sessions = New-PSSession -ComputerName $computers.Name -SessionOption $sessionOpt # Create reusable PS Sessions


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
# !!!! Doesn't work remotely (see comments in the fuction above
<#
Invoke-Command -Session $sessions -ScriptBlock ${function:getLocalGroupMembers} |
    Export-Csv -Path local_groups.csv -NoTypeInformation
#>

# Local user accounts
Invoke-Command -Session $sessions -ScriptBlock ${function:getLocalUsers} | 
	Export-Csv -Path local_users.csv -NoTypeInformation

# Processes
Invoke-Command -Session $sessions -ScriptBlock {Get-Process -IncludeUserName | Select-Object Name,Id,Path,@{Name='Hash'; Expression={if($_.Path -notlike '') {(Get-FileHash $_.Path).Hash}}},UserName,Company,Description,ProductVersion,StartTime} |
	Export-Csv -Path processes.csv -NoTypeInformation

# Scheduled tasks
Invoke-Command -Session $sessions -ScriptBlock {Get-ScheduledTask | Select-Object TaskName,State,Author,TaskPath,Description} | 
	Export-Csv -Path scheduled_tasks.csv -NoTypeInformation

# Services
Invoke-Command -Session $sessions -ScriptBlock {Get-Service | Select-Object Name,DisplayName,Status,StartType,ServiceType} |
	Export-Csv -Path services.csv -NoTypeInformation

# Downloads, Documents, and Desktop files
Invoke-Command -Session $sessions -ScriptBlock {Get-ChildItem -Path 'C:\Users\*\Downloads\','C:\Users\*\Documents\','C:\Users\*\Desktop\' -Recurse | Select-Object Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes} |
	Export-Csv -Path files.csv -NoTypeInformation

# 64 bit programs
Invoke-Command -Session $sessions -ScriptBlock {Get-ChildItem -Path 'C:\Program Files' | Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'64-bit'}}} |
	Export-Csv -Path programs.csv -NoTypeInformation

# 32 bit programs
Invoke-Command -Session $sessions -ScriptBlock {Get-ChildItem -Path 'C:\Program Files (x86)' | Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'32-bit'}}} |
	Export-Csv -Path programs.csv -Append -NoTypeInformation

# Network connections
Invoke-Command -Session $sessions -ScriptBlock ${function:netConnects} |
    Export-Csv -Path net.csv -Append -NoTypeInformation
    
Remove-PSSession -Session $sessions


<#
    Pull data from the local system and append to the existing CSV files
    Note: I put in a function so it won't call the code automatically - still needs work
#>
function Collect-LocalSystemData {
    # Local Administrators group membership
    getLocalGroupMembers |
	    Export-Csv -Path local_groups.csv -Append -NoTypeInformation

    # Local user accounts
    getLocalUsers | 
        Select-Object Name,SID,Enabled,PasswordRequired,PasswordChangeable,PrincipalSource,Description,PasswordLastSet,LastLogon,@{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},PSShowComputerName,RunspaceID |
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
        Select-Object Name,Id,Path,@{Name='Hash'; Expression={if($_.Path -notlike '') {(Get-FileHash $_.Path).Hash}}},UserName,Company,Description,ProductVersion,StartTime,@{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},PSShowComputerName,RunspaceID |
	    Export-Csv -Path processes.csv -Append -NoTypeInformation

    # Scheduled tasks
    Get-ScheduledTask |
        Select-Object TaskName,State,Author,TaskPath,Description,@{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},PSShowComputerName,RunspaceID |
	    Export-Csv -Path scheduled_tasks.csv -Append -NoTypeInformation

    # Services
    Get-Service |
        Select-Object Name,DisplayName,Status,StartType,ServiceType,@{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},PSShowComputerName,RunspaceID |
	    Export-Csv -Path services.csv -Append -NoTypeInformation

    # Downloads, Documents, and Desktop files
    Get-ChildItem -Path 'C:\Users\*\Downloads\','C:\Users\*\Documents\','C:\Users\*\Desktop\' -Recurse |
        Select-Object Name,Extension,Directory,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},PSShowComputerName,RunspaceID |
	    Export-Csv -Path files.csv -Append -NoTypeInformation

    # 64 bit programs
    Get-ChildItem -Path 'C:\Program Files' |
        Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'64-bit'}},@{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},PSShowComputerName,RunspaceID |
	    Export-Csv -Path programs.csv -Append -NoTypeInformation

    # 32 bit programs
    Get-ChildItem -Path 'C:\Program Files (x86)' |
        Select-Object Name,CreationTime,LastAccessTime,LastWriteTime,Attributes,@{Name='ProgramType'; Expression={'32-bit'}},@{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},PSShowComputerName,RunspaceID |
	    Export-Csv -Path programs.csv -Append -NoTypeInformation

    # Network connections
    netConnects | 
        Select-Object Date,Time,LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess,ProcessName,@{Name='PSComputerName'; Expression={$env:COMPUTERNAME}},PSShowComputerName,RunspaceID |
        Export-Csv -Path net.csv -Append -NoTypeInformation
}

<#
Pull Active Directory datasets
#>

# Get domain user account information
Get-ADUser -Filter * -Properties AccountExpirationDate,AccountNotDelegated,AllowReversiblePasswordEncryption,CannotChangePassword,DisplayName,Name,Enabled,LastLogonDate,LockedOut,PasswordExpired,PasswordNeverExpires,PasswordNotRequired,SamAccountName,SmartcardLogonRequired -SearchBase $distinguishedName |
	Export-Csv -Path domain_users.csv -NoTypeInformation

# Get privileged domain account group memberships
$adminMemberOf = New-Object System.Collections.ArrayList
$groups = Get-ADGroup -Filter * -Properties * -SearchBase $distinguishedName

foreach($group in $groups) {
    Get-ADGroupMember -Identity $group.SamAccountName -Recursive | 
	    Where-Object {
	        ($_.objectClass -like "user") -and 
		    ($_.SamAccountName -like "*adm*" -or $_.SamAccountName -like "*admin*" -or $_.SamAccountName -like "*isso*")
	    } |
        ForEach-Object {
            $adminMemberOf.Add([PSCustomObject]@{
                UserSamAccountName  = $_.SamAccountName
                UserDN              = $_.distinguishedName
                UserName            = $_.name
                GroupSamAccountName = $group.SamAccountName
                GroupDN             = $group.DistinguishedName
            }) | Out-Null
        }
}

$adminMemberOf | Export-Csv -Path domain_admins.csv -NoTypeInformation
