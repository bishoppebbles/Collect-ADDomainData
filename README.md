# Collect-ADDomainData (aka FakeHyena)
This is a collection of commands to pull a variety of datasets in an Active Directory (AD) domain environment.  If you're familiar with the tool Hyena, this reproduces some of its collection capability but can pull data exponentially faster due to the parallel operation of PowerShell's `Invoke-Command`.  Credit for the `FakeHyena` name goes to Kennon Lee.

## !!!WARNING!!! ~~Usage~~
This script is hacked up and still under development!  It won't run as-is if you try `.\Collect-ADDomainData -OUName <ou>`.  Well it might run but probably not as expected, possible worse.  I obvioulsy know the command specifics so I run sections of the code piecemeal (e.g., import the necessary functions for the current sessions, get the list of domain computer objects, create the PS sessions, then collect the datasets).  I'm working towards making it more robust but as of now it's not there.  Use are your own risk!

### Requirements
This code requires the use of PowerShell (PS) Remoting so this must be enabled and accessible in your target environment.  I also wrote code to run these commands locally as well.  This can be used if PS Remoting isn't an option or to ensure you capture the dataset of the host system.

#### Enabling PS Remoting with Group Policy
1) Enable the WinRM service
  * `Computer Configuration > Policies > Administrative Templates > Windows Components > Windows Remote Management (WinRM) > WinRM Service > Allow remote server management through WinRM`
    * Set `IPv4/IPv6 filters to all (*)`

2) Set the WS-Management service to automatic startup
  * `Computer Configuration > Policies > Windows Settings > Security Settings > System Services > Windows Remote Management (WS-Management)`

3) Allow Windows Remote Management in the Firewall
  * Navigate to the following folder in the Group Policy Management Console (GPMC), right-click `Inbound Rules`, and click `New Rule`.
    * `Computer Configuration > Policies > Windows Settings > Security Settings > Windows (Defender) Firewall with Advanced Security`
      * In the `Predefined` field, select `Windows Remote Management` and then follow the wizard to add the new firewall rule.

#### Enable PS Remoting with WMI
There may be circumstances where you have local admin in your target environment but no access to a domain controller or server with the Group Policy Management MMC console.  In those cases it may be possible to enable PS Remoting using the PowerShell CIM cmdlets with DCOM.  Since you need WinRM to use PS Remoting you can't use that here if it hasn't been enabled.  If it was, this wouldn't be necessary.

```powershell
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
```

## Workstation and Server Datasets
* **Local group Memberships** (note: disabled/broken)
    * Output fields: GroupName, Name, Domain, SID, PrincipalSource, ObjectClass
* **Local user accounts**
    * Output fields: Name, SID, RID (calculated), Enabled, PasswordRequired, PasswordChangeable (calculated), PrincipalSource, Description, PasswordLastSet, LastLogon
* **Processes**
    * Output fields: Name, Id, Path, Hash (calculated), UserName, Company, Description, ProductVersion, StartTime
* **Scheduled tasks**
    * Output fields: TaskName (unique suffixes removed), State, Author, TaskPath, Description
* **Services**
    * Output fields: Name (unique suffixes removed), DisplayName (unique suffixes removed), Status, StartType, ServiceType
* **File names** from the `Documents`, `Downloads`, or `Desktop` directories (recursively) for any user profile in `C:\Users`
    * Output fields: Name, Extension, Directory, CreationTime, LastAccessTime, LastWriteTime, Attributes
* **Program names** (i.e., directories) in `C:\Program Files` and `C:\Program Files (x86)`
    * Output fields: Name, CreationTime, LastAccessTime, LastWriteTime, Attributes, ProgramType (calculated 32/64 bit)
* **Network connections**
    * Output fields: Date, Time, LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess , ProcessName (calculated)
* **Shares**
    * Output fields: Name, Path, Description, EncryptData, CurrentUsers, ShareType
* **Share permissions**
    * Output fields: Name, AccountName, AccessControlType, AccessRight

## Server Specific Datasets
* **Windows installed features**
    * Output fields: Name, DisplayName, Description, InstallState, Parent, Depth, Path, FeatureType
* **DHCP scopes and leases**
    * Output fields: IPAddress, ScopeId, AddressState, ClientId, ClientType, Description, HostName, LeaseExpiryTime, ServerIP

## Active Directory Datasets
* **AD computer objects**
    * Output fields: DistinguishedName, Enabled, IPv4Address, LastLogonDate, Name, OperatingSystem, SamAccountName
* **AD user objects**
    * Output fields: AccountExpirationDate, AccountNotDelegated, AllowReversiblePasswordEncryption, CannotChangePassword, DisplayName, Name, Enabled, LastLogonDate, LockedOut, PasswordExpired, PasswordNeverExpires, PasswordNotRequired, SamAccountName, SmartcardLogonRequired
* **AD group memberships**
    * Output fields: UserSamAccountName, UserDN, UserName, GroupSamAccountName, GroupDN

### TODO
* Fix local group member issues
* Auto pull DHCP server (if possible)
* Switch to run local collection
* Check if PS Remoting is enabled (maybe a switch)

