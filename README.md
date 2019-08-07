# Get-Plex1080pUpgrades

Disclaimer: This script should only be used to download legal torrents and should not be used to illegally pirate any media. I am not responsible for any consequences of users of this script illegally pirating movies.

In order to run this script, you'll first need to install the CredentialManager module and store your Plex token and DownloadStation credentials in the Windows Credential Manager. Note that in order for this to work as-is, you'll need to use 'plexToken' and 'DownloadStation' as the names for these credentials specifically.

```powershell
Install-Module CredentialManager

New-StoredCredential -Target plexToken -UserName plex -Password [Plex token] -Type Generic -Persist LocalMachine
New-StoredCredential -Target DownloadStation -UserName [DownloadStation username] -Password [DownloadStation password] -Type Generic -Persist LocalMachine
```
