<#
.SYNOPSIS
    Downloads 1080p copies of any movies in Plex of a lower quality.

.DESCRIPTION
    This script retrieves a list of all movies in Plex (or in a specified library), and for each movie of a
        quality other than 1080p, generates a magnet link for a 1080p download based on search results from
        yts.lt. Once the magnet link is generated, it starts the download on DownloadStation hosted at the
        specified Synology URL.

.NOTES
    File Name: Get-Plex1080pUpgrades.ps1
    Requires: CredentialManager


.PARAMETER Url
    Specifies the URL or IP address of the Plex server. Default is localhost.

.PARAMETER Port
    Specifies the port Plex uses. Default is 32400.

.PARAMETER Libraries
    Specifies an array of libraries to look at for movies. Default is all movies.

.PARAMETER SynologyURL
    Specifies the URL of the Synology where DownloadStation is hosted.

.PARAMETER Verbose
    Specifies whether to output verbose console messages.

.EXAMPLE
    PS C:\>Get-Plex1080pUpgrades.ps1 -SynologyURL https://192.168.1.100

.EXAMPLE
    PS C:\>Get-Plex1080pUpgrades.ps1 -SynologyURL https://mysynology.mydomain.com

.EXAMPLE
    PS C:\>Get-Plex1080pUpgrades.ps1 -SynologyURL https://mysynology.mydomain.com -Libraries 'Movies'

.EXAMPLE
    PS C:\>Get-Plex1080pUpgrades.ps1 -SynologyURL https://mysynology.mydomain.com -Libraries @('Movies','Kids Movies')

.NOTES
    Requires CredentialManager module.

    > Install-Module CredentialManager

    > New-StoredCredential -Target plexToken -UserName plex -Password [Plex token] -Type Generic -Persist LocalMachine
    > New-StoredCredential -Target DownloadStation -UserName [DownloadStation username] -Password [DownloadStation password] -Type Generic -Persist LocalMachine

#>
param(
    # Optionally specify IP of the server we want to connect to
    [Parameter (Mandatory = $false)]
    [string]$PlexUrl = 'http://127.0.0.1',

    # Optionally define a custom port
    [Parameter (Mandatory = $false)]
    [int]$PlexPort = '32400',

    # Optionally, provide specific libraries to check
    [Parameter (Mandatory = $false)]
    [string[]] $Libraries,

    # Specify the URL of the Synology hosting DownloadStation
    [Parameter (Mandatory = $true)]
    [string]$SynologyURL,

    [Parameter (Mandatory = $false)]
    [bool] $Verbose = $true
)

#region Associated Files
if (-not (Get-Module CredentialManager)) {
    Try {
        Import-Module CredentialManager -ErrorAction Stop
    } Catch {
        Throw "Failed to load CredentialManager. Aborting."
    }
}
#endregion

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Try {
    $plexToken = Get-StoredCredential -Target 'plexToken' -ErrorAction Stop
    $plexToken = $plexToken.GetNetworkCredential().password
}
Catch {
    Throw "Failed to retrieve $Token from Windows Credential Manager."
}

Try {
    $downloadStationCreds = Get-StoredCredential -Target DownloadStation -ErrorAction Stop
}
Catch {
    Throw "Failed to retrieve DownloadStation creds from Windows Credential Manager."
}


$movieLibraries = Invoke-RestMethod "$PlexUrl`:$PlexPort/library/sections?X-Plex-Token=$plexToken"
$movieLibraries = $movieLibraries.MediaContainer.Directory | Where-Object {$_.type -eq 'movie'}

if ($Libraries) {
    $movieLibraries = $movieLibraries | Where-Object {$_.title -in $Libraries}
}

if ($movieLibraries.count -eq 0) {
    Throw "No libraries found to check against."
}

# Grab those libraries!
$movies = @()

foreach ($library in $movieLibraries) {
    $libraryContent = Invoke-RestMethod -Uri "$PlexUrl`:$PlexPort/library/sections/$($library.key)/all?X-Plex-Token=$plexToken"
    $movies = $libraryContent.MediaContainer.Video
}

$lowResMovies = $movies | Where-Object {$_.media.videoResolution -notin @("720","1080","4k")}

# Retrieve IMDB IDs for all matching movies from their guid (might assume you're using IMDB as the info source?)
$imdbID = [Regex]::new('tt\d{7,8}')
$imdbIDs = $imdbID.Matches($lowResMovies.guid).value

$torrents = @()
$i = 0
foreach ($movie in $imdbIDs) {
    $i++
    Write-Verbose "Retrieving $movie ($i of $($imdbIDs.count))." -Verbose:$Verbose
    $ytsResponse = Invoke-RestMethod -Uri "https://yts.lt/api/v2/list_movies.json?quality=1080p&query_term=$movie"

    if ($ytsResponse<#.data.movie_count#>) {
        $item = $ytsResponse.data.movies | Where-Object {$_.torrents.quality -eq '1080p'}

        $torrent = New-Object PSObject
        $torrent | Add-Member -Type NoteProperty -Name 'imdbID' -Value $movie
        $torrent | Add-Member -Type NoteProperty -Name 'slug' -Value ($item.slug | Select-Object -First 1)
        $torrent | Add-Member -Type NoteProperty -Name '1080pHash' -Value ($item.torrents | Where-Object {$_.quality -eq '1080p'} | Select-Object -ExpandProperty hash | Select-Object -First 1)

        $torrents += $torrent
    }
    <#else {
        Write-Verbose "WARN: No 1080p torrent found for $movie." -Verbose:$Verbose
    }#>
}

# Initialize connection to Synology
Invoke-RestMethod -uri "$SynologyURL/webapi/query.cgi?api=SYNO.API.Info&version=1&method=query&query=SYNO.API.Auth,SYNO.DownloadStation.Task"
# Create a session
$session = Invoke-RestMethod -uri "$SynologyURL/webapi/auth.cgi?api=SYNO.API.Auth&version=2&method=login&account=$($downloadStationCreds.username)&passwd=$($downloadStationCreds.GetNetworkCredential().password)&session=DownloadStation&format=cookie"
# Request DownloadStation API
Invoke-RestMethod -uri "$SynologyURL/webapi/DownloadStation/info.cgi?api=SYNO.DownloadStation.Info&version=1&method=getinfo&_sid=$($session.data.sid)"

$trackers = @(
    'udp://open.demonii.com:1337/announce'
    'udp://tracker.openbittorrent.com:80'
    'udp://tracker.coppersurfer.tk:6969'
    'udp://glotorrents.pw:6969/announce'
    'udp://tracker.opentrackr.org:1337/announce'
    'udp://torrent.gresille.org:80/announce'
    'udp://p4p.arenabg.com:1337'
    'udp://tracker.leechers-paradise.org:6969'
)

foreach ($torrent in $torrents | Where-Object {$_.slug}) {
    $magnetLink = "magnet:?xt=urn:btih:$($torrent.'1080pHash')&dn=$($torrent.slug)&tr=$($trackers -join ('&tr='))"
    $response = Invoke-RestMethod -uri "$SynologyURL/webapi/DownloadStation/task.cgi?api=SYNO.DownloadStation.Task&version=1&method=create&_sid=$($session.data.sid)&uri=$magnetLink"
}

# Log out of Synology
Invoke-RestMethod -uri "$SynologyURL/webapi/auth.cgi?api=SYNO.API.Auth&version=1&method=logout&session=DownloadStation"