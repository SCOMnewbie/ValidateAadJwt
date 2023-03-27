function New-CacheFolder {
    [CmdletBinding()]
    param()

    Write-Verbose 'New-CacheFolder - Begin function'

    $Path = Join-Path -Path $(Get-HomePath) -ChildPath ".validateaadjwt"
    $null = New-Item -Path $path -ItemType Directory -Force
    Write-Verbose 'New-CacheFolder - Cache folder created'

    Write-Verbose 'New-CacheFolder - End function'
}