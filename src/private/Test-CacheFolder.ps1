function Test-CacheFolder {
    [CmdletBinding()]
    [OutputType([Bool])]
    param()

    Write-Verbose 'Test-CacheFolder - Begin function'
    $Path = Join-Path -Path $(Get-HomePath) -ChildPath ".validateaadjwt"
    Write-Verbose 'Test-CacheFolder- End function'
    Test-Path $Path
}