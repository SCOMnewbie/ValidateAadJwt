function Clear-PublicKeysCache {
    [CmdletBinding()]
    param()

    Write-Verbose 'Clear-PublicKeysCache - Begin function'

    $Path = Join-Path -Path $(Get-HomePath) -ChildPath ".validateaadjwt"
    Remove-Item -Path $Path

    Write-Verbose 'Clear-PublicKeysCache - End function'
}