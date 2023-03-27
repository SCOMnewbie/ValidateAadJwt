Function Add-PublicKeysToCache {
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [string]$Kid
    )

    Write-Verbose 'Add-PublicKeysToCache - Begin function'

    $HOMEPath = Get-HomePath
    $FullPath = Join-Path -Path $HOMEPath -ChildPath ".validateaadjwt" -AdditionalChildPath $Kid

    $x5c = Find-AzureX5c -Kid $Kid
    Write-Verbose 'Add-PublicKeysToCache - Update cache with new value'
    Set-Content -Path $FullPath -Value $x5c -Force
    Write-Verbose 'Add-PublicKeysToCache - End function'
}