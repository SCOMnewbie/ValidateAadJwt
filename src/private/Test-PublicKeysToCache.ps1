Function Test-PublicKeysToCache {
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [string]$Kid
    )

    Write-Verbose 'Test-PublicKeysToCache - Begin function'

    #Define $HOMEPath variable dependin the platform
    $HOMEPath = Get-HomePath
    $FullPath = Join-Path -Path $HOMEPath -ChildPath ".validateaadjwt" -AdditionalChildPath $Kid
    Write-Verbose 'Test-PublicKeysToCache - End function'
    Test-Path $FullPath
}