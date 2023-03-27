Function Get-PublicKeysFromCache {
    [cmdletbinding()]
    param(
        [parameter(Mandatory)]
        [string]$Kid
    )

    Write-Verbose 'Get-PublicKeysFromCache - Begin function'

    #Define $HOMEPath variable dependin the platform
    $HOMEPath = Get-HomePath
    $FullPath = Join-Path -Path $HOMEPath -ChildPath ".validateaadjwt" -AdditionalChildPath $Kid

   Get-Content -Path $FullPath
   Write-Verbose 'Get-PublicKeysFromCache - End function'
}