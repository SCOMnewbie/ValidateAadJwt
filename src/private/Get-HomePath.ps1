function Get-HomePath {
    [CmdletBinding()]
    param()

    Write-Verbose 'Get-HomePath - Begin function'
    if ($env:FUNCTIONS_WORKER_RUNTIME -eq 'Powershell') {
        Write-Verbose 'Get-HomePath - Azure function detected'
        $HOMEPath = [Environment]::GetEnvironmentVariable('TEMP')
    }
    elseif($IsLinux){
        Write-Verbose 'Get-HomePath - Linux detected'
        $HOMEPath = [Environment]::GetEnvironmentVariable('HOME')
    }
    else{
        Write-Verbose 'Get-HomePath - Windows detected'
        $HOMEPath = Join-Path $env:HOMEDRIVE $env:HOMEPATH
    }

    Write-Verbose 'Get-HomePath - End function'
    return $HOMEPath
}