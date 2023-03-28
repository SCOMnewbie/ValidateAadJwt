using namespace System.Security.Cryptography.X509Certificates
using namespace System.Security.Cryptography

class TokenExpiredException : System.Exception {
    TokenExpiredException ([string] $Message) : base($Message){
    }
}

class TokenVersionValidationFailedException : System.Exception {
    TokenVersionValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenAudienceValidationFailedException : System.Exception {
    TokenAudienceValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenSignatureValidationFailedException : System.Exception {
    TokenSignatureValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenAzpacrValidationFailedException : System.Exception {
    TokenAzpacrValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenAzpValidationFailedException : System.Exception {
    TokenAzpValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenIssValidationFailedException : System.Exception {
    TokenIssValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenUnusableException : System.Exception {
    TokenUnusableException ([string] $Message) : base($Message){
    }
}

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


function ConvertTo-X509Certificate2 {
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.X509Certificates.X509Certificate2])]
    param(
        [parameter(Mandatory)]$x5c
    )

    $ModCertInfo = @"
-----BEGIN CERTIFICATE-----
$($x5c)
-----END CERTIFICATE-----
"@
    $cBytes = [System.Text.Encoding]::UTF8.GetBytes($ModCertInfo)
    [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cBytes)
}

function Find-AzureX5c {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][String]$Kid
    )

    Write-Verbose 'Find-AzureX5c - Begin function'
    $ErrorActionPreference = 'Stop'

    try{
        #According to https://docs.microsoft.com/fr-fr/azure/active-directory/develop/access-tokens#validating-tokens
        $uri = 'https://login.microsoftonline.com/common/.well-known/openid-configuration'
        $WellKnownInfo = Invoke-RestMethod -Uri $uri -Method GET
        $PublicAADKeysURI = $WellKnownInfo.jwks_uri
        Write-Verbose "Find-AzureX5c - AAD Keys URI: $PublicAADKeysURI"
        $AADPublicKeys = Invoke-RestMethod -Uri $PublicAADKeysURI -Method GET
        Write-Verbose "Find-AzureX5c - AAD Keys: $AADPublicKeys"

        #Let's see if your Kid (cert thumbprint) parameter exist in Azure. If empty means your token is a bad one. If exist, means we have to pick one of Azure pubkey.
        $UsedKey = $AADPublicKeys.keys.Kid -contains $Kid
        Write-Verbose "Find-AzureX5c - AAD Used Key: $UsedKey"

        if ($UsedKey) {
            #$X5c represent the public key that has been used to encrypt your token
            Write-Verbose "Find-AzureX5c - Get public key value"
            $x5c = $AADPublicKeys.keys | Where-Object { $_.Kid -eq $Kid } | Select-Object -ExpandProperty x5c
            Write-Verbose 'Find-AzureX5c - End function'
        }
        else {
            Write-Verbose 'Find-AzureX5c - End function'
            $x5c = $null
        }

        return $x5c
    }
    catch{
        New-CustomExceptionGenerator -SignatureValidationFailed
    }
}

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

function New-CacheFolder {
    [CmdletBinding()]
    param()

    Write-Verbose 'New-CacheFolder - Begin function'

    $Path = Join-Path -Path $(Get-HomePath) -ChildPath ".validateaadjwt"
    $null = New-Item -Path $path -ItemType Directory -Force
    Write-Verbose 'New-CacheFolder - Cache folder created'

    Write-Verbose 'New-CacheFolder - End function'
}

function New-CustomExceptionGenerator {
    param(
        [Parameter(Mandatory=$true,ParameterSetName='TokenExpired')]
        [switch]$TokenExpired,
        [Parameter(Mandatory=$true,ParameterSetName='VersionValidationFailed')]
        [switch]$VersionValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='AudienceValidationFailed')]
        [switch]$AudienceValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='SignatureValidationFailed')]
        [switch]$SignatureValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='AzpacrValidationFailed')]
        [switch]$AzpacrValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='AzpValidationFailed')]
        [switch]$AzpValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='IssuerFailed')]
        [switch]$IssuerValidationFailed,
        [Parameter(Mandatory=$true,ParameterSetName='TokenUnusable')]
        [switch]$TokenUnusable
    )
    # This function is a wrapper to generate custom terminated exception from classes (look _CustomExceptions.ps1)
    $null = $MyError

    switch($PSBoundParameters.Keys){
        'TokenExpired'{
            $MyError = [TokenExpiredException]::new('Token provided is expired')
            break
        }
        'VersionValidationFailed'{
            $MyError = [TokenVersionValidationFailedException]::new('Token provided does not use the 2.0 endpoint version')
            break
        }
        'AudienceValidationFailed'{
            $MyError = [TokenAudienceValidationFailedException]::new('Token provided does target the right audience')
            break
        }
        'SignatureValidationFailed'{
            $MyError = [TokenSignatureValidationFailedException]::new('The signature of the provided token cannot be verified')
            break
        }
        'AzpacrValidationFailed'{
            $MyError = [TokenAzpacrValidationFailedException]::new('Token provided are not sent by a public application')
            break
        }
        'AzpValidationFailed'{
            $MyError = [TokenAzpValidationFailedException]::new('Token provided are not sent by a trusted application')
            break
        }
        'IssuerValidationFailed'{
            $MyError = [TokenIssValidationFailedException]::new('Token issuer is not valid')
            break
        }
        'TokenUnusable'{
            $MyError = [TokenUnusableException]::new('Token provided are not usable')
            break
        }
    }

    throw $MyError
}

function Test-CacheFolder {
    [CmdletBinding()]
    [OutputType([Bool])]
    param()

    Write-Verbose 'Test-CacheFolder - Begin function'
    $Path = Join-Path -Path $(Get-HomePath) -ChildPath ".validateaadjwt"
    Write-Verbose 'Test-CacheFolder- End function'
    Test-Path $Path
}

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

function Clear-PublicKeysCache {
    [CmdletBinding()]
    param()

    Write-Verbose 'Clear-PublicKeysCache - Begin function'

    $Path = Join-Path -Path $(Get-HomePath) -ChildPath ".validateaadjwt"
    Remove-Item -Path $Path

    Write-Verbose 'Clear-PublicKeysCache - End function'
}

function ConvertFrom-Jwt {
    <#
    .SYNOPSIS
    This function will decode a base64 JWT token.
    .DESCRIPTION
    Big thank you to both Darren Robinson (https://github.com/darrenjrobinson/JWTDetails/blob/master/JWTDetails/1.0.0/JWTDetails.psm1) and
    Mehrdad Mirreza in the comment of the blog post (https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell)
    I've used both article for inspiration because:
    Darren does not have header wich is a mandatory peace according to me and Mehrdad does not have signature which is also a mandatory piece.
    .PARAMETER Token
        Specify the access token you want to decode
    .EXAMPLE
    PS> ConvertFrom-Jwt -Token "ey...."

    "will decode the token"
    .NOTES
    VERSION HISTORY
    1.0 | 2021/07/06 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )

    Write-Verbose 'ConvertFrom-Jwt - Begin function'

    $ErrorActionPreference = 'Stop'
    $Token = $Token.Replace('Bearer ','')

    try {

        # Validate as per https://tools.ietf.org/html/rfc7519
        # Access and ID tokens are fine, Refresh tokens will not work
        if (!$Token.Contains('.') -or !$Token.StartsWith('eyJ')) { Write-Error 'Invalid token' -ErrorAction Stop }

        # Extract header and payload
        $tokenheader, $tokenPayload, $tokensignature = $Token.Split('.').Replace('-', '+').Replace('_', '/')[0..2]

        # Fix padding as needed, keep adding '=' until string length modulus 4 reaches 0
        while ($tokenheader.Length % 4) { Write-Debug 'Invalid length for a Base-64 char array or string, adding ='; $tokenheader += '=' }
        while ($tokenPayload.Length % 4) { Write-Debug 'Invalid length for a Base-64 char array or string, adding ='; $tokenPayload += '=' }
        while ($tokenSignature.Length % 4) { Write-Debug 'Invalid length for a Base-64 char array or string, adding ='; $tokenSignature += '=' }

        Write-Verbose "ConvertFrom-Jwt - Base64 encoded (padded) header:`n$tokenheader"
        Write-Verbose "ConvertFrom-Jwt - Base64 encoded (padded) payoad:`n$tokenPayload"
        Write-Verbose "ConvertFrom-Jwt - Base64 encoded (padded) payoad:`n$tokenSignature"

        # Convert header from Base64 encoded string to PSObject all at once
        $header = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json

        # Convert payload to string array
        $tokenArray = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($tokenPayload))

        # Convert from JSON to PSObject
        $tokobj = $tokenArray | ConvertFrom-Json

        # Convert Expiry time to PowerShell DateTime
        $orig = (Get-Date -Year 1970 -Month 1 -Day 1 -hour 0 -Minute 0 -Second 0 -Millisecond 0)
        $timeZone = Get-TimeZone
        $utcTime = $orig.AddSeconds($tokobj.exp)
        $hoursOffset = $timeZone.GetUtcOffset($(Get-Date)).hours #Daylight saving needs to be calculated
        $localTime = $utcTime.AddHours($hoursOffset)     # Return local time,

        # Time to Expiry
        $timeToExpiry = ($localTime - (get-date))

        Write-Verbose 'ConvertFrom-Jwt - End function'
        [pscustomobject]@{
            Tokenheader         = $header
            TokenPayload        = $tokobj
            TokenSignature      = $tokenSignature
            TokenExpiryDateTime = $localTime
            TokentimeToExpiry   = $timeToExpiry
        }
    }
    catch {
        New-CustomExceptionGenerator -TokenUnusable
    }
}

function Test-AADJWTSignature {
    <#
    .SYNOPSIS
    This function will validate Azure Active Directory token signature and other critical claims.
    .DESCRIPTION
    this function will also cache locally the public key used for the token signature to speed things up with offline token signature.
    .PARAMETER Token
        Specify the access token you want to verify.
    .PARAMETER TenantId
        Specify the Azure tenantId used to sign the token.
    .EXAMPLE
    PS> Test-AADJWTSignature -Token $AccessToken -TenantId "<my tenantid>"

    True means the token received is safe to use.
    .NOTES
    VERSION HISTORY
    1.0 | 2023/003/27 | Francois LEON
        initial version
    POSSIBLE IMPROVEMENT
        -
    #>
    [CmdletBinding()]
    [OutputType([Bool])]
    param(
        [Parameter(Mandatory)][String]$Token,
        [Parameter(Mandatory)][string]$TenantId
    )

    begin {
        Write-Verbose 'Test-AADJWTSignature - Begin function'
        # To avoid issue when we activate Azure func auth
        $AccessToken = $AccessToken.Replace('Bearer ','')
        if (-not $(Test-CacheFolder)) {
            New-CacheFolder
        }
        else {
            Write-Verbose 'Test-AADJWTSignature - Cache detected'
        }
    }

    process {

        $Jwt = ConvertFrom-Jwt -Token $Token -erroraction stop

        # Drop wrong token as quickly as possible

        # Azure expose only JWT Token with algorithm RS256, iss "https://login.microsoftonline.com/<tenantid>/v2.0" or "https://sts.windows.net/<tenantId>/"
        if ($Jwt.Tokenheader.typ -ne 'JWT') {
            Write-Verbose 'Test-AADJWTSignature - typ not equal JWT'
            New-CustomExceptionGenerator -TokenUnusable
        }

        if ($Jwt.Tokenheader.alg -ne 'RS256') {
            Write-Verbose 'Test-AADJWTSignature - typ not equal alg'
            New-CustomExceptionGenerator -TokenUnusable
        }

        $exp = (Get-Date 01.01.1970) + ([System.TimeSpan]::fromseconds($Jwt.TokenPayload.exp))
        if ((New-TimeSpan -Start $(Get-Date -AsUTC) -End $exp).TotalSeconds -lt 0) {
            New-CustomExceptionGenerator -TokenExpired
        }

        $iss = @("https://login.microsoftonline.com/$tenantid/v2.0","https://sts.windows.net/$tenantid/") #v1 and v2 endpoint included
        if ($Jwt.TokenPayload.iss -notin $iss) {
            Write-Verbose 'Test-AADJWTSignature - not issued by Azure'
            New-CustomExceptionGenerator -TokenUnusable
        }

        if ($null -eq $Jwt.Tokenheader.kid) {
            Write-Verbose 'Test-AADJWTSignature - kid not defined'
            New-CustomExceptionGenerator -TokenUnusable
        }

        # Now it's time to read the signature
        $kid = $Jwt.Tokenheader.kid

        #Update cache if needed for offline signature check
        if (-not $(Test-PublicKeysToCache -Kid $kid)) {
            Write-Verbose 'Test-AADJWTSignature - No cache detected'
            Add-PublicKeysToCache -Kid $kid
        }

        $x5c = Get-PublicKeysFromCache -Kid $kid
        $x509 = ConvertTo-X509Certificate2 -x5c $x5c

        # Now we can calculate the signature
        try {

            Write-Verbose "Test-AADJWTSignature - Verifying JWT signature"
            $parts = $Token.Split('.')

            #Compute our hash
            $SHA256 = New-Object Security.Cryptography.SHA256Managed
            $computed = $SHA256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($parts[0] + '.' + $parts[1])) # Computing SHA-256 hash of the JWT parts 1 and 2 - header and payload

            # Grab signature we received
            $signed = $parts[2].replace('-', '+').replace('_', '/') # Decoding Base64url to the original byte array
            $mod = $signed.Length % 4
            switch ($mod) {
                0 { $signed = $signed }
                1 { $signed = $signed.Substring(0, $signed.Length - 1) }
                2 { $signed = $signed + '==' }
                3 { $signed = $signed + '=' }
            }
            $bytes = [Convert]::FromBase64String($signed) # Conversion completed

            #Compare the two
            return $x509.PublicKey.Key.VerifyHash($computed, $bytes, [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1) # Returns True if the hash verifies successfully
        }
        catch {
            New-CustomExceptionGenerator -SignatureValidationFailed
        }
    }
}

Export-ModuleMember -Function 'Clear-PublicKeysCache', 'ConvertFrom-Jwt', 'Test-AADJWTSignature'
