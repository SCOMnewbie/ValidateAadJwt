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