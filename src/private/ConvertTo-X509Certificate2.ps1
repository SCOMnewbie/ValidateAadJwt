
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