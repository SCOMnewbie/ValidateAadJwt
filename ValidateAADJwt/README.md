# ValidateAadJwt

A PowerShell module to validate Azure Active Directory tokens. The goal of this module is simply to drop all bad tokens as quickly as possible and 
finally varify the signature based on your tenantId. This module will include both v1 and v2 Microsoft identity platform endpoints.

This module should be used when you plan to create Powershell API protected by Azure AD. Some mansatory claims are harcoded to avoid classic JWT attacks based on alg claim. In addition, to avoid unecessary Internet calls, this module cache locally the public key used to verify the token signature.

## Install

```powershell
Install-Module -Name ValidateAadJwt
```

## Disclaimer

This module was created AS IS with no warranty !
