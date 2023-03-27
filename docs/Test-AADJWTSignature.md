---
external help file: ValidateAadJwt-help.xml
Module Name: ValidateAADJwt
online version:
schema: 2.0.0
---

# Test-AADJWTSignature

## SYNOPSIS
This function will validate Azure Active Directory token signature and other critical claims.

## SYNTAX

```
Test-AADJWTSignature [-Token] <String> [-TenantId] <String> [<CommonParameters>]
```

## DESCRIPTION
this function will also cache locally the public key used for the token signature to speed things up with offline token signature.

## EXAMPLES

### EXAMPLE 1
```
Test-AADJWTSignature -Token $AccessToken -TenantId "<my tenantid>"
```

True means the token received is safe to use.

## PARAMETERS

### -Token
Specify the access token you want to verify.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -TenantId
Specify the Azure tenantId used to sign the token.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### System.Boolean
## NOTES
VERSION HISTORY
1.0 | 2023/003/27 | Francois LEON
    initial version
POSSIBLE IMPROVEMENT
    -

## RELATED LINKS
