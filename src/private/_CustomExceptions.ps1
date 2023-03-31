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

class TokenTypValidationFailedException : System.Exception {
    TokenTypValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenAlgValidationFailedException : System.Exception {
    TokenAlgValidationFailedException ([string] $Message) : base($Message){
    }
}

class TokenKidValidationFailedException : System.Exception {
    TokenKidValidationFailedException ([string] $Message) : base($Message){
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