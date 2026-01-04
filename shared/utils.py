def is_password_secure(password: str) -> bool:
    if len(password) < 16:
        return False

    hasLower = False
    hasUpper = False
    hasDigit = False
    hasSpecialCharacter = False
    for c in password:
        if c.islower(): hasLower = True
        if c.isupper(): hasUpper = True
        if c.isdigit(): hasDigit = True
        if not c.isalnum(): hasSpecialCharacter = True

    return hasLower and hasUpper and hasDigit and hasSpecialCharacter