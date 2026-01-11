from http import HTTPStatus
import shared.DTOs as DTOs

def is_password_secure(password: str) -> bool:
    if not (16 < len(password) < 50):
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

def get_b64_binary_size(b64_string):
    if not b64_string:
        return 0
    s = b64_string.strip()

    return (len(s)*3 // 4) - s.count('=', -2)

def verify_message_size(message_dto: DTOs.MessageDTO):
    MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024
    MAX_MESSAGE_SIZE = 5 * 1024

    if get_b64_binary_size(message_dto.content[0]) > MAX_MESSAGE_SIZE:
        return HTTPStatus.REQUEST_ENTITY_TOO_LARGE

    size_B = 0
    for a in message_dto.attachments:
        size_B += get_b64_binary_size(a[1])
        if size_B > MAX_ATTACHMENT_SIZE:
            break

    if size_B > MAX_ATTACHMENT_SIZE:
        return HTTPStatus.REQUEST_ENTITY_TOO_LARGE

    return HTTPStatus.OK

def verify_username(username: str):
    if not (3 <= len(username) <= 50):
        return False

    return all(c.isalnum() or c == '_' for c in username)