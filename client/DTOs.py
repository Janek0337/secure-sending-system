from pydantic import BaseModel

class RegisterDTO(BaseModel):
    login: str
    password: str
    email: str
    public_key: str

class LoginDTO(BaseModel):
    login: str
    password: str

class MessageDTO(BaseModel):
    receiver: str
    content: tuple[str, str] # (message, key) in base64
    attachments: list[tuple[tuple[str, str], str]] # [ ((filename, file_content), key) ] in base64

class KeyTransferDTO(BaseModel):
    login: str
    key: str | None