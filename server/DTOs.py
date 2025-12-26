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
    content: tuple[bytes, bytes] # (message, key)
    attachments: list[tuple[tuple[str, bytes], bytes]] # [ ((filename, file_content), key) ]

class KeyTransferDTO(BaseModel):
    login: str
    key: str | None