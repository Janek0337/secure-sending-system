from pydantic import BaseModel

class RegisterDTO(BaseModel):
    username: str
    password: str
    email: str
    public_key: str

class LoginDTO(BaseModel):
    username: str
    password: str

class MessageDTO(BaseModel):
    receiver: str
    content: tuple[str, str] # (message, key) in base64
    attachments: list[tuple[tuple[str, str], str]] # [ ((filename, file_content), key) ] in base64

class GetMessageDTO(BaseModel):
    sender: str
    content: tuple[str, str] # (message, key) in base64
    attachments: list[tuple[tuple[str, str], str]] # [ ((filename, file_content), key) ] in base64
    date_sent: float

class KeyTransferDTO(BaseModel):
    username: str
    key: str | None

class MessageListElementDTO(BaseModel):
    username: str
    is_read: bool
    message_id: int
    date_sent: str

class MessageListListDTO(BaseModel):
    list_elements: list[MessageListElementDTO]
    owner: str

class ViewMessage(BaseModel):
    message_id: int
    sender: str
    content: str
    attachments: list[tuple[str, str]] # [ (filename, file_content) ] file_content in base64
    date_sent: str