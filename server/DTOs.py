from pydantic import BaseModel

class RegisterDTO(BaseModel):
    login: str
    password: str
    email: str
    public_key: str

class LoginDTO(BaseModel):
    login: str
    password: str