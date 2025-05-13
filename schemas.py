from pydantic import BaseModel, EmailStr

class UserCreate(BaseModel):
    email: EmailStr
    password: str
    role: str = "user"  

class UserOut(BaseModel):
    id: int
    email: EmailStr
    role: str

    class Config:
        from_attributes = True

class TokenData(BaseModel):
   email: str
   role: str  

class TokenResponse(BaseModel):
    access_token: str
    token_type: str

  