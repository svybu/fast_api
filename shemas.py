from datetime import date
from typing import List, Optional
from pydantic import BaseModel, Field


class ContactBase(BaseModel):
    """Base model for contact related fields."""
    first_name: str = Field(..., max_length=50)
    last_name: str = Field(..., max_length=50)
    email: str = Field(..., max_length=100)
    phone_number: str = Field(..., max_length=15)
    date_of_birth: date


class ContactCreate(ContactBase):
    """Model for creating a contact."""
    pass
    #done: bool


class ContactUpdate(ContactBase):
    """Model for updating a contact."""
    pass


class ContactResponse(ContactBase):
    """Model for response of a contact."""
    id: int

    class Config:
        orm_mode = True


class ContactListResponse(BaseModel):
    """Model for response of a list of contacts."""
    contacts: List[ContactResponse]


class UserAuthenticate(BaseModel):
    """Model for user authentication."""
    email: str
    password: str


class UserCreate(BaseModel):
    """Model for creating a user."""
    email: str
    password: str
    avatar: Optional[str]


class Token(BaseModel):
    """Model for JWT token."""
    access_token: str
    token_type: str
