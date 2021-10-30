from typing import List, Optional
from pydantic import BaseModel

class Location(BaseModel):
    id: Optional[str]
    lat: float
    lon: float
    acc: float
    weight: Optional[float]
    created_at: Optional[str]
    last_login_date: Optional[str]


class User(BaseModel):
    id: str
    name: str
    email: str
    hashed_password: str
    trusted_locations: List[Location]
    totp_secret: str
    refered_by: Optional[str]


class NewUser(BaseModel):
    name: str
    email: str
    password: str
    locations: Optional[List[Location]]
    refered_by: Optional[str]


class LoginUser(BaseModel):
    email: str
    password: str
    locations: List[Location]


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    user_email: str


class TOTPLocation(BaseModel):
    totp: str
    locations: Optional[List[Location]]

