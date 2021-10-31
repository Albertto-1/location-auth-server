from typing import List, Optional
from datetime import datetime, timedelta
import base64

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from jose import JWTError, jwt
import pyotp
from firebase_admin import db

from utils.models import Location, LoginUser, TokenData, NewUser
from utils.user import get_user
from utils.location import calculate_locations_weighted_center, get_locations_weighted_center, is_trusted_location, store_new_trusted_location, are_valid_locations

ACCESS_TOKEN_EXPIRE_MINUTES = 60
ALGORITHM = "HS256"
SECRET_KEY = "0842160add0aa60aaa83f66bce0c9c35efd601522b16f35411965188749684b3"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def authenticate_user_location(user_email: str, password: str, locations: Optional[List[Location]]):
    user = get_user(user_email)
    if not user:
        return {
                "success": False,
                "user": None,
                "error": "No existe ese usuario"
                }
    if not verify_password(password, user.hashed_password):
        return {
                "success": False,
                "user": None,
                "error": "Email o contraseña incorrectos"
                }
    are_valid, why = are_valid_locations(locations)
    if locations and are_valid and is_trusted_location(calculate_locations_weighted_center(locations), user):
        return {
                "success": True,
                "user": user,
                "error": None
                }
    return {
            "success": False,
            "user": user,
            "error": why
            }


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: Optional[str] = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar tus credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not token:
        raise credentials_exception
    try:
        tk = token;
        if "Bearer" in token or "bearer" in token:
            tk = token.split(" ")[1]
        payload = jwt.decode(tk, SECRET_KEY, algorithms=[ALGORITHM])
        user_email = payload.get("sub")
        print(payload)
        if user_email is None:
            raise credentials_exception
        token_data = TokenData(user_email=user_email)
    except JWTError as err:
        print(err)
        raise credentials_exception
    user = get_user(token_data.user_email)
    if user is None:
        raise credentials_exception
    return user


def register_user(user: NewUser):
    already_exist = get_user(user.email)
    if already_exist: return "Error: That email is already registered"
    base32secret = base64.b32encode(bytearray(user.password, 'ascii')).decode('utf-8')
    try:
        if user.locations:
            location = get_locations_weighted_center(user.locations)
            db.reference('/users').push({
                "name": user.name,
                "email": user.email,
                "hashed_password": get_password_hash(user.password),
                "trusted_locations": {db.reference().push().key: location},
                "totp_secret": base32secret,
                "refered_by": user.refered_by
                })
            access_token = create_access_token( data={
                "sub": user.email,
                "base32secret": base32secret,
                "new_location": location
                })
            return {"access_token": access_token, "token_type": "bearer"}
        else:
            db.reference('/users').push({
                "name": user.name,
                "email": user.email,
                "hashed_password": get_password_hash(user.password),
                "totp_secret": base32secret,
                "refered_by": user.refered_by
                })
            access_token = create_access_token( data={
                "sub": user.email,
                "base32secret": base32secret,
                "new_location": None
                })
            return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        return f'There was an error: {e}'



def login_location(login_data: LoginUser):
    auth_result = authenticate_user_location(login_data.email, login_data.password, login_data.locations)
    success = auth_result['success']
    user = auth_result['user']
    error = auth_result['error']
    if not success:
        if user:
            access_token = create_access_token( data={
                "sub": user.email,
                "trusted_location": False,
                "error": error
                })
            return {"access_token": access_token, "token_type": "bearer"}
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if user:
        access_token = create_access_token( data={
            "sub": user.email,
            "trusted_location": True
            })
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Error desconocido"
    )


async def login_totp(totp_location, authorization):
    totp_code = totp_location.totp
    user = await get_current_user(authorization)
    totp_decoder = pyotp.TOTP(user.totp_secret)
    totp_code = totp_decoder.now() # DELETE
    if totp_decoder.verify(totp_code):
        are_valid, why = are_valid_locations(totp_location.locations)
        if totp_location.locations and are_valid:
            location = get_locations_weighted_center(totp_location.locations)
            store_new_trusted_location(user.id, location)
            access_token = create_access_token( data={
                "sub": user.email,
                "new_location": location
                })
        else:
            access_token = create_access_token( data={
                "sub": user.email,
                "new_location": None,
                "error": why
                })
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Ocurrió un error."
    )

