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
    if locations and are_valid:
        center = calculate_locations_weighted_center(locations)
        lat = center["lat"]
        lon = center["lon"]
        acc = center["acc"]
        if is_trusted_location({"lat":lat, "lon":lon, "acc":acc}, user):
            return {
                    "success": True,
                    "user": user,
                    "error": None
                    }
        else: 
            return {
                    "success": False,
                    "user": user,
                    "error": "No estás en una ubicación confiable."
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


def get_token_payload(token: Optional[str] = Depends(oauth2_scheme)):
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
        return payload
    except JWTError as err:
        print(err)
        raise credentials_exception


async def get_current_user(payload):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar tus credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    user_email = payload.get("sub")
    if user_email is None:
        raise credentials_exception
    user = get_user(user_email)
    if user is None:
        raise credentials_exception
    return user


def register_user(user: NewUser):
    already_exist = get_user(user.email)
    if already_exist: return { "detail": "Este correo ya está registrado" }
    base32secret = base64.b32encode(bytearray(user.password, 'ascii')).decode('utf-8')
    try:
        are_valid, why = are_valid_locations(user.locations)
        if user.locations and are_valid:
            location = get_locations_weighted_center(user.locations)
            db.reference('/users').push({
                "name": user.name,
                "email": user.email,
                "hashed_password": get_password_hash(user.password),
                "trusted_locations": {db.reference().push().key: location},
                "totp_secret": base32secret,
                "refered_by": user.refered_by,
                "is_active": False
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
                "refered_by": user.refered_by,
                "is_active": False
                })
            access_token = create_access_token( data={
                "sub": user.email,
                "base32secret": base32secret,
                "new_location": None,
                "error": why
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
        if user.is_active:
            access_token = create_access_token( data={
                "sub": user.email,
                "trusted_location": True,
                "active_account": user.is_active
                })
        else:
            access_token = create_access_token( data={
                "sub": user.email,
                "trusted_location": True,
                "active_account": user.is_active,
                "base32secret": user.totp_secret
                })
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Error desconocido"
    )


async def login_totp(totp_location, authorization):
    totp_code = totp_location.totp
    payload = get_token_payload(authorization)
    user = await get_current_user(payload)
    totp_decoder = pyotp.TOTP(user.totp_secret)
    # totp_code = totp_decoder.now() # DELETE
    if totp_decoder.verify(totp_code):
        are_valid, why = are_valid_locations(totp_location.locations)
        if totp_location.locations and are_valid and payload.get("error") == "No estás en una ubicación confiable.":
            location = get_locations_weighted_center(totp_location.locations)
            store_new_trusted_location(user.id, location)
            access_token = create_access_token( data={
                "sub": user.email,
                "new_location": location
                })
        else:
            if are_valid and payload.get("error") != "No estás en una ubicación confiable.":
                why = payload.get("error")
            if payload.get("base32secret"):
                access_token = create_access_token( data={
                    "sub": user.email,
                    "new_location": None,
                    "base32secret": payload.get("base32secret")
                    })
            else:
                access_token = create_access_token( data={
                    "sub": user.email,
                    "new_location": None,
                    "error": why
                    })
        db.reference(f'/users/{user.id}').update({
            "is_active": True,
            })
        return {"access_token": access_token, "token_type": "bearer"}
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Ocurrió un error."
    )


async def store_user_feedback(feedback_form, authorization):
    payload = get_token_payload(authorization)
    user = await get_current_user(payload)
    location = None
    if feedback_form.locations:
        location = get_locations_weighted_center(feedback_form.locations)
    today = datetime.today().isoformat()
    db.reference("/feedbacks").push({
        "used_id": user.id,
        "network_type": feedback_form.network_type,
        "device": feedback_form.device,
        "result": feedback_form.result,
        "expected_trusted_location": feedback_form.expected_trusted_location,
        "with_interference": feedback_form.with_interference,
        "moving": feedback_form.moving,
        "location": location,
        "created_at": today
        })
    return {
            "success": True,
            "message": "Gracias por tomarte el tiempo de ayudar en este proyecto."
            }

