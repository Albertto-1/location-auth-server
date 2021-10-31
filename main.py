from typing import Optional

from utils.auth import get_current_user, login_totp, login_location, register_user, get_token_payload
from utils.models import LoginUser, NewUser, TOTPLocation
from fastapi import FastAPI, Header
import firebase_admin
from firebase_admin import credentials
from fastapi.middleware.cors import CORSMiddleware

cred = credentials.Certificate("./service-account.json")
firebase_admin.initialize_app(cred, {
    'databaseURL': 'https://location-auth-10-default-rtdb.firebaseio.com/'
    })

app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/user")
async def user_get(authorization: Optional[str] = Header(None)):
    payload = get_token_payload(authorization)
    return await get_current_user(payload)

@app.post("/user")
async def user_post(user: NewUser):
    return register_user(user)

@app.post("/auth/location")
async def auth_location(login_data: LoginUser):
    return login_location(login_data)

@app.post("/auth/totp")
async def auth_totp(totp_location: TOTPLocation, authorization: Optional[str] = Header(None)):
    return await login_totp(totp_location, authorization)

@app.post("/user/feedback")
async def user_feedback():
    return {"message": "Hello World"}
