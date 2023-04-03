import pymongo
from pydantic import BaseModel,EmailStr
from fastapi import FastAPI, HTTPException, Depends,Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from bson.objectid import ObjectId
from datetime import datetime, timedelta
from jose import jwt
from passlib.context import CryptContext
from fastapi import Depends
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
import secrets
import random
import uvicorn
client = pymongo.MongoClient("mongodb+srv://fa18c2bb038:Ma6IuqQ1n36twJCj@cluster0.am8x5h0.mongodb.net/?retryWrites=true&w=majority")

db = client["auth"]

class User(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    username: str
    phone_number: str
    date_of_birth: str
    password: str
    gender: str
    role: str = "user"


    

users_collection = db["users"]

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def get_user(username: str):
    user = users_collection.find_one({"username": username})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return User(**user)

def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not pwd_context.verify(password, user.password):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    return user

def create_access_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt



@app.post("/signup")
async def signup(user: User):
    user_dict = user.dict()
    user_dict["hashed_password"] = pwd_context.hash(user_dict.pop("password"))
    user_id = users_collection.insert_one(user_dict)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": str(user_id.inserted_id)}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/confirm-email")
def confirm_email(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"is_active": True}})
    except:
        raise HTTPException(status_code=400, detail="Invalid token")

@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token({"sub": str(user["_id"]), "role": user.role}, access_token_expires)
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/forgot-password")
def forgot_password(username: str):
    user = get_user(username)
    expires_delta = timedelta(minutes=30)
    access_token = create_access_token({"sub": str(user["_id"])}, expires_delta)
    # Send email with password reset link containing access_token
    return {"detail": "Password reset email sent"}

@app.post("/reset-password")
def reset_password(token: str, new_password: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"password": pwd_context.hash(new_password)}})
    except:
        raise HTTPException(status_code=400, detail="Invalid token")
    return {"detail": "Password updated successfully"}



async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("sub")
        user = users_collection.find_one({"_id": ObjectId(user_id)})
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid credentials")
        return User(**user)
    except:
        raise HTTPException(status_code=401, detail="Invalid credentials")

async def get_current_superuser(current_user: User = Depends(get_current_user)):
    if not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Permission denied")
    return current_user

@app.post("/create-user", dependencies=[Depends(get_current_superuser)])
def create_user(user: User):
    user_dict = user.dict()
    user_dict["password"] = pwd_context.hash(user.password)
    user_id = users_collection.insert_one(user_dict).inserted_id
    return {"id": str(user_id)}
uvicorn.run("main:app", host="0.0.0.0", port=8000)
