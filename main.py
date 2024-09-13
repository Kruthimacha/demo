from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pymongo import MongoClient
import hashlib
from datetime import datetime, timedelta
from jose import JWTError, jwt

app = FastAPI()

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["mydatabase"] 
users_collection = db["users"]

class User(BaseModel):
    name: str
    email: str
    password: str
    dob: str

# Secret key for JWT encoding and decoding
SECRET_KEY = "your_generated_secret_key"  
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@app.get("/")
def read_root():
    return {"Hello": "World"}

@app.post("/api/register")
def register(user: User):
    # Check if email already exists
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Hash the password
    hashed_password = hashlib.sha256(user.password.encode()).hexdigest()

    # Insert user into MongoDB
    users_collection.insert_one({
        "name": user.name,
        "email": user.email,
        "password": hashed_password,
        "dob": user.dob
    })

    return {"message": "User registered successfully"}

@app.post("/api/login")
def login(email: str, password: str):
    # Retrieve user from MongoDB
    user = users_collection.find_one({"email": email})
    if user is None:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Verify password
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    if hashed_password != user.get("password"):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": email}, expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}
