from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncpg
import os
from dotenv import load_dotenv
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import uuid

load_dotenv()

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
SECRET_KEY = os.getenv("JWT_SECRET", "super_secret_jwt_key_please_change_in_prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7 # 1 week

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

class UserCreate(BaseModel):
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class CategoryCreate(BaseModel):
    name: str
    storage_path: str
    color_hex: str
    icon_name: str
    parent_id: Optional[str] = None

async def get_db():
    conn = await asyncpg.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", 5432)),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
    )
    try:
        yield conn
    finally:
        await conn.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), conn: asyncpg.Connection = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    try:
        user = await conn.fetchrow("SELECT * FROM profiles WHERE email = $1", email)
    except Exception as e:
        print("Error fetching user:", e)
        raise credentials_exception
        
    if user is None:
        raise credentials_exception
    return dict(user)

@app.on_event("startup")
async def startup_event():
    conn = await asyncpg.connect(
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", 5432)),
        database=os.getenv("DB_NAME"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
    )
    try:
        await conn.execute("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS email text UNIQUE")
        await conn.execute("ALTER TABLE profiles ADD COLUMN IF NOT EXISTS password_hash text")
    except Exception as e:
        print("Startup schema adjustment error:", e)
    finally:
        await conn.close()

@app.post("/auth/register")
async def register(user: UserCreate, conn: asyncpg.Connection = Depends(get_db)):
    existing = await conn.fetchrow("SELECT id FROM profiles WHERE email = $1", user.email)
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
        
    hashed_password = get_password_hash(user.password)
    user_id = str(uuid.uuid4())
    
    try:
        await conn.execute(
            "INSERT INTO profiles (id, email, password_hash) VALUES ($1, $2, $3)",
            user_id, user.email, hashed_password
        )
    except Exception as e:
        print("Error inserting:", e)
        raise HTTPException(status_code=500, detail=str(e))
        
    return {"message": "User registered successfully"}

@app.post("/auth/login")
async def login(user: UserLogin, conn: asyncpg.Connection = Depends(get_db)):
    try:
        db_user = await conn.fetchrow("SELECT * FROM profiles WHERE email = $1", user.email)
    except Exception as e:
        raise HTTPException(status_code=500, detail="Database error")

    if not db_user or not db_user.get("password_hash"):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
        
    if not verify_password(user.password, db_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
        
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email, "id": str(db_user["id"])}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/profiles")
async def get_profiles(current_user: dict = Depends(get_current_user)):
    profile = {k: v for k, v in current_user.items() if k != "password_hash"}
    return profile

@app.get("/categories")
async def get_categories(conn: asyncpg.Connection = Depends(get_db)):
    rows = await conn.fetch("SELECT * FROM categories ORDER BY name ASC")
    return [dict(row) for row in rows]

@app.post("/categories")
async def create_category(cat: CategoryCreate, conn: asyncpg.Connection = Depends(get_db)):
    cat_id = str(uuid.uuid4())
    try:
        await conn.execute(
            """INSERT INTO categories (id, name, storage_path, color_hex, icon_name, parent_id)
               VALUES ($1, $2, $3, $4, $5, $6)""",
            cat_id, cat.name, cat.storage_path, cat.color_hex, cat.icon_name, cat.parent_id
        )
        return {
            "id": cat_id, 
            "name": cat.name, 
            "storage_path": cat.storage_path, 
            "color_hex": cat.color_hex, 
            "icon_name": cat.icon_name, 
            "parent_id": cat.parent_id
        }
    except Exception as e:
        print("Error inserting category:", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/documents")
async def get_documents(conn: asyncpg.Connection = Depends(get_db)):
    rows = await conn.fetch("SELECT * FROM documents ORDER BY uploaded_at DESC")
    return [dict(row) for row in rows]

@app.get("/")
async def root():
    return {"status": "GDAVault API running"}

@app.get("/health")
async def health(conn: asyncpg.Connection = Depends(get_db)):
    return {"db": "connected"}