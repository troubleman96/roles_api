from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from database import Base, engine, get_db
from models import User
from schemas import TokenResponse, UserCreate, UserOut, TokenData
from auth import get_password_hash, verify_password, create_access_token, get_current_user

app = FastAPI()
Base.metadata.create_all(bind=engine)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Role-based dependency
def role_required(roles: list[str]):
    def check_role(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return check_role

# Super Admin creates Admin
@app.post("/register/admin", response_model=UserOut)
def register_admin(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required(["super_admin"]))
):
    if user.role != "admin":
        raise HTTPException(status_code=400, detail="This endpoint is for creating admins only")
    
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password, role="admin")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# Admin creates Driver
@app.post("/register/driver", response_model=UserOut)
def register_driver(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(role_required(["admin"]))
):
    if user.role != "driver":
        raise HTTPException(status_code=400, detail="This endpoint is for creating drivers only")
    
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password, role="driver")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# User self-registration
@app.post("/register/user", response_model=UserOut)
def register_user(
    user: UserCreate,
    db: Session = Depends(get_db)
):
    if user.role != "user":
        raise HTTPException(status_code=400, detail="This endpoint is for creating users only")
    
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, hashed_password=hashed_password, role="user")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

# Login endpoint (unchanged)
@app.post("/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == form_data.username).first()
    if not db_user or not verify_password(form_data.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(data={"sub": db_user.email, "role": db_user.role})

    return {"access_token": access_token, "token_type": "bearer"}

# Get current user (unchanged)
@app.get("/users/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user