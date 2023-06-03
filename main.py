from fastapi import FastAPI, Depends, HTTPException, Security, Request, BackgroundTasks, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from fastapi_limiter import FastAPILimiter
from fastapi_limiter.depends import RateLimiter
from fastapi.middleware.cors import CORSMiddleware
import redis.asyncio as redis
from sqlalchemy.orm import Session
from pydantic import BaseModel
from starlette import status
from passlib.context import CryptContext
import cloudinary
import cloudinary.uploader
from dotenv import load_dotenv
import os

from database.db import get_db
from database.models import User, Contact
from shemas import ContactCreate, ContactUpdate
from services.auth import Hash, auth_service
from services.email import send_email

load_dotenv()

cloudinary.config(
    cloud_name=os.getenv("CLOUD_NAME"),
    api_key=os.getenv("API_KEY"),
    api_secret=os.getenv("API_SECRET"),
)
app = FastAPI()
origins = [
    "http://localhost:8000"
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

hash_handler = Hash()
security = HTTPBearer()


class UserModel(BaseModel):
    """Model representing a user."""
    email: str
    password: str


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@app.on_event("startup")
async def startup():
    """Event handler for application startup."""
    r = await redis.Redis(host='localhost', port=6379, db=0, encoding="utf-8", decode_responses=True)
    await FastAPILimiter.init(r)


@app.post("/signup", status_code=status.HTTP_201_CREATED, dependencies=[Depends(RateLimiter(times=5, minutes=1))])
async def signup(body: UserModel, background_tasks: BackgroundTasks, request: Request,
                 db: Session = Depends(get_db)):
    """
    Register a new user.

    Parameters:
    - body (UserModel): The user data including email and password.
    - background_tasks (BackgroundTasks): Background tasks to execute.
    - request (Request): The incoming request.
    - db (Session): The database session.

    Returns:
    - dict: The newly created user information.
    """
    exist_user = db.query(User).filter(User.email == body.email).first()
    if exist_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Account already exists")

    hashed_password = pwd_context.hash(body.password)
    new_user = User(email=body.email, password=hashed_password)
    background_tasks.add_task(send_email, new_user.email, new_user.email, request.base_url)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {"user": new_user, "detail": "User successfully created. Check your email for confirmation."}


@app.post("/login")
async def login(body: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Authenticate a user and generate access and refresh tokens.

    Parameters:
    - body (OAuth2PasswordRequestForm): The login form data including username (email) and password.
    - db (Session): The database session.

    Returns:
    - dict: The access and refresh tokens.
    """
    user = db.query(User).filter(User.email == body.username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email")
    if not user.confirmed:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email not confirmed")
    if not hash_handler.verify_password(body.password, user.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

    access_token = await auth_service.create_access_token(data={"sub": user.email})
    refresh_token = await auth_service.create_refresh_token(data={"sub": user.email})
    user.refresh_token = refresh_token
    db.commit()

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.get('/auth/confirmed_email/{token}')
async def confirmed_email(token: str, db_session: Session = Depends(get_db)):
    """
    Confirm a user's email address.

    Parameters:
    - token (str): The email verification token.
    - db_session (Session): The database session.

    Returns:
    - dict: A message indicating whether the email is confirmed.
    """
    email = await auth_service.get_email_from_email_token(token)
    user = db_session.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Verification error")
    if user.confirmed:
        return {"message": "Your email is already confirmed"}
    user.confirmed = True
    db_session.commit()

    return {"message": "Email confirmed"}


@app.post("/users/{user_id}/avatar")
async def upload_avatar(user_id: int, db: Session = Depends(get_db), avatar: UploadFile = File(...)):
    """
    Upload an avatar for a user.

    Parameters:
    - user_id (int): The ID of the user.
    - db (Session): The database session.
    - avatar (UploadFile): The uploaded avatar file.

    Returns:
    - dict: The avatar URL.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    upload_result = None
    if avatar:
        upload_result = cloudinary.uploader.upload(avatar.file)

    user.avatar = upload_result['url']
    db.commit()

    return {"avatar_url": upload_result['url']}


@app.put("/users/{user_id}/avatar")
async def update_avatar(user_id: int, db: Session = Depends(get_db), avatar: UploadFile = File(...)):
    """
    Update the avatar for a user.

    Parameters:
    - user_id (int): The ID of the user.
    - db (Session): The database session.
    - avatar (UploadFile): The updated avatar file.

    Returns:
    - dict: The updated avatar URL.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    upload_result = None
    if avatar:
        upload_result = cloudinary.uploader.upload(avatar.file)

    user.avatar = upload_result['url']
    db.commit()

    return {"avatar_url": upload_result['url']}


@app.get('/refresh_token')
async def refresh_token(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)):
    """
    Refresh the access token using a valid refresh token.

    Parameters:
    - credentials (HTTPAuthorizationCredentials): The bearer token credentials.
    - db (Session): The database session.

    Returns:
    - dict: The new access and refresh tokens.
    """
    token = credentials.credentials
    email = await auth_service.get_email_from_refresh_token(token)
    user = db.query(User).filter(User.email == email).first()
    if user.refresh_token != token:
        user.refresh_token = None
        db.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    access_token = await auth_service.create_access_token(data={"sub": email})
    refresh_token = await auth_service.create_refresh_token(data={"sub": email})
    user.refresh_token = refresh_token
    db.commit()

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


@app.get("/")
async def root():
    """
    Root endpoint.

    Returns:
    - dict: A greeting message.
    """
    return {"message": "Hello World"}


@app.get("/secret")
async def read_item(current_user: User = Depends(auth_service.get_current_user)):
    """
    Example protected route.

    Parameters:
    - current_user (User): The authenticated user.

    Returns:
    - dict: A secret message.
    """
    return {"message": 'secret router', "owner": current_user.email}


@app.post("/contacts/", dependencies=[Depends(RateLimiter(times=1, minutes=1))])
async def create_contact(
        contact: ContactCreate,
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_db)
):
    """
    Create a new contact for the current user.

    Parameters:
    - contact (ContactCreate): The contact data.
    - current_user (User): The authenticated user.
    - db (Session): The database session.

    Returns:
    - Contact: The created contact.
    """
    db_contact = Contact(
        first_name=contact.first_name,
        last_name=contact.last_name,
        email=contact.email,
        phone_number=contact.phone_number,
        date_of_birth=contact.date_of_birth,
        user_id=current_user.id
    )
    db.add(db_contact)
    db.commit()
    db.refresh(db_contact)

    return db_contact


@app.get("/contacts/")
async def get_contacts(
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_db)
):
    """
    Get all contacts for the current user.

    Parameters:
    - current_user (User): The authenticated user.
    - db (Session): The database session.

    Returns:
    - dict: The list of contacts.
    """
    contacts = db.query(Contact).filter(Contact.user_id == current_user.id).all()
    return {"contacts": contacts}


@app.get("/contacts/{contact_id}")
async def get_contact(
        contact_id: int,
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_db)
):
    """
    Get a specific contact for the current user.

    Parameters:
    - contact_id (int): The ID of the contact.
    - current_user (User): The authenticated user.
    - db (Session): The database session.

    Returns:
    - Contact: The requested contact.
    """
    contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact


@app.put("/contacts/{contact_id}")
async def update_contact(
        contact_id: int,
        contact: ContactUpdate,
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_db)
):
    """
    Update a specific contact for the current user.

    Parameters:
    - contact_id (int): The ID of the contact.
    - contact (ContactUpdate): The updated contact data.
    - current_user (User): The authenticated user.
    - db (Session): The database session.

    Returns:
    - Contact: The updated contact.
    """
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()
    if not db_contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    db_contact.first_name = contact.first_name
    db_contact.last_name = contact.last_name
    db_contact.email = contact.email
    db_contact.phone_number = contact.phone_number
    db_contact.date_of_birth = contact.date_of_birth

    db.commit()
    db.refresh(db_contact)

    return db_contact


@app.delete("/contacts/{contact_id}")
async def delete_contact(
        contact_id: int,
        current_user: User = Depends(auth_service.get_current_user),
        db: Session = Depends(get_db)
):
    """
    Delete a specific contact for the current user.

    Parameters:
    - contact_id (int): The ID of the contact.
    - current_user (User): The authenticated user.
    - db (Session): The database session.

    Returns:
    - dict: A message indicating the successful deletion of the contact.
    """
    db_contact = db.query(Contact).filter(Contact.id == contact_id, Contact.user_id == current_user.id).first()
    if not db_contact:
        raise HTTPException(status_code=404, detail="Contact not found")

    db.delete(db_contact)
    db.commit()

    return {"message": "Contact deleted successfully"}
