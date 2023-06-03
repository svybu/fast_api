from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from jose import JWTError, jwt
from starlette import status

from database.db import get_db
from database.models import User


class Hash:
    """Class for password hashing and verification."""

    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

    def verify_password(self, plain_password, hashed_password):
        """
        Verify if the plain password matches the hashed password.

        :param plain_password: The plain text password.
        :type plain_password: str
        :param hashed_password: The hashed password.
        :type hashed_password: str
        :return: True if the passwords match, False otherwise.
        :rtype: bool
        """
        return self.pwd_context.verify(plain_password, hashed_password)

    def get_password_hash(self, password: str):
        """
        Get the hashed password for the given plain password.

        :param password: The plain text password.
        :type password: str
        :return: The hashed password.
        :rtype: str
        """
        return self.pwd_context.hash(password)


class Auth:
    """Class for authentication and JWT token handling."""

    SECRET_KEY = "secret_key"
    ALGORITHM = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES = 30
    oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

    async def create_access_token(self, data: dict, expires_delta: Optional[float] = None):
        """
        Create a new access token.

        :param data: The data to encode into the token.
        :type data: dict
        :param expires_delta: Optional expiration time in seconds.
        :type expires_delta: float
        :return: The encoded access token.
        :rtype: str
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + timedelta(seconds=expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(minutes=15)
        to_encode.update({"iat": datetime.utcnow(), "exp": expire, "scope": "access_token"})
        encoded_access_token = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return encoded_access_token

    async def create_refresh_token(self, data: dict, expires_delta: Optional[float] = None):
        """
        Create a new refresh token.

        :param data: The data to encode into the token.
        :type data: dict
        :param expires_delta: Optional expiration time in seconds.
        :type expires_delta: float
        :return: The encoded refresh token.
        :rtype: str
        """
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + timedelta(seconds=expires_delta)
        else:
            expire = datetime.utcnow() + timedelta(days=7)
        to_encode.update({"iat": datetime.utcnow(), "exp": expire, "scope": "refresh_token"})
        encoded_refresh_token = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return encoded_refresh_token

    async def get_email_from_refresh_token(self, refresh_token: str):
        """
        Get the email from a refresh token.

        :param refresh_token: The refresh token.
        :type refresh_token: str
        :return: The email associated with the refresh token.
        :rtype: str
        :raises HTTPException: If the refresh token is invalid.
        """
        try:
            payload = jwt.decode(refresh_token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload['scope'] == 'refresh_token':
                email = payload['sub']
                return email
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid scope for token')
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate credentials')

    async def get_current_user(self, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
        """
        Get the current authenticated user.

        :param token: The JWT token.
        :type token: str
        :param db: The database session.
        :type db: Session
        :return: The current authenticated user.
        :rtype: User
        :raises HTTPException: If the credentials are invalid or the user does not exist.
        """
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

        try:
            if token is None:
                raise credentials_exception
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            if payload['scope'] == 'access_token':
                email = payload["sub"]
                if email is None:
                    raise credentials_exception
            else:
                raise credentials_exception
        except JWTError as e:
            raise credentials_exception

        user: User = db.query(User).filter(User.email == email).first()
        if user is None:
            raise credentials_exception
        return user

    def create_email_token(self, data: dict):
        """
        Create a token for email verification.

        :param data: The data to encode into the token.
        :type data: dict
        :return: The encoded email verification token.
        :rtype: str
        """
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=7)
        to_encode.update({"iat": datetime.utcnow(), "exp": expire})
        token = jwt.encode(to_encode, self.SECRET_KEY, algorithm=self.ALGORITHM)
        return token

    async def get_email_from_token(self, token: str):
        """
        Get the email from a token.

        :param token: The token.
        :type token: str
        :return: The email associated with the token.
        :rtype: str
        :raises HTTPException: If the token is invalid.
        """
        try:
            payload = jwt.decode(token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            email = payload["sub"]
            return email
        except JWTError as e:
            print(e)
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                                detail="Invalid token for email verification")

    async def get_email_from_email_token(self, email_token: str):
        """
        Get the email from an email verification token.

        :param email_token: The email verification token.
        :type email_token: str
        :return: The email associated with the email verification token.
        :rtype: str
        :raises HTTPException: If the token is invalid.
        """
        try:
            payload = jwt.decode(email_token, self.SECRET_KEY, algorithms=[self.ALGORITHM])
            email = payload['sub']
            return email
        except JWTError:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Could not validate credentials')


auth_service = Auth()
