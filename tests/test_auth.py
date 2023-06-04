import asyncio
from unittest.mock import MagicMock
import pytest
import redis
from fastapi import FastAPI
from fastapi_limiter import FastAPILimiter
import pytest_asyncio
from database.models import User
from conftest import startup
import aioredis

from main import hash_handler
from services.auth import Hash

app = FastAPI()



def test_create_user(client, user, monkeypatch):
    mock_send_email = MagicMock()
    monkeypatch.setattr("services.email.send_email", mock_send_email)

    response = client.post(
        "/signup",
        json=user,
    )
    assert response.status_code == 201, response.text
    data = response.json()
    assert data["user"]["email"] == user.get("email")
    assert "id" in data["user"]




def test_repeat_create_user(client, user):
    response = client.post(
        "/signup",
        json=user,
    )
    assert response.status_code == 409, response.text
    data = response.json()
    assert data["detail"] == "Account already exists"





def test_login(client, session, user):
    # Create the user
    test_user = User(email=user.get('email'), password=Hash.pwd_context.hash(user.get('password')), confirmed=False)
    session.add(test_user)
    session.commit()

    # Now the user exists in the DB, let's try to authenticate
    current_user: User = session.query(User).filter(User.email == user.get('email')).first()
    if current_user is None:
        pytest.fail("User not found in the database")

    # Confirm the user
    current_user.confirmed = True
    session.commit()

    # Now test the login
    response = client.post(
        "/login",
        data={"username": user.get('email'), "password": user.get('password')},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["token_type"] == "bearer"




def test_login_wrong_password(client, user):
    response = client.post(
        "/login",
        data={"username": user.get('email'), "password": 'password'},
    )
    assert response.status_code == 401, response.text
    data = response.json()
    assert data["detail"] == "Invalid password"


def test_login_wrong_email(client, user):
    response = client.post(
        "/login",
        data={"username": 'email', "password": user.get('password')},
    )
    assert response.status_code == 401, response.text
    data = response.json()
    assert data["detail"] == "Invalid email"



if __name__ == '__main__':
    asyncio.run(startup())
    pytest.main()
