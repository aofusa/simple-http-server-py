from fastapi import FastAPI, Response, Cookie, status
from typing import Annotated
from pydantic import BaseModel
from enum import Enum
from datetime import datetime, timedelta
from hashlib import pbkdf2_hmac
from logging import getLogger, StreamHandler


app = FastAPI()


logger = getLogger("uvicorn.app")
# logger = getLogger(__name__)
# logger.addHandler(StreamHandler())
# logger.setLevel("INFO")


""" Entity ################################
"""
class User(BaseModel):
    username: str
    password: str


class LoginUser(BaseModel):
    # username: str
    hashed_password: bytes  # pbkdf2_hmac('sha512', b'<password>', b'123456789', 310000)


class Session(BaseModel):
    # id: str
    # username: str
    expired: datetime


""" Emulation Database ################################
"""
login_users = {"user": LoginUser(hashed_password=b'*\x15\xf2\xfam\xa6"\x12s\x13\x1e\xa7\x97oLf\x10\x00E\x8e\xd1\xae\x9eu=s\xcd)\x1a=\xd4\xaf\x9a\t\xef\x99\xe6]\xee\xc1\x87\xd9\x06\x02\x8a\xf6\xd8\xb0\xee{\x05\xcb\xbc.1\xc2\x96\x99r\xe0\x12L\xb4\x0e')}  # user: user
session_storage = {}


""" HealthCheck ################################
"""
class HealthCheckMessage(str, Enum):
    SUCCESS = "Hello World"


class HealthCheckResponse(BaseModel):
    message: HealthCheckMessage = HealthCheckMessage.SUCCESS


@app.get("/health-check", response_model=HealthCheckResponse)
async def health_check():
    logger.info("health check log")
    return HealthCheckResponse(message=HealthCheckMessage.SUCCESS)


""" Login ################################
"""
class LoginMessage(str, Enum):
    NOT_FOUND = "user not found"
    INCORRECT_PASSWORD = "incorrect password"
    SUCCESS = "ok"


class LoginResponse(BaseModel):
    message: LoginMessage = LoginMessage.SUCCESS


@app.post("/login", response_model=LoginResponse)
async def login(user: User, response: Response):
    username = user.username
    password = user.password
    hashed_password = pbkdf2_hmac('sha512', password.encode(), b'123456789', 310000)
    session_id = pbkdf2_hmac('sha512', username.encode(), b'123456789', 310000).hex()
    expired_time = datetime.now() + timedelta(minutes=5)

    if (username not in login_users):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        logger.info(f"user not found. username: {username}")
        return LoginResponse(message=LoginMessage.NOT_FOUND)

    if (hashed_password != login_users[username].hashed_password):
        response.status_code = status.HTTP_401_UNAUTHORIZED
        logger.info(f"incorrect password. username: {username}")
        return LoginResponse(message=LoginMessage.INCORRECT_PASSWORD)

    session_storage[session_id] = Session(expired=expired_time)
    response.headers["Set-Cookie"] = f"session={session_id}; Max-Age=300; Path=/; SameSite=lax"
    # response.set_cookie(key="session", value=session_id, max_age=300)

    logger.info(f"login new session. username: {username}, session-id: {session_id}, expired: {expired_time}")
    return LoginResponse(message=LoginMessage.SUCCESS)


""" Logout ################################
"""
class LogoutMessage(str, Enum):
    SUCCESS = "ok"


class LogoutResponse(BaseModel):
    message: LogoutMessage = LogoutMessage.SUCCESS


@app.post("/logout", response_model=LogoutResponse)
async def logout(session: Annotated[str | None, Cookie()] = None):
    if (session in session_storage):
        del session_storage[session]

    logger.info(f"logout session id: {session}")
    return LogoutResponse(message=LogoutMessage.SUCCESS)


""" Protected ################################
"""
class ProtectedMessage(str, Enum):
    NOT_FOUND = "session not found"
    TIME_OUT = "session timed out"
    SUCCESS = "ok"


class ProtectedResponse(BaseModel):
    message: ProtectedMessage = ProtectedMessage.SUCCESS


@app.get("/protected", response_model=ProtectedResponse)
async def protected(response: Response, session: Annotated[str | None, Cookie()] = None):
    access_time = datetime.now()

    if (session not in session_storage):
        response.status_code = status.HTTP_403_FORBIDDEN
        logger.info(f"session not found. session id: {session}")
        return ProtectedResponse(message=ProtectedMessage.NOT_FOUND)

    if (access_time > session_storage[session].expired):
        response.status_code = status.HTTP_403_FORBIDDEN
        logger.info(f"session timed out. session id: {session}, access time: {access_time}, expired time: {session_storage[session].expired}")
        return ProtectedResponse(message=ProtectedMessage.TIME_OUT)

    return ProtectedResponse(message=ProtectedMessage.SUCCESS)

