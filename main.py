
from datetime import datetime
from fastapi import FastAPI
from typing import Optional
from pydantic import BaseModel
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy import func
from sqlalchemy.orm import declarative_base
from sqlalchemy import desc
from fastapi.templating import Jinja2Templates


import sqlalchemy as db
from sqlalchemy.sql.schema import Column
from sqlalchemy.sql.sqltypes import Date, Integer, String

engine = db.create_engine('sqlite:///example.db')
connection = engine.connect()
metadata = db.MetaData()
session = scoped_session(sessionmaker(bind=engine))

Base = declarative_base()
templates = Jinja2Templates(directory="templates")

class EmpAlchemy(Base):
    __tablename__ = 'emp'
    id = Column(Integer, primary_key=True)
    name = Column(String)
    age = Column(Integer, default=18)
    sex = Column(String, default=True)
    date = Column(Date, default=datetime.now())


class CarAlchemy(Base):
    __tablename__ = 'cars'
    id = Column(Integer, primary_key=True)
    name = Column(String)

metadata.create_all(engine, tables=[EmpAlchemy.__table__,CarAlchemy.__table__,])


class Emp(BaseModel):
    name: str
    age: str
    sex: str

class Car(BaseModel):
    name:str

"""
*************************************
"""

from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel


fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        "hashed_password": "fakehashedsecret",
        "disabled": False,
    },
    "alice": {
        "username": "alice",
        "full_name": "Alice Wonderson",
        "email": "alice@example.com",
        "hashed_password": "fakehashedsecret2",
        "disabled": True,
    },
}

app = FastAPI()

def fake_hash_password(password: str):
	return "fakehashed" + password

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

class User(BaseModel):
	username: str
	email: Optional[str] = None
	full_name: Optional[str] = None
	disabled: Optional[bool] = None
    
class UserInDB(User):
	hashed_password: str

def get_user(db, username: str):
	if username in db:
		user_dict = db[username]
		return UserInDB(**user_dict)

def fake_decode_token(token):
	user = get_user(fake_users_db, token)
	return user

async def get_current_user(token: str = Depends(oauth2_scheme)):
	user = fake_decode_token(token)
	if not user:
		raise HTTPException(status_code = status.HTTP_401_UNAUTHORIZED, detail = "Invalid authentication credentials",
			headers = {"WWW-Authenticate":"Bearer"},
		)
	return user
async def get_current_active_user(current_user: User = Depends(get_current_user)):
	if current_user.disabled:
		raise HTTPException(status_code=400,detail="It is not allowed")
	return current_user

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
	user_dict = fake_users_db.get(form_data.username)
	if not user_dict:
		raise HTTPException(status_code=400, detail = "Incorrect username or password")
	user = UserInDB(**user_dict)
	hashed_password = fake_hash_password(form_data.password)
	if not hashed_password == user.hashed_password:
		raise HTTPException(status_code = 400,detail = '"Incorrect username or password')
	return {"access_token": user.username, "token_type":"bearer"}

# @app.get("/users/me")
# async def read_users_me(current_user: User = Depends(get_current_active_user)):
# 	return current_user

# @app.get("/items/")
# async def read_items(token: str = Depends(oauth2_scheme)):
# 	return {"token" : token}

"""
**********************************
"""

@app.get("/")
async def root(last_id: Optional[int] = 1,token: str = Depends(oauth2_scheme)):
    if token == 'johndoe':
        if last_id < 1:
            last_id = 1
        result = session.query(EmpAlchemy).filter(
            EmpAlchemy.id > last_id
        ).order_by(desc(EmpAlchemy.id)).all()
        count = session.query(func.count(EmpAlchemy.id)).scalar()
        res = {}
        res["count"] = count
        res["result"] = result
        return res
    else:
        raise HTTPException(status_code = 400,detail = 'Invalid user')


@app.post("/")
async def create_item(emp: Emp,token: str = Depends(oauth2_scheme)):
    if token !="":
        empdict = emp.__dict__
        em = EmpAlchemy(name=empdict["name"], age=int(
            empdict["age"]), sex=empdict["sex"])
        session.add(em)
        session.commit()
        result = session.query(EmpAlchemy).all()
        print(result)
        return emp
    else:
        raise HTTPException(status_code = 400,detail = 'Invalid user')
     

@app.get("/cars")
async def get_cars(token: str = Depends(oauth2_scheme)):
    if token != '':
        result = session.query(CarAlchemy).all()
        return result
    else:
        raise HTTPException(status_code = 400,detail = 'Invalid user')
     

@app.post("/cars")
async def create_car(car:Car,token: str = Depends(oauth2_scheme)):
    if token == "johndoe":
        cardict = car.__dict__
        cr = CarAlchemy(name=cardict["name"])
        session.add(cr)
        session.commit()
        result = session.query(CarAlchemy).all()
        print(result)
        return car
    else:
        raise HTTPException(status_code = 400,detail = 'Invalid user')