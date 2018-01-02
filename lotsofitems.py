from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item


# Connect to Database and create database session
engine = create_engine('sqlite:///itemcatalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

category1 = Category(name="Hockey",description="Items needed to play hockey")
session.add(category1)



session.commit()