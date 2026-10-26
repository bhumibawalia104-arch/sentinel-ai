"""SQLite connection (SQLAlchemy). The database file is created automatically."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app import config

# check_same_thread=False lets FastAPI use the connection from its worker threads
engine = create_engine(config.DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


class Base(DeclarativeBase):
    pass


def init_db():
    from app import models  # noqa: F401  (importing registers the tables)
    Base.metadata.create_all(bind=engine)


def get_db():
    """FastAPI dependency: gives each request its own session and closes it afterwards."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
