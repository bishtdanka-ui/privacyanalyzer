import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.main import app
from backend.database import Base, get_db
from backend.models.user import User
from backend.security.hashing import hash_password
from backend.security.jwt_auth import create_access_token

# Use an in-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def db_session():
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(db_session):
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

@pytest.fixture
def normal_user(db_session):
    user = User(
        email="analyst@example.com",
        username="analyst_bob",
        full_name="Bob Analyst",
        hashed_password=hash_password("AnalystPassword123!"),
        role="user",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture
def admin_user(db_session):
    user = User(
        email="superadmin@example.com",
        username="superadmin",
        full_name="Super Admin",
        hashed_password=hash_password("AdminSecurePassword123!"),
        role="admin",
        is_active=True
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user

@pytest.fixture
def user_auth_headers(normal_user):
    token = create_access_token(data={"sub": str(normal_user.id), "role": normal_user.role, "username": normal_user.username})
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def admin_auth_headers(admin_user):
    token = create_access_token(data={"sub": str(admin_user.id), "role": admin_user.role, "username": admin_user.username})
    return {"Authorization": f"Bearer {token}"}
