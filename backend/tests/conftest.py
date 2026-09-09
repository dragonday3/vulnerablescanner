"""Shared pytest fixtures for the API test suite.

Test database strategy
-----------------------
Tests run against a real Postgres database rather than mocks or SQLite,
because the models rely on Postgres-specific features (JSONB, native enum
types) that SQLite can't reproduce, and we want the suite to catch real
constraint/SQL issues.

* A second database, ``vulnsight_test``, is used on the *same* Postgres
  server as local dev (see ``docker-compose.yml`` / ``.env.example`` — one
  ``postgres`` service, two databases) so tests never touch dev data. The
  connection string is ``TEST_DATABASE_URL`` (env var), defaulting to the
  same host/credentials as the documented dev ``DATABASE_URL`` with the
  database name swapped to ``vulnsight_test``.
* That database is created automatically if missing (``CREATE DATABASE``
  issued against the ``postgres`` maintenance database over an autocommit
  connection), and its schema is built once per test session via
  ``Base.metadata.create_all`` — no Alembic migration run is required for
  tests, keeping this file self-contained.
* Each test function gets its own SQLAlchemy ``Session`` bound to a
  connection that has an outer transaction plus a SAVEPOINT
  (``join_transaction_mode="create_savepoint"``). Service-layer code is
  free to call ``session.commit()`` as it normally does; a commit only
  releases and reopens the SAVEPOINT. The outer transaction is rolled back
  once the test finishes, so no data written by a test is ever persisted -
  each test is fully isolated from the others.
"""

import os
from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, Engine, make_url
from sqlalchemy.orm import Session

# Must be set before any `app.*` import below, since app.core.config.Settings
# (instantiated at app.main import time) requires DATABASE_URL from the
# environment / .env file.
_DATABASE_URL = os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://vulnsight:vulnsight@localhost:5432/vulnsight"
)
# Default TEST_DATABASE_URL to the same host/credentials as DATABASE_URL (just
# swapping the database name), rather than hardcoding "localhost". Inside the
# backend container, Postgres is reachable at the Compose service name
# ("postgres"), not "localhost" — deriving from DATABASE_URL keeps this
# correct both there and for local (non-Docker) test runs.
TEST_DATABASE_URL = os.environ.setdefault(
    "TEST_DATABASE_URL",
    # render_as_string(hide_password=False): plain str(URL) masks the
    # password as "***", which would make the derived URL unusable.
    make_url(_DATABASE_URL).set(database="vulnsight_test").render_as_string(hide_password=False),
)

from app.db.base_class import Base  # noqa: E402
from app.db.session import get_db  # noqa: E402

# Importing app.main (rather than a service/model module directly) guarantees
# app.db.base has already run and registered every model on Base, so
# relationship() string references like Mapped["Target"] resolve correctly.
from app.main import app  # noqa: E402

test_engine: Engine = create_engine(TEST_DATABASE_URL)


def _ensure_database_exists(url: str) -> None:
    """Create the target Postgres database on the server if missing."""
    target = make_url(url)
    admin_url: URL = target.set(database="postgres")
    admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        with admin_engine.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": target.database},
            ).scalar()
            if not exists:
                conn.execute(text(f'CREATE DATABASE "{target.database}"'))
    finally:
        admin_engine.dispose()


@pytest.fixture(scope="session", autouse=True)
def _test_database() -> Generator[None, None, None]:
    _ensure_database_exists(TEST_DATABASE_URL)
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()


@pytest.fixture()
def db() -> Generator[Session, None, None]:
    connection = test_engine.connect()
    trans = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        trans.rollback()
        connection.close()


@pytest.fixture()
def client(db: Session) -> Generator[TestClient, None, None]:
    def _override_get_db() -> Generator[Session, None, None]:
        yield db

    app.dependency_overrides[get_db] = _override_get_db
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.pop(get_db, None)
