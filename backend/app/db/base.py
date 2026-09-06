from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


from app.models.project import Project  # noqa: F401,E402
from app.models.target import Target  # noqa: F401,E402
from app.models.scan import Scan  # noqa: F401,E402
