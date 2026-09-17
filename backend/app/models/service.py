import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base

if TYPE_CHECKING:
    from app.models.asset import Asset


class Service(Base):
    __tablename__ = "services"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True, nullable=False
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(10), nullable=False, default="tcp")
    state: Mapped[str] = mapped_column(String(20), nullable=False, default="open")
    service_name: Mapped[str | None] = mapped_column(String(50), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    # --- Phase 3 additions ---
    # Structured, commonly-queried evidence fields. Populated from either
    # nmap's `-sV` <service> element or the HTTP prober's parsed `Server`
    # header — whichever adapter/pass produced them. `extrainfo` uses Text
    # (not String) because nmap's extrainfo field is free-text and can run
    # well past a short varchar (e.g. "Ubuntu Linux; protocol 2.0").
    product: Mapped[str | None] = mapped_column(String(255), nullable=True)
    version: Mapped[str | None] = mapped_column(String(100), nullable=True)
    extrainfo: Mapped[str | None] = mapped_column(Text, nullable=True)
    # "nmap-sv" | "http" | None this phase ("port-guess" reserved, see
    # this doc's scope-limits note — not written by any Phase 3 code path).
    fingerprint_source: Mapped[str | None] = mapped_column(String(20), nullable=True)
    # Raw evidence, verbatim: nmap's full <service> attribute set + <cpe>
    # list, or the HTTP prober's status/headers/title. Always the source of
    # truth even when product/version above are only a best-effort parse of
    # part of it (e.g. splitting a `Server` header) — never lossy.
    evidence: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    asset: Mapped["Asset"] = relationship(back_populates="services")
