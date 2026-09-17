import ipaddress
import re
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from app.models.target import TargetType

# Conservative hostname/domain pattern per RFC 1035/1123: dot-separated labels
# of letters, digits, and hyphens, no leading/trailing hyphen per label.
_HOSTNAME_LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_HOSTNAME_LABEL}(\.{_HOSTNAME_LABEL})*$")
# NOTE: re.fullmatch (used below) makes the "$" here redundant against
# trailing-newline bypasses on its own merits; kept for readability.

# Shell metacharacters and other characters that must never appear in a value
# that may eventually reach a subprocess argument list (see Task 4's
# NmapPortScanner). Checked outright, before any format-specific parsing.
_FORBIDDEN_CHARS_RE = re.compile(r"[;|&`$<>'\"\s\x00-\x1f\x7f]")

# A value made up solely of digits, dots, and hyphens is exactly the shape of
# an nmap-syntax octet range/list ("172.18.0.2-4", "1-254",
# "10.0.0.1-10.0.0.5") even though `_HOSTNAME_RE` above accepts it as a
# syntactically valid hostname label sequence. Any such value that isn't a
# plain, single, parseable IP address must be rejected for hostname/domain
# targets - otherwise it sails past the CIDR-only range check in
# app.workers.tasks and reaches nmap, whose own target-syntax parser expands
# the range into multiple hosts from what the system believes is one
# authorized target. Genuine hostnames contain at least one letter and are
# unaffected; the intentionally-supported IP-shaped-hostname case (e.g.
# "192.168.1.1" submitted with target_type=hostname) still passes because it
# *does* parse as a plain IP address.
_DIGITS_DOTS_HYPHENS_RE = re.compile(r"^[0-9.\-]+$")


class TargetBase(BaseModel):
    # target_type is declared before value so that, in subclasses adding a
    # field_validator on "value", ValidationInfo.data already has target_type
    # populated (pydantic v2 validates fields in declaration order).
    target_type: TargetType
    value: str = Field(min_length=1, max_length=255)
    authorization_note: str | None = None


class TargetCreate(TargetBase):
    authorization_confirmed: bool

    @field_validator("value")
    @classmethod
    def validate_value_format(cls, value: str, info: ValidationInfo) -> str:
        if _FORBIDDEN_CHARS_RE.search(value):
            raise ValueError(
                "Target value must not contain whitespace, shell metacharacters "
                "(; | & ` $ < > quotes), or control characters"
            )

        target_type = info.data.get("target_type")

        if target_type in (TargetType.IP, TargetType.CIDR):
            # Python's ipaddress module implements RFC 4007 IPv6 zone IDs
            # ("fe80::1%eth0"), and accepts almost any character after the
            # "%" (only "%" and "/" are excluded) up to the length cap -
            # including Unicode. Scan targets have no legitimate use for a
            # zone ID (that addresses a local interface, not a remote
            # target), and such a suffix is exactly the kind of
            # near-unrestricted text that must never reach Task 4's Nmap
            # subprocess call unexamined. Reject it outright rather than
            # trying to validate the zone-ID content itself.
            if "%" in value:
                raise ValueError(f"'{value}' must not contain an IPv6 zone ID ('%...' suffix)")

        if target_type == TargetType.IP:
            try:
                ipaddress.ip_address(value)
            except ValueError as exc:
                raise ValueError(f"'{value}' is not a valid IP address") from exc
        elif target_type == TargetType.CIDR:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError as exc:
                raise ValueError(f"'{value}' is not a valid CIDR network") from exc
        elif target_type in (TargetType.DOMAIN, TargetType.HOSTNAME):
            if len(value) > 253 or not _HOSTNAME_RE.fullmatch(value):
                raise ValueError(f"'{value}' is not a valid hostname/domain")
            if _DIGITS_DOTS_HYPHENS_RE.match(value):
                try:
                    ipaddress.ip_address(value)
                except ValueError as exc:
                    raise ValueError(
                        f"'{value}' looks like an nmap host-range/list expression "
                        "(digits, dots, and hyphens only) rather than a plain "
                        "hostname or IP address; range/list scan targets are not "
                        "supported"
                    ) from exc

        return value

    @field_validator("authorization_confirmed")
    @classmethod
    def must_be_confirmed(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError("Target must be confirmed as authorized before it can be added")
        return value


class TargetRead(TargetBase):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    project_id: uuid.UUID
    authorization_confirmed: bool
    created_at: datetime
