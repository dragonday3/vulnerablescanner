"""Shared contracts for port-scanning adapters (native, nmap, ...)."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class PortScanResult:
    port: int
    protocol: str
    state: str
    # Optional fingerprinting evidence populated only by adapters that
    # obtain it "for free" during discovery itself — currently only
    # NmapPortScanner, since `-sV` runs in the same subprocess call as the
    # port scan. NativePortScanner leaves these at their defaults; its own
    # (separate, later) HTTP-based enrichment operates on already-persisted
    # Service rows instead (see tasks.py), not through this dataclass.
    service_name: str | None = None
    product: str | None = None
    version: str | None = None
    extrainfo: str | None = None
    method: str | None = None
    cpe: tuple[str, ...] = ()
    raw_evidence: dict[str, object] | None = None


class PortScannerInterface(Protocol):
    def scan(self, host: str, ports: list[int], timeout_seconds: float) -> list[PortScanResult]: ...
