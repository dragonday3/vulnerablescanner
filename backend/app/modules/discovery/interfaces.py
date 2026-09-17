"""Shared contracts for port-scanning adapters (native, nmap, ...)."""

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class PortScanResult:
    port: int
    protocol: str
    state: str


class PortScannerInterface(Protocol):
    def scan(self, host: str, ports: list[int], timeout_seconds: float) -> list[PortScanResult]: ...
