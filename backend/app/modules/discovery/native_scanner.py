"""Pure-Python TCP-connect port scanner (no external binary required)."""

import asyncio
import socket

from app.modules.discovery.interfaces import PortScanResult

DEFAULT_MAX_CONCURRENCY = 50


class NativeScanError(RuntimeError):
    """Raised when the target host can't even be resolved, so no port probe
    was ever actually attempted.

    Mirrors `NmapPortScanner`'s `NmapScanError` "never actually scanned"
    semantics: `asyncio.open_connection`'s per-port DNS resolution failure
    was previously swallowed by the blanket `except Exception` in `_probe`,
    making an unresolvable host indistinguishable from "resolved fine,
    every port closed" (an empty list). Resolving once up front and raising
    here keeps that distinction for the native adapter too.
    """


class NativePortScanner:
    """`PortScannerInterface` adapter using asyncio TCP-connect probes."""

    def __init__(self, max_concurrency: int = DEFAULT_MAX_CONCURRENCY) -> None:
        self._max_concurrency = max_concurrency

    def scan(self, host: str, ports: list[int], timeout_seconds: float) -> list[PortScanResult]:
        return asyncio.run(self._scan_async(host, ports, timeout_seconds))

    async def _scan_async(
        self, host: str, ports: list[int], timeout_seconds: float
    ) -> list[PortScanResult]:
        try:
            await asyncio.get_running_loop().getaddrinfo(host, None)
        except socket.gaierror as exc:
            raise NativeScanError(f"failed to resolve host {host!r}: {exc}") from exc

        semaphore = asyncio.Semaphore(self._max_concurrency)
        results = await asyncio.gather(
            *(self._probe(host, port, timeout_seconds, semaphore) for port in ports)
        )
        return [result for result in results if result is not None]

    async def _probe(
        self, host: str, port: int, timeout_seconds: float, semaphore: asyncio.Semaphore
    ) -> PortScanResult | None:
        async with semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout_seconds
                )
            except Exception:
                return None
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return PortScanResult(port=port, protocol="tcp", state="open")
