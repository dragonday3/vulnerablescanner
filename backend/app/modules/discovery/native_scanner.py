"""Pure-Python TCP-connect port scanner (no external binary required)."""

import asyncio

from app.modules.discovery.interfaces import PortScanResult

DEFAULT_MAX_CONCURRENCY = 50


class NativePortScanner:
    """`PortScannerInterface` adapter using asyncio TCP-connect probes."""

    def __init__(self, max_concurrency: int = DEFAULT_MAX_CONCURRENCY) -> None:
        self._max_concurrency = max_concurrency

    def scan(self, host: str, ports: list[int], timeout_seconds: float) -> list[PortScanResult]:
        return asyncio.run(self._scan_async(host, ports, timeout_seconds))

    async def _scan_async(
        self, host: str, ports: list[int], timeout_seconds: float
    ) -> list[PortScanResult]:
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
