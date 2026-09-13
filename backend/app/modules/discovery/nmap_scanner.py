"""nmap-backed TCP-connect port scanner adapter (requires the `nmap` binary).

Unlike `NativePortScanner`, this adapter shells out to the real `nmap`
binary. Task 1 guarantees that by the time a `Target` row exists, its
`.value` is already validated against its declared `target_type` and is
free of shell metacharacters/control characters/whitespace, so this module
does not re-validate the host string's shape. As defense-in-depth it still
never uses `shell=True` and never builds the command via string
formatting/concatenation of `host` into a shell string - the command is
always passed to `subprocess.run` as a list.
"""

import subprocess
import xml.etree.ElementTree as ET

from app.modules.discovery.interfaces import PortScanResult

DEFAULT_TOP_PORTS = 1000


class NmapScanError(RuntimeError):
    """Raised when nmap fails to run or its output can't be parsed.

    Distinguishes a real failure (non-zero exit, unparseable XML) from a
    genuine "scanned successfully, found nothing open" result, which is
    returned as an empty list instead.
    """


class NmapPortScanner:
    """`PortScannerInterface` adapter that shells out to the `nmap` binary."""

    def scan(self, host: str, ports: list[int], timeout_seconds: float) -> list[PortScanResult]:
        if ports:
            port_args = ["-p", ",".join(str(port) for port in ports)]
        else:
            port_args = ["--top-ports", str(DEFAULT_TOP_PORTS)]

        # List-form argv only - never shell=True, never a string-interpolated
        # command - so `host` can never be interpreted as shell syntax even
        # though Task 1 already guarantees its shape.
        cmd = ["nmap", "-sT", *port_args, "-oX", "-", host]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise NmapScanError(
                f"nmap timed out after {timeout_seconds}s scanning {host!r}: "
                f"stdout={exc.stdout!r} stderr={exc.stderr!r}"
            ) from exc
        except OSError as exc:
            raise NmapScanError(f"failed to execute nmap scanning {host!r}: {exc}") from exc

        if result.returncode != 0:
            raise NmapScanError(
                f"nmap exited with status {result.returncode} scanning {host!r}: "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            )

        try:
            root = ET.fromstring(result.stdout)
        except ET.ParseError as exc:
            raise NmapScanError(
                f"failed to parse nmap XML output for {host!r}: {exc}; "
                f"stdout={result.stdout!r} stderr={result.stderr!r}"
            ) from exc

        scan_results: list[PortScanResult] = []
        for port_el in root.iter("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = port_el.get("portid")
            protocol = port_el.get("protocol")
            if portid is None or protocol is None:
                continue
            scan_results.append(PortScanResult(port=int(portid), protocol=protocol, state="open"))

        return scan_results
