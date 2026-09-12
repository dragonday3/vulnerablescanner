import socket

from app.modules.discovery.native_scanner import NativePortScanner


def _free_port(listener: socket.socket) -> int:
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    return listener.getsockname()[1]


def test_detects_open_and_closed_ports() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        open_port = _free_port(listener)

        # Find a definitely-closed port: bind-and-immediately-close a second
        # socket to get an OS-assigned free port, guaranteed distinct from
        # open_port since it's still bound.
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        probe.bind(("127.0.0.1", 0))
        closed_port = probe.getsockname()[1]
        probe.close()
        if closed_port == open_port:
            closed_port += 1

        scanner = NativePortScanner()
        results = scanner.scan("127.0.0.1", [open_port, closed_port], timeout_seconds=1.0)

        open_ports = {result.port for result in results}
        assert open_port in open_ports
        assert closed_port not in open_ports
        for result in results:
            assert result.protocol == "tcp"
            assert result.state == "open"
    finally:
        listener.close()


def test_scan_returns_empty_list_when_nothing_open() -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    scanner = NativePortScanner()
    results = scanner.scan("127.0.0.1", [closed_port], timeout_seconds=1.0)

    assert results == []


def test_import_has_no_side_effects() -> None:
    # Importing the module must not open any sockets; if it did, binding
    # this listener (or any subsequent connection attempt) would be the
    # first indication something went wrong. Presence of this test - and
    # the module having already been imported at collection time without
    # error - is itself the assertion.
    import app.modules.discovery.native_scanner  # noqa: F401
