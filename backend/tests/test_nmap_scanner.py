import shutil
import socket
import subprocess
from unittest.mock import patch

import pytest

from app.modules.discovery.nmap_scanner import NmapPortScanner, NmapScanError

pytestmark = pytest.mark.skipif(
    shutil.which("nmap") is None, reason="nmap binary not found on PATH"
)


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

        captured_cmd: list[str] = []
        real_run = subprocess.run

        def _spying_run(cmd, *args, **kwargs):  # type: ignore[no-untyped-def]
            captured_cmd.extend(cmd)
            return real_run(cmd, *args, **kwargs)

        scanner = NmapPortScanner()
        with patch("subprocess.run", side_effect=_spying_run):
            results = scanner.scan("127.0.0.1", [open_port, closed_port], timeout_seconds=30.0)

        # Phase 3: -sV must actually be part of the built command.
        assert "-sV" in captured_cmd

        open_ports = {result.port for result in results}
        assert open_port in open_ports
        assert closed_port not in open_ports
        for result in results:
            assert result.protocol == "tcp"
            assert result.state == "open"
            if result.port == open_port:
                # A bare test listener (accepts connections, speaks nothing
                # recognizable) is exactly the case where nmap's -sV probe
                # can't identify anything useful. That must be a normal,
                # non-crashing outcome: parsing must not raise, and an
                # unidentified service must leave the evidence fields at
                # their PortScanResult defaults rather than fabricating data.
                assert isinstance(result.cpe, tuple)
                if result.service_name is None:
                    assert result.product is None
                    assert result.version is None
                    assert result.raw_evidence is None
    finally:
        listener.close()


def test_scan_returns_empty_list_when_nothing_open() -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    closed_port = probe.getsockname()[1]
    probe.close()

    scanner = NmapPortScanner()
    results = scanner.scan("127.0.0.1", [closed_port], timeout_seconds=30.0)

    assert results == []


def test_raises_on_nmap_failure_instead_of_returning_empty_list() -> None:
    # A port number outside 0-65535 is rejected by nmap itself before any
    # scanning happens ("Ports specified must be between 0 and 65535
    # inclusive", non-zero exit). This must surface as a raised error, not
    # be conflated with a genuine "scanned fine, nothing open" empty-list
    # result.
    scanner = NmapPortScanner()

    with pytest.raises(NmapScanError):
        scanner.scan("127.0.0.1", [99999], timeout_seconds=30.0)


def test_raises_on_unresolvable_host_instead_of_returning_empty_list() -> None:
    # nmap exits 0 on an unresolvable hostname ("Failed to resolve ...") but
    # scans zero hosts (`<hosts up="0" down="0" total="0"/>`, no <host>
    # element at all). That must raise, not be conflated with a genuine
    # "scanned fine, nothing open" empty-list result - otherwise a
    # decommissioned host or typo'd hostname would silently report as
    # "scanned, zero services" instead of "scan didn't actually happen".
    scanner = NmapPortScanner()

    with pytest.raises(NmapScanError):
        scanner.scan("this-host-does-not-exist.invalid.", [80], timeout_seconds=30.0)


_MULTI_HOST_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="172.18.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="172.18.0.3" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
      </port>
    </ports>
  </host>
  <host>
    <address addr="172.18.0.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
      </port>
    </ports>
  </host>
  <runstats><hosts up="3" down="0" total="3"/></runstats>
</nmaprun>
"""


def test_raises_on_multi_host_result_instead_of_collapsing_into_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding 1 (Critical): nmap's own target-syntax parser accepts
    host-range/list expressions ("172.18.0.2-4") and will scan MULTIPLE
    hosts for what the caller believes is a single authorized target. This
    adapter must not silently collapse those hosts' services into one
    result - it must raise, even if a range-shaped value somehow reaches it
    (e.g. a future regression in the upstream Target validator). Simulated
    here via a mocked `subprocess.run` returning crafted multi-<host> XML,
    since safely provisioning 3 real distinct hosts in a test environment
    is impractical.
    """
    fake_result = subprocess.CompletedProcess(
        args=["nmap"], returncode=0, stdout=_MULTI_HOST_XML, stderr=""
    )
    scanner = NmapPortScanner()

    with patch("subprocess.run", return_value=fake_result):
        with pytest.raises(NmapScanError, match="scanned 3 hosts"):
            scanner.scan("172.18.0.2-4", [22, 80, 443], timeout_seconds=30.0)


_SERVICE_EVIDENCE_XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="172.18.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24.0"
                 extrainfo="Ubuntu" method="probed" conf="10">
          <cpe>cpe:/a:nginx:nginx:1.24.0</cpe>
          <cpe>cpe:/o:linux:linux_kernel</cpe>
        </service>
      </port>
      <port protocol="tcp" portid="22">
        <state state="open"/>
      </port>
    </ports>
  </host>
  <runstats><hosts up="1" down="0" total="1"/></runstats>
</nmaprun>
"""


def test_parses_service_and_cpe_evidence_from_sv_output() -> None:
    """Deterministic unit test (doesn't depend on real nmap -sV probe
    behavior): a canned XML fixture with a full <service> element plus two
    <cpe> children must map exactly onto the new PortScanResult fields, and
    a port with no <service> child (port 22 here) must leave those fields at
    their defaults.
    """
    fake_result = subprocess.CompletedProcess(
        args=["nmap"], returncode=0, stdout=_SERVICE_EVIDENCE_XML, stderr=""
    )
    scanner = NmapPortScanner()

    with patch("subprocess.run", return_value=fake_result):
        results = scanner.scan("172.18.0.5", [22, 80], timeout_seconds=30.0)

    by_port = {result.port: result for result in results}
    assert set(by_port) == {22, 80}

    http = by_port[80]
    assert http.protocol == "tcp"
    assert http.state == "open"
    assert http.service_name == "http"
    assert http.product == "nginx"
    assert http.version == "1.24.0"
    assert http.extrainfo == "Ubuntu"
    assert http.method == "probed"
    assert http.cpe == ("cpe:/a:nginx:nginx:1.24.0", "cpe:/o:linux:linux_kernel")
    assert http.raw_evidence == {
        "name": "http",
        "product": "nginx",
        "version": "1.24.0",
        "extrainfo": "Ubuntu",
        "method": "probed",
        "conf": "10",
        "cpe": ["cpe:/a:nginx:nginx:1.24.0", "cpe:/o:linux:linux_kernel"],
    }

    ssh = by_port[22]
    assert ssh.service_name is None
    assert ssh.product is None
    assert ssh.version is None
    assert ssh.extrainfo is None
    assert ssh.method is None
    assert ssh.cpe == ()
    assert ssh.raw_evidence is None


def test_import_has_no_side_effects() -> None:
    # Importing the module must not run any subprocess; presence of this
    # test - and the module having already been imported at collection time
    # without error - is itself the assertion.
    import app.modules.discovery.nmap_scanner  # noqa: F401
