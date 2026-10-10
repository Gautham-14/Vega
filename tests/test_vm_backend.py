"""Host/guest boundary regressions, without a VM download or a live model."""

import datetime
import hashlib
import http.client
import io
import json
import socket
import ssl
import struct
import threading
from pathlib import Path
from unittest.mock import Mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from aegis.version import __version__
from aegis.vm import guest, host, policy, protocol


@pytest.fixture
def vm_inventory(tmp_path):
    tls = tmp_path / "tls"
    tls.mkdir()
    now = datetime.datetime.now(datetime.UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Aegis test CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    (tls / "ca-cert.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    for name, usage in (
        ("server", ExtendedKeyUsageOID.SERVER_AUTH),
        ("client", ExtendedKeyUsageOID.CLIENT_AUTH),
    ):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "localhost" if name == "server" else "operator"
                        )
                    ]
                )
            )
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
        )
        if name == "server":
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
            )
        certificate = builder.sign(ca_key, hashes.SHA256())
        (tls / f"{name}-cert.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
        (tls / f"{name}-key.pem").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    for name in ("qemu", "root.raw", "state.raw"):
        (tmp_path / name).write_bytes(b"offline test inventory " + name.encode())
    firmware = tmp_path / "firmware"
    firmware.mkdir()
    (firmware / "bios.bin").write_bytes(b"reviewed test firmware")
    value = {
        "schema": 1,
        "qemu": str(tmp_path / "qemu"),
        "qemu_sha256": policy.digest(tmp_path / "qemu"),
        "root_image": str(tmp_path / "root.raw"),
        "root_sha256": policy.digest(tmp_path / "root.raw"),
        "state_image": str(tmp_path / "state.raw"),
        "tls_directory": str(tls),
        "server_certificate_sha256": hashlib.sha256(
            ssl.PEM_cert_to_DER_cert((tls / "server-cert.pem").read_text())
        ).hexdigest(),
        "api_port": 18765,
        "channel_port": 18766,
        "cpus": 2,
        "memory_mib": 4096,
        "accelerator": "tcg",
        "firmware_directory": str(firmware),
        "firmware_sha256": policy.firmware_digest(firmware),
    }
    path = tmp_path / "vm.json"
    path.write_text(json.dumps(value), encoding="utf-8")
    return path, value


def test_policy_and_fixed_command(vm_inventory, monkeypatch):
    path, _ = vm_inventory
    settings = policy.load(path)
    argv = policy.command(settings)
    assert argv[argv.index("-nic") + 1] == "none"
    assert argv[argv.index("-display") + 1] == "none"
    assert not any(item in argv for item in ("-netdev", "-virtfs", "-fsdev", "-usb", "-vnc"))
    disks = [json.loads(argv[index + 1]) for index, item in enumerate(argv) if item == "-blockdev"]
    assert disks[0]["read-only"] is True and disks[1]["read-only"] is False
    assert all(item["driver"] == "raw" for item in disks)
    assert json.loads(argv[argv.index("-object") + 1])["verify-peer"] is True
    monkeypatch.setenv("AEGIS_SECRET", "do-not-pass")
    monkeypatch.setenv("LD_PRELOAD", "do-not-load")
    monkeypatch.setenv("SSLKEYLOGFILE", "do-not-log")
    assert "AEGIS_SECRET" not in host.child_environment(settings)
    assert "LD_PRELOAD" not in host.child_environment(settings)
    assert policy.context(settings).keylog_filename is None


@pytest.mark.parametrize(
    "field,value",
    [
        ("qemu_sha256", "0" * 64),
        ("root_sha256", "f" * 64),
        ("firmware_sha256", "f" * 64),
        ("server_certificate_sha256", "f" * 64),
        ("api_port", 80),
        ("api_port", 18766),
        ("cpus", True),
        ("memory_mib", 1),
        ("accelerator", "auto"),
        ("accelerator", []),
        ("extra_args", ["-nic", "user"]),
        ("root_image", "relative.raw"),
    ],
)
def test_policy_rejects_unsafe_inventory(vm_inventory, field, value):
    path, settings = vm_inventory
    settings[field] = value
    path.write_text(json.dumps(settings), encoding="utf-8")
    with pytest.raises(ValueError):
        policy.load(path)


@pytest.mark.parametrize(
    "platform,accelerator", [("win32", "whpx"), ("darwin", "hvf"), ("linux", "kvm")]
)
def test_accelerator_selection(vm_inventory, monkeypatch, platform, accelerator):
    path, settings = vm_inventory
    monkeypatch.setattr(policy.sys, "platform", platform)
    monkeypatch.setattr(policy.platform, "machine", lambda: "x86_64")
    settings["accelerator"] = accelerator
    path.write_text(json.dumps(settings), encoding="utf-8")
    assert policy.load(path)["accelerator"] == accelerator
    monkeypatch.setattr(policy.platform, "machine", lambda: "arm64")
    with pytest.raises(ValueError, match="TCG"):
        policy.load(path)


def test_framing_round_trip_and_partial_writes():
    class Partial(io.BytesIO):
        def write(self, value):
            return super().write(value[:3])

    stream = Partial()
    protocol.send(stream, {"text": "bounded"})
    stream.seek(0)
    assert protocol.receive(stream) == {"text": "bounded"}
    for value in (
        struct.pack("!I", protocol.MAX_FRAME + 1),
        struct.pack("!I", 0),
        struct.pack("!I", 2) + b"[]",
    ):
        with pytest.raises(ValueError):
            protocol.receive(io.BytesIO(value))
    with pytest.raises(EOFError):
        protocol.receive(io.BytesIO(b"\x00"))
    with pytest.raises(ValueError):
        protocol.decode_body("%%%")


@pytest.mark.parametrize(
    "path",
    [
        "https://remote/api/tasks",
        "//remote/api/tasks",
        "/docs",
        "/api/tasks\r\n",
        "/api/\\remote",
        "/api/tasks#fragment",
    ],
)
def test_reject_non_api_and_ssrf_targets(path):
    with pytest.raises(ValueError):
        protocol.target("GET", path)


def test_auth_headers_preserved_and_ambiguity_rejected():
    assert protocol.headers(
        [
            ["Authorization", "Bearer secret"],
            ["Origin", "http://evil.invalid"],
            ["Host", "localhost"],
            ["Connection", "close"],
        ]
    ) == [("Authorization", "Bearer secret"), ("Origin", "http://evil.invalid")]
    for value in (
        [["Authorization", "one"], ["authorization", "two"]],
        [["X-Test", "bad\nvalue"]],
        [["bad name", "value"]],
    ):
        with pytest.raises(ValueError):
            protocol.headers(value)


def test_guest_forwards_only_to_fixed_api(monkeypatch):
    connection = Mock()
    response = connection.getresponse.return_value
    response.status = 401
    response.getheaders.return_value = [("Content-Type", "application/json")]
    response.read.return_value = b'{"detail":"unauthorized"}'
    factory = Mock(return_value=connection)
    monkeypatch.setattr(guest.http.client, "HTTPConnection", factory)
    result = guest.forward(
        {
            "id": "1" * 32,
            "method": "POST",
            "path": "/api/tasks",
            "headers": [["Authorization", "Bearer token"], ["Origin", "http://evil.invalid"]],
            "body": protocol.encode_body(b"{}"),
        }
    )
    factory.assert_called_once_with("127.0.0.1", 8000, timeout=300)
    connection.putheader.assert_any_call("Authorization", "Bearer token")
    connection.putheader.assert_any_call("Origin", "http://evil.invalid")
    assert result["status"] == 401
    assert protocol.decode_body(result["body"]) == response.read.return_value
    connection.close.assert_called_once()


def test_guest_health_requires_production(monkeypatch):
    from aegis.security import deployment

    monkeypatch.setattr(deployment, "validate", lambda: {"production_ready": False})
    with pytest.raises(RuntimeError, match="production"):
        guest.health()
    monkeypatch.setattr(deployment, "validate", lambda: {"production_ready": True})
    monkeypatch.setattr(
        guest,
        "forward",
        lambda request: {
            "status": 200,
            "body": protocol.encode_body(b'{"configured":true,"demo":false}'),
        },
    )
    assert guest.health() == {"version": __version__, "production_ready": True}


def test_real_mutual_tls_and_certificate_pin(vm_inventory):
    path, _ = vm_inventory
    settings = policy.load(path)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    directory = settings["tls_directory"]
    ctx.load_cert_chain(str(directory / "server-cert.pem"), str(directory / "server-key.pem"))
    ctx.load_verify_locations(str(directory / "ca-cert.pem"))
    ctx.verify_mode = ssl.CERT_REQUIRED
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(10)
        settings["channel_port"] = listener.getsockname()[1]

        def serve():
            try:
                raw, _ = listener.accept()
                with ctx.wrap_socket(raw, server_side=True) as secured:
                    with secured.makefile("rwb", buffering=0) as stream:
                        assert protocol.receive(stream) == {"operation": "health"}
                        protocol.send(stream, {"version": __version__, "production_ready": True})
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        channel = host.connect(settings)
        try:
            assert channel.exchange({"operation": "health"}) == {
                "version": __version__,
                "production_ready": True,
            }
        finally:
            channel.close()
        thread.join(timeout=10)
        assert not thread.is_alive() and not errors


def test_loopback_gateway_preserves_guest_auth_and_rejects_rebinding():
    channel = Mock()

    def exchange(request):
        assert ["Authorization", "Bearer token"] in request["headers"]
        return {
            "id": request["id"],
            "status": 403,
            "headers": [["Content-Type", "application/json"]],
            "body": protocol.encode_body(b'{"detail":"forbidden"}'),
        }

    channel.exchange.side_effect = exchange
    with host.Gateway(0, channel) as gateway:
        assert gateway.server_address[0] == "127.0.0.1"
        for spoof, expected in ((False, 403), (True, 400)):
            thread = threading.Thread(target=gateway.handle_request, daemon=True)
            thread.start()
            connection = http.client.HTTPConnection("127.0.0.1", gateway.server_port, timeout=5)
            request_headers = {"Authorization": "Bearer token"}
            if spoof:
                request_headers["Host"] = "evil.invalid"
            connection.request("GET", "/api/tasks", headers=request_headers)
            response = connection.getresponse()
            assert response.status == expected
            response.read()
            connection.close()
            thread.join(timeout=5)
            assert not thread.is_alive()
    assert channel.exchange.call_count == 1


def test_no_plaintext_retry_or_native_fallback(vm_inventory, monkeypatch):
    path, _ = vm_inventory
    settings = policy.load(path)
    monkeypatch.setattr(policy, "secure_mutable_files", Mock())
    process = Mock()
    process.poll.return_value = None
    monkeypatch.setattr(host.subprocess, "Popen", Mock(return_value=process))
    connector = Mock(side_effect=ssl.SSLCertVerificationError("untrusted peer"))
    monkeypatch.setattr(host, "connect", connector)
    stopper = Mock()
    monkeypatch.setattr(host, "stop", stopper)
    with pytest.raises(ssl.SSLCertVerificationError):
        host.run(settings)
    connector.assert_called_once()
    stopper.assert_called_once_with(process)


def test_guest_provisioning_examples_are_restricted_and_non_installing():
    directory = Path(__file__).resolve().parents[1] / "deploy/vm"
    template = json.loads((directory / "policy.example.json").read_text(encoding="utf-8"))
    assert set(template) == policy.FIELDS
    assert template["accelerator"] == "tcg"
    assert template["qemu_sha256"] == "0" * 64  # Deliberately cannot be deployed as-is.
    service = (directory / "aegis-vm-bridge.service").read_text(encoding="utf-8")
    for required in (
        "User=aegis\n",
        "JoinsNamespaceOf=aegis-api.service\n",
        "PrivateNetwork=yes\n",
        "NoNewPrivileges=yes\n",
        "DevicePolicy=closed\n",
        "DeviceAllow=/dev/virtio-ports/org.aegis.api rw\n",
        "Environment=AEGIS_SECURITY_PROFILE=production\n",
        "ExecStart=/opt/aegis/.venv/bin/python -m aegis.vm.guest\n",
    ):
        assert required in service
    rule = (directory / "99-aegis-virtio.rules").read_text(encoding="utf-8")
    assert 'ATTR{name}=="org.aegis.api"' in rule
    assert 'OWNER="aegis"' in rule and 'MODE="0600"' in rule
