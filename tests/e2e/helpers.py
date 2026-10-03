"""Shared helpers for the ghacc end-to-end tests.

The tests drive a real ``ghacc`` process over loopback sockets: a local
upstream HTTP/HTTPS server plays the accelerated origin and the engine is
started in forward-proxy mode on an ephemeral port.
"""

from __future__ import annotations

import contextlib
import http.server
import os
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence

# --- process / port helpers ------------------------------------------------


def free_port(host: str = "127.0.0.1") -> int:
    """Return a currently free TCP port on ``host``."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def wait_for_port(
    host: str,
    port: int,
    proc: subprocess.Popen,
    log_path: Path,
    timeout: float = 15.0,
) -> None:
    """Block until ``host:port`` accepts a connection or the process dies."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(
                f"ghacc exited early with {proc.returncode}:\n{read_log(log_path)}"
            )
        with contextlib.suppress(OSError):
            with socket.create_connection((host, port), timeout=0.5):
                return
        time.sleep(0.05)
    proc.terminate()
    raise TimeoutError(f"ghacc did not listen on {host}:{port}:\n{read_log(log_path)}")


def read_log(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except OSError:
        return "<no log>"


# --- raw socket HTTP -------------------------------------------------------


def recv_all(sock: socket.socket, limit: int = 1 << 20) -> bytes:
    """Read until EOF (or ``limit`` bytes)."""
    chunks: list[bytes] = []
    total = 0
    while total < limit:
        try:
            chunk = sock.recv(65536)
        except (TimeoutError, socket.timeout):
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def read_until(sock: socket.socket, delimiter: bytes, limit: int = 1 << 20) -> bytes:
    """Read until ``delimiter`` is seen (inclusive)."""
    data = b""
    while delimiter not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def raw_request(host: str, port: int, request: bytes, timeout: float = 15.0) -> bytes:
    """Send ``request`` to ``host:port`` and return everything until EOF."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        return recv_all(sock)


# --- ghacc process ---------------------------------------------------------


@dataclass
class ProxyProcess:
    host: str
    port: int
    proc: subprocess.Popen
    log_path: Path

    def log(self) -> str:
        return read_log(self.log_path)


@contextlib.contextmanager
def start_forward_proxy(
    ghacc_bin: Path,
    workdir: Path,
    *,
    mode: str = "forward",
    config: Path | None = None,
    extra_args: Sequence[str] = (),
    host: str = "127.0.0.1",
) -> Iterator[ProxyProcess]:
    """Start ``ghacc run`` in the given capture mode and wait until ready."""
    port = free_port(host)
    workdir.mkdir(parents=True, exist_ok=True)
    log_path = workdir / "ghacc.log"
    args = [
        str(ghacc_bin),
        "run",
        "--mode",
        mode,
        "--address",
        host,
        "--proxy-port",
        str(port),
        "--dir",
        str(workdir / "ca"),
        *extra_args,
    ]
    if config is not None:
        args += ["--config", str(config)]

    with log_path.open("w") as log:
        proc = subprocess.Popen(args, stdout=log, stderr=subprocess.STDOUT, text=True)
        try:
            wait_for_port(host, port, proc, log_path)
            yield ProxyProcess(host=host, port=port, proc=proc, log_path=log_path)
        finally:
            _terminate(proc)


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)


def run_ghacc(ghacc_bin: Path, args: Sequence[str], timeout: float = 30.0) -> subprocess.CompletedProcess:
    """Run a one-shot ghacc command and capture its output."""
    return subprocess.run(
        [str(ghacc_bin), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def write_config(path: Path, text: str) -> Path:
    path.write_text(text)
    return path


# --- upstream servers ------------------------------------------------------


class _QuietHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    body = b"hello-plain"

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        payload = type(self).body
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args, **kwargs) -> None:  # silence the test log
        pass


@dataclass
class Upstream:
    host: str
    port: int

    @property
    def authority(self) -> str:
        return f"{self.host}:{self.port}"


@contextlib.contextmanager
def http_upstream(body: bytes = b"hello-plain") -> Iterator[Upstream]:
    handler = type("Handler", (_QuietHandler,), {"body": body})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Upstream("127.0.0.1", server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextlib.contextmanager
def https_upstream(
    workdir: Path, *, common_name: str = "test.local", body: bytes = b"hello-tls"
) -> Iterator[Upstream]:
    """A TLS origin presenting a self-signed certificate for ``common_name``."""
    cert = workdir / "upstream.crt"
    key = workdir / "upstream.key"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(key), "-out", str(cert), "-days", "1",
            "-subj", f"/CN={common_name}",
            "-addext", f"subjectAltName=DNS:{common_name}",
        ],
        check=True,
        capture_output=True,
    )

    handler = type("Handler", (_QuietHandler,), {"body": body})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    server.socket = context.wrap_socket(server.socket, server_side=True)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield Upstream("127.0.0.1", server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def connect_request(authority: str) -> bytes:
    return (
        f"CONNECT {authority} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "\r\n"
    ).encode()
