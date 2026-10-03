"""Forward-proxy end-to-end tests: absolute-URI, CONNECT, PAC, MITM and Block."""

from __future__ import annotations

import socket
import ssl

from helpers import (
    connect_request,
    raw_request,
    read_until,
    recv_all,
    start_forward_proxy,
    write_config,
)

BLOCK_CONFIG = """
[general]
mode = "forward"

[providers]
enabled = []

[[provider.custom]]
id = "e2e"
name = "E2E"

[[provider.custom.rules]]
pattern = "blocked.local"
action = "block"
"""

MITM_CONFIG = """
[general]
mode = "forward"

[providers]
enabled = []

[[provider.custom]]
id = "e2e"
name = "E2E"

[[provider.custom.rules]]
pattern = "test.local"
ip = "127.0.0.1"
tls_ignore_name_mismatch = true
"""


def test_absolute_uri_is_forwarded(ghacc_bin, tmp_path, upstream_http):
    with start_forward_proxy(ghacc_bin, tmp_path) as proxy:
        request = (
            f"GET http://{upstream_http.authority}/ HTTP/1.1\r\n"
            f"Host: {upstream_http.authority}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        response = raw_request(proxy.host, proxy.port, request)
        assert b"200 OK" in response, proxy.log()
        assert b"hello-plain" in response


def test_connect_creates_a_plain_tunnel(ghacc_bin, tmp_path, upstream_http):
    with start_forward_proxy(ghacc_bin, tmp_path) as proxy:
        with socket.create_connection((proxy.host, proxy.port), timeout=15) as sock:
            sock.sendall(connect_request(upstream_http.authority))
            head = read_until(sock, b"\r\n\r\n")
            assert b"200 Connection Established" in head, proxy.log()

            sock.sendall(b"GET /tunnel HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            response = recv_all(sock)
            assert b"hello-plain" in response


def test_pac_file_is_served(ghacc_bin, tmp_path):
    with start_forward_proxy(ghacc_bin, tmp_path, mode="pac") as proxy:
        response = raw_request(
            proxy.host,
            proxy.port,
            b"GET /pac HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        )
        assert b"application/x-ns-proxy-autoconfig" in response, proxy.log()
        assert b"FindProxyForURL" in response
        assert f"PROXY 127.0.0.1:{proxy.port}".encode() in response


def test_block_rule_returns_403(ghacc_bin, tmp_path):
    config = write_config(tmp_path / "config.toml", BLOCK_CONFIG)
    with start_forward_proxy(ghacc_bin, tmp_path, config=config) as proxy:
        response = raw_request(
            proxy.host,
            proxy.port,
            b"GET http://blocked.local/ HTTP/1.1\r\n"
            b"Host: blocked.local\r\nConnection: close\r\n\r\n",
        )
        assert b"403" in response, proxy.log()
        assert b"hello" not in response


def test_connect_tls_interception_issues_a_trusted_leaf(ghacc_bin, tmp_path, upstream_https):
    config = write_config(tmp_path / "config.toml", MITM_CONFIG)
    with start_forward_proxy(ghacc_bin, tmp_path, config=config) as proxy:
        ca_file = tmp_path / "ca" / "ca.crt"
        assert ca_file.is_file(), proxy.log()

        context = ssl.create_default_context(cafile=str(ca_file))
        raw = socket.create_connection((proxy.host, proxy.port), timeout=15)
        try:
            raw.sendall(connect_request(f"test.local:{upstream_https.port}"))
            head = read_until(raw, b"\r\n\r\n")
            assert b"200 Connection Established" in head, proxy.log()

            with context.wrap_socket(raw, server_hostname="test.local") as tls:
                tls.sendall(b"GET / HTTP/1.1\r\nHost: test.local\r\nConnection: close\r\n\r\n")
                response = recv_all(tls)
            assert b"200 OK" in response
            assert b"hello-tls" in response
        finally:
            raw.close()
