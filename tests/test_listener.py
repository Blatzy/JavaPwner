"""Unit tests for javapwner.protocols.rmi.listener (JRMP listener)."""

from __future__ import annotations

import socket
import struct
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from javapwner.protocols.rmi.listener import (
    JrmpListener,
    JrmpListenerResult,
)
from javapwner.protocols.rmi.protocol import JRMP_MAGIC, PROTOCOL_ACK, MSG_RETURN


# ---------------------------------------------------------------------------
# JrmpListenerResult
# ---------------------------------------------------------------------------

class TestJrmpListenerResult:
    def test_to_dict(self):
        r = JrmpListenerResult(connections=2, payloads_sent=1, errors=["test"])
        d = r.to_dict()
        assert d["connections"] == 2
        assert d["payloads_sent"] == 1
        assert d["errors"] == ["test"]

    def test_default_empty(self):
        r = JrmpListenerResult()
        assert r.connections == 0
        assert r.payloads_sent == 0
        assert r.errors == []


# ---------------------------------------------------------------------------
# JrmpListener
# ---------------------------------------------------------------------------

class TestJrmpListener:
    def test_init(self):
        listener = JrmpListener(
            payload=b"\xac\xed\x00\x05",
            listen_host="127.0.0.1",
            listen_port=0,
            timeout=5.0,
        )
        assert listener.payload == b"\xac\xed\x00\x05"
        assert listener.listen_host == "127.0.0.1"
        assert listener.timeout == 5.0

    def test_start_stop(self):
        """Can start and stop without errors."""
        listener = JrmpListener(
            payload=b"\xac\xed\x00\x05",
            listen_host="127.0.0.1",
            listen_port=0,  # OS picks a port
            timeout=2.0,
        )
        # Bind to port 0 to get a random available port
        listener._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener._server.settimeout(1.0)
        listener._server.bind(("127.0.0.1", 0))
        actual_port = listener._server.getsockname()[1]
        listener._server.listen(5)
        listener.listen_port = actual_port

        listener._thread = threading.Thread(target=listener._serve, daemon=True)
        listener._thread.start()

        # Connect as a fake JRMP client
        try:
            client = socket.create_connection(("127.0.0.1", actual_port), timeout=3)
            # Send JRMP handshake
            client.sendall(JRMP_MAGIC + b"\x00\x02" + b"\x4b")
            # Read ProtocolAck
            ack = client.recv(256)
            assert ack[0] == PROTOCOL_ACK
            # Send client endpoint info
            client.sendall(b"\x00\x04test\x00\x00\x00\x01")
            # Read the RETURN message with payload
            data = client.recv(4096)
            assert data[0] == MSG_RETURN
            client.close()
        except Exception:
            pass
        finally:
            listener.stop()

        assert listener.result.connections >= 1

    def test_result_property(self):
        listener = JrmpListener(payload=b"test")
        assert isinstance(listener.result, JrmpListenerResult)
