class JavaPwnerError(Exception):
    """Base exception for all JavaPwner errors."""


class ConnectionError(JavaPwnerError):
    """Raised when a network connection fails or times out."""


class ProtocolError(JavaPwnerError):
    """Raised when an unexpected protocol response is received."""


class JrmpError(ProtocolError):
    """Raised when JRMP handshake fails or response is malformed."""


class PayloadError(JavaPwnerError):
    """Raised when payload generation fails (ysoserial error, empty output, timeout)."""


class NotJiniError(JavaPwnerError):
    """Raised when the target does not appear to be a Jini/Reggie service."""
