"""Fail-closed Paramiko host-key setup shared by Linux deployment clients.

An unknown host is accepted only when its SHA-256 host-key fingerprint was
obtained through a trusted, independent channel and supplied explicitly.
The pin is used for this connection only; it is not silently persisted.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import pathlib
import re

import paramiko


def validate_sha256_pin(fingerprint: str) -> str:
    """Validate an out-of-band OpenSSH SHA256 fingerprint.

    Args: fingerprint is the operator-supplied SHA256:base64 pin.
    Returns: The unchanged canonical pin.
    Raises: ValueError for malformed or noncanonical fingerprints.
    """
    if not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint):
        raise ValueError("host-key pin must be an OpenSSH SHA256 fingerprint")
    encoded = fingerprint.removeprefix("SHA256:")
    decoded = base64.b64decode(encoded + "=", validate=True)
    if len(decoded) != 32 or base64.b64encode(decoded).decode("ascii").rstrip("=") != encoded:
        raise ValueError("host-key pin is not a canonical SHA-256 fingerprint")
    return fingerprint


def sha256_fingerprint(key: paramiko.PKey) -> str:
    """Calculate a host-key fingerprint without trusting the key.

    Args: key is the server public host key.
    Returns: Its canonical OpenSSH SHA256:base64 fingerprint.
    Raises: The key serializer's error if the key cannot be encoded.
    """
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def require_pinned_key(key: paramiko.PKey, expected: str) -> None:
    """Compare a server key with an independently verified pin.

    Args: key is the presented public key; expected is the operator pin.
    Returns: None when the fingerprints match.
    Raises: ValueError for an invalid pin; SSHException for a mismatch.
    """
    if not hmac.compare_digest(sha256_fingerprint(key), validate_sha256_pin(expected)):
        raise paramiko.SSHException("SSH host key does not match the supplied SHA-256 pin")


class PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Trust an unknown host only for this connection after pin verification.

    Args: fingerprint is a canonical, independently verified SHA-256 pin.
    Raises: ValueError if the pin is malformed.
    """

    def __init__(self, fingerprint: str) -> None:
        self.fingerprint = validate_sha256_pin(fingerprint)

    def missing_host_key(self, client: paramiko.SSHClient, hostname: str, key: paramiko.PKey) -> None:
        """Validate an unknown server key before authentication proceeds.

        Args: client owns the in-memory keys; hostname is Paramiko's host label;
            key is the newly presented public key.
        Returns: None after adding a matching key in memory only.
        Raises: SSHException if the presented key differs from the pin.
        """
        require_pinned_key(key, self.fingerprint)
        client.get_host_keys().add(hostname, key.get_name(), key)


def configure_host_key_verification(
    client: paramiko.SSHClient, known_hosts: pathlib.Path, fingerprint: str | None
) -> None:
    """Configure strict host-key checking on a Paramiko client.

    Args: client is not yet connected; known_hosts is an optional local trust
        file; fingerprint is an optional out-of-band SHA-256 pin.
    Returns: None; mutates only the in-memory client configuration.
    Raises: ValueError for a malformed pin or a file-read error from Paramiko.
    """
    client.load_system_host_keys()
    if known_hosts.is_file():
        client.load_host_keys(str(known_hosts))
    client.set_missing_host_key_policy(
        PinnedHostKeyPolicy(fingerprint) if fingerprint else paramiko.RejectPolicy()
    )


def verify_connected_host_key(client: paramiko.SSHClient, fingerprint: str | None) -> None:
    """Check an explicit pin even if known_hosts already matched the host.

    Args: client is the connected SSH client; fingerprint is the optional pin.
    Returns: None when no pin was requested or the key matches it.
    Raises: SSHException if transport is absent or the key mismatches.
    """
    if fingerprint is None:
        return
    transport = client.get_transport()
    if transport is None:
        raise paramiko.SSHException("SSH transport is unavailable for host-key verification")
    require_pinned_key(transport.get_remote_server_key(), fingerprint)
