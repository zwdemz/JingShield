"""Offline regressions for SSH host-key validation; no network is contacted."""

from __future__ import annotations

import pathlib
import unittest
from unittest.mock import Mock

import paramiko

from scripts.ssh_host_keys import (
    PinnedHostKeyPolicy,
    configure_host_key_verification,
    sha256_fingerprint,
    validate_sha256_pin,
    verify_connected_host_key,
)


class DummyHostKey:
    def __init__(self, encoded: bytes) -> None:
        self.encoded = encoded

    def asbytes(self) -> bytes:
        return self.encoded

    def get_name(self) -> str:
        return "ssh-ed25519"


class HostKeyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key = DummyHostKey(b"ssh-ed25519 test public key")
        self.pin = sha256_fingerprint(self.key)

    def test_invalid_fingerprints_fail_before_connection(self) -> None:
        for invalid in ("", "MD5:aa:bb", "SHA256:abcd", self.pin + "=", "SHA256:" + "a" * 43):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                validate_sha256_pin(invalid)

    def test_unknown_host_requires_matching_out_of_band_pin(self) -> None:
        client = paramiko.SSHClient()
        PinnedHostKeyPolicy(self.pin).missing_host_key(client, "nas.example", self.key)
        self.assertIs(client.get_host_keys().lookup("nas.example")["ssh-ed25519"], self.key)

        denied = paramiko.SSHClient()
        different_pin = sha256_fingerprint(DummyHostKey(b"different public key"))
        with self.assertRaises(paramiko.SSHException):
            PinnedHostKeyPolicy(different_pin).missing_host_key(denied, "nas.example", self.key)
        self.assertIsNone(denied.get_host_keys().lookup("nas.example"))

    def test_missing_pin_uses_reject_policy(self) -> None:
        client = Mock(spec=paramiko.SSHClient)
        configure_host_key_verification(client, pathlib.Path("definitely-no-such-known-hosts"), None)
        client.load_system_host_keys.assert_called_once_with()
        client.load_host_keys.assert_not_called()
        self.assertIsInstance(client.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy)

    def test_explicit_pin_is_checked_even_with_existing_known_host(self) -> None:
        transport = Mock()
        transport.get_remote_server_key.return_value = self.key
        client = Mock(spec=paramiko.SSHClient)
        client.get_transport.return_value = transport
        verify_connected_host_key(client, self.pin)
        with self.assertRaises(paramiko.SSHException):
            verify_connected_host_key(client, sha256_fingerprint(DummyHostKey(b"other public key")))


if __name__ == "__main__":
    unittest.main()
