"""Ethereum addresses and EIP-55 mixed-case checksums.

address = last 20 bytes of Keccak-256(x || y)   (uncompressed key, no 0x04 prefix)

Keccak-256 is NOT hashlib.sha3_256: Ethereum adopted Keccak before NIST changed
the padding rule for SHA-3, and the two give different digests.
"""

from __future__ import annotations

import re

from Crypto.Hash import keccak

from .curve import Point, private_to_public, serialize_public_key

_HEX40 = re.compile(r"^[0-9a-fA-F]{40}$")


def keccak256(data: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=data).digest()


def public_key_to_address(point: Point) -> str:
    """Lowercase 0x-prefixed address (unchecked)."""
    raw = serialize_public_key(point, compressed=False)[1:]  # drop 0x04
    return "0x" + keccak256(raw)[-20:].hex()


def _strip(address: str | bytes) -> str:
    if isinstance(address, (bytes, bytearray)):
        if len(address) != 20:
            raise ValueError("address must be 20 bytes")
        return address.hex()
    body = address[2:] if address[:2] in ("0x", "0X") else address
    if not _HEX40.match(body):
        raise ValueError("address must be 40 hexadecimal characters")
    return body


def to_checksum_address(address: str | bytes) -> str:
    """EIP-55: uppercase a letter iff the matching nibble of
    Keccak-256(lowercase hex string) is >= 8. Hashes the ASCII text, not the bytes."""
    lower = _strip(address).lower()
    digest = keccak256(lower.encode("ascii")).hex()
    return "0x" + "".join(
        c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c
        for i, c in enumerate(lower)
    )


def is_valid_checksum_address(address: str) -> bool:
    """True for a correct EIP-55 address, or an unchecked all-lower/all-upper one."""
    try:
        body = _strip(address)
    except ValueError:
        return False
    if body == body.lower() or body == body.upper():
        return True  # backwards compatible: no checksum present
    return to_checksum_address(body) == "0x" + body


def address_from_private_key(d: int) -> str:
    return to_checksum_address(public_key_to_address(private_to_public(d)))
