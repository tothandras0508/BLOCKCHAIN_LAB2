"""ECDSA over secp256k1: sign, verify, RFC 6979 nonces, low-s, key recovery,
and the nonce-reuse attack.

Signing:      R = k*G,  r = R.x mod n,  s = k^-1 (z + r*d) mod n
Verification: u1 = z/s, u2 = r/s,  check (u1*G + u2*Q).x mod n == r
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from .curve import (
    G,
    N,
    P,
    Point,
    add,
    inverse_mod,
    is_on_curve,
    private_to_public,
    scalar_mul,
    scalar_mul_ladder,
    sqrt_mod,
)

HALF_N = N // 2


@dataclass(frozen=True)
class Signature:
    r: int
    s: int
    recovery_id: int = 0  # bit 0: parity of R.y; bit 1: R.x >= n (overflow)

    def to_bytes(self) -> bytes:
        """Compact 64-byte form r || s."""
        return self.r.to_bytes(32, "big") + self.s.to_bytes(32, "big")

    @classmethod
    def from_bytes(cls, data: bytes, recovery_id: int = 0) -> Signature:
        if len(data) != 64:
            raise ValueError("compact signature must be 64 bytes")
        return cls(int.from_bytes(data[:32], "big"), int.from_bytes(data[32:], "big"), recovery_id)

    def to_der(self) -> bytes:
        """Strict DER: SEQUENCE { INTEGER r, INTEGER s }."""

        def der_int(v: int) -> bytes:
            body = v.to_bytes(max(1, (v.bit_length() + 7) // 8), "big")
            if body[0] & 0x80:  # keep it positive
                body = b"\x00" + body
            return b"\x02" + bytes([len(body)]) + body

        content = der_int(self.r) + der_int(self.s)
        return b"\x30" + bytes([len(content)]) + content


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _check_hash(msg_hash: bytes) -> None:
    if not isinstance(msg_hash, (bytes, bytearray)) or len(msg_hash) != 32:
        raise ValueError("message hash must be exactly 32 bytes")


def _z(msg_hash: bytes) -> int:
    """bits2int for a 256-bit hash and 256-bit n: the hash as an integer."""
    return int.from_bytes(msg_hash, "big")


# --------------------------------------------------------------------------- #
# RFC 6979
# --------------------------------------------------------------------------- #


def rfc6979_nonce(d: int, msg_hash: bytes) -> int:
    """Deterministic k = HMAC-DRBG(d, H(m)), RFC 6979 section 3.2, HMAC-SHA256.

    Different for every (key, message) pair, and computing it requires d.
    """
    _check_hash(msg_hash)
    x = d.to_bytes(32, "big")
    h = (_z(msg_hash) % N).to_bytes(32, "big")  # bits2octets
    v = b"\x01" * 32
    k = b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + h, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        candidate = int.from_bytes(v, "big")
        if 1 <= candidate < N:
            return candidate
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


# --------------------------------------------------------------------------- #
# Sign / verify / recover
# --------------------------------------------------------------------------- #


def sign(
    d: int,
    msg_hash: bytes,
    nonce: int | None = None,
    enforce_low_s: bool = True,
) -> Signature:
    """Sign a 32-byte hash. ``nonce`` overrides RFC 6979 (for the attack demo only)."""
    _check_hash(msg_hash)
    if not (1 <= d < N):
        raise ValueError("private key out of range")
    k = rfc6979_nonce(d, msg_hash) if nonce is None else nonce
    if not (1 <= k < N):
        raise ValueError("nonce out of range")

    R = scalar_mul_ladder(k, G)
    r = R.x % N
    if r == 0:
        raise ValueError("r = 0; choose another nonce")
    s = inverse_mod(k, N) * (_z(msg_hash) + r * d) % N
    if s == 0:
        raise ValueError("s = 0; choose another nonce")

    recovery_id = (R.y & 1) | (2 if R.x >= N else 0)
    if enforce_low_s and s > HALF_N:
        # s -> n - s corresponds to k -> -k, i.e. R -> -R: the y parity flips.
        s = N - s
        recovery_id ^= 1
    return Signature(r, s, recovery_id)


def verify(public_key: Point, msg_hash: bytes, sig: Signature) -> bool:
    if len(msg_hash) != 32:
        return False
    if public_key.is_infinity or not is_on_curve(public_key):
        return False
    if not (1 <= sig.r < N and 1 <= sig.s < N):
        return False
    w = inverse_mod(sig.s, N)
    u1 = _z(msg_hash) * w % N
    u2 = sig.r * w % N
    X = add(scalar_mul(u1, G), scalar_mul(u2, public_key))
    return not X.is_infinity and X.x % N == sig.r


def recover_public_key(msg_hash: bytes, sig: Signature) -> Point:
    """Q = r^-1 (s*R - z*G), with R rebuilt from r and the recovery id.

    This is what ecrecover does, and why an Ethereum transaction carries no
    public key: any signature on chain reveals it.
    """
    _check_hash(msg_hash)
    if not (1 <= sig.r < N and 1 <= sig.s < N) or not (0 <= sig.recovery_id <= 3):
        raise ValueError("invalid signature values")
    x = sig.r + (N if sig.recovery_id & 2 else 0)
    if x >= P:
        raise ValueError("recovery id points outside the field")
    y = sqrt_mod(x * x * x + 7)
    if y is None:
        raise ValueError("r does not correspond to a curve point")
    if (y & 1) != (sig.recovery_id & 1):
        y = P - y
    R = Point(x, y)
    r_inv = inverse_mod(sig.r, N)
    sR = scalar_mul(sig.s, R)
    zG = scalar_mul((-_z(msg_hash)) % N, G)
    Q = scalar_mul(r_inv, add(sR, zG))
    if Q.is_infinity or not is_on_curve(Q):
        raise ValueError("recovered an invalid public key")
    return Q


# --------------------------------------------------------------------------- #
# The attack
# --------------------------------------------------------------------------- #


def looks_like_nonce_reuse(sig1: Signature, sig2: Signature) -> bool:
    """Equal nonces give equal r: the reuse is visible to anyone reading the chain."""
    return sig1.r == sig2.r


def recover_private_key_from_nonce_reuse(
    r: int, s1: int, msg_hash1: bytes, s2: int, msg_hash2: bytes
) -> int:
    """Recover d from two signatures (r, s1), (r, s2) that share a nonce.

        k = (z1 - z2) / (s1 - s2),   d = (s1*k - z1) / r     (all mod n)

    Low-s normalisation may have replaced either s by n - s (i.e. k by -k).
    Flipping *both* gives the same d, so only the relative sign matters: try
    s2 and n - s2, and keep the candidate whose k actually reproduces r.
    """
    z1, z2 = _z(msg_hash1), _z(msg_hash2)
    for s2_candidate in (s2, (N - s2) % N):
        denom = (s1 - s2_candidate) % N
        if denom == 0:
            continue
        k = (z1 - z2) * inverse_mod(denom, N) % N
        if k == 0:
            continue
        if scalar_mul(k, G).x % N != r:
            continue
        return (s1 * k - z1) * inverse_mod(r, N) % N
    raise ValueError("signatures are not consistent with a shared nonce")


__all__ = [
    "Signature",
    "rfc6979_nonce",
    "sign",
    "verify",
    "recover_public_key",
    "looks_like_nonce_reuse",
    "recover_private_key_from_nonce_reuse",
    "private_to_public",
]
