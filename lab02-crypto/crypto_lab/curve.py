"""secp256k1 field and group arithmetic, written from the definitions.

    y^2 = x^3 + 7  (mod p),   p = 2^256 - 2^32 - 977

Teaching code only. Python integers are not constant-time, so even the
Montgomery ladder below leaks timing information. Never protect value with it.
"""

from __future__ import annotations

from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# Domain parameters (SEC 2, section 2.4.1)
# --------------------------------------------------------------------------- #

P = 2**256 - 2**32 - 977
A = 0
B = 7
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


@dataclass(frozen=True)
class Point:
    """An affine point. ``x is None and y is None`` encodes the identity O."""

    x: int | None
    y: int | None

    @property
    def is_infinity(self) -> bool:
        return self.x is None

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        if self.is_infinity:
            return "Point(INFINITY)"
        return f"Point(x=0x{self.x:064x}, y=0x{self.y:064x})"


INFINITY = Point(None, None)
G = Point(GX, GY)


# --------------------------------------------------------------------------- #
# Field arithmetic
# --------------------------------------------------------------------------- #


def inverse_mod(a: int, m: int = P) -> int:
    """Multiplicative inverse modulo a prime ``m`` via Fermat: a^(m-2) = a^-1.

    Valid only because both P and N are prime. Raises ZeroDivisionError for 0,
    which has no inverse; silently returning 0 would hide bugs.
    """
    a %= m
    if a == 0:
        raise ZeroDivisionError("0 has no inverse modulo m")
    return pow(a, m - 2, m)


def sqrt_mod(a: int) -> int | None:
    """Square root mod P, or None if ``a`` is a quadratic non-residue.

    P = 3 (mod 4), so a^((P+1)/4) is a root whenever one exists.
    """
    a %= P
    root = pow(a, (P + 1) // 4, P)
    return root if root * root % P == a else None


# --------------------------------------------------------------------------- #
# Group law
# --------------------------------------------------------------------------- #


def is_on_curve(point: Point) -> bool:
    if point.is_infinity:
        return True
    x, y = point.x, point.y
    if not (0 <= x < P and 0 <= y < P):
        return False
    return (y * y - (x * x * x + A * x + B)) % P == 0


def negate(point: Point) -> Point:
    if point.is_infinity:
        return INFINITY
    return Point(point.x, (-point.y) % P)


def double(point: Point) -> Point:
    """2P. The tangent at a point with y = 0 is vertical, so 2P = O there."""
    if point.is_infinity or point.y == 0:
        return INFINITY
    x, y = point.x, point.y
    lam = (3 * x * x + A) * inverse_mod(2 * y) % P
    x3 = (lam * lam - 2 * x) % P
    y3 = (lam * (x - x3) - y) % P
    return Point(x3, y3)


def add(p1: Point, p2: Point) -> Point:
    """P1 + P2 with every special case of the chord-and-tangent rule."""
    if p1.is_infinity:
        return p2
    if p2.is_infinity:
        return p1
    if p1.x == p2.x:
        if (p1.y + p2.y) % P == 0:  # P + (-P) = O
            return INFINITY
        return double(p1)  # same point
    lam = (p2.y - p1.y) * inverse_mod(p2.x - p1.x) % P
    x3 = (lam * lam - p1.x - p2.x) % P
    y3 = (lam * (p1.x - x3) - p1.y) % P
    return Point(x3, y3)


def scalar_mul(k: int, point: Point) -> Point:
    """k*P by Double-and-Add, O(log k).

    LEAKS k: the ``add`` runs only when the current bit is 1, so time and
    power draw reveal the scalar bit by bit. Use for public scalars only.
    """
    if k < 0:
        return scalar_mul(-k, negate(point))
    result = INFINITY
    addend = point
    while k:
        if k & 1:
            result = add(result, addend)
        addend = double(addend)
        k >>= 1
    return result


def scalar_mul_ladder(k: int, point: Point) -> Point:
    """k*P by the Montgomery ladder.

    Every iteration performs exactly one add and one double whatever the bit,
    over a fixed 256-bit width, so the *sequence* of operations is independent
    of k. (The underlying Python big-int arithmetic is still not constant-time.)
    Invariant: R1 - R0 = P.
    """
    if k < 0:
        return scalar_mul_ladder(-k, negate(point))
    r0, r1 = INFINITY, point
    for i in reversed(range(max(256, k.bit_length()))):
        if (k >> i) & 1:
            r0, r1 = add(r0, r1), double(r1)
        else:
            r0, r1 = double(r0), add(r0, r1)
    return r0


# --------------------------------------------------------------------------- #
# Keys
# --------------------------------------------------------------------------- #


def private_to_public(d: int) -> Point:
    """Q = d*G for a private key in [1, n-1], using the ladder (d is secret)."""
    if not isinstance(d, int) or not (1 <= d < N):
        raise ValueError("private key must be an integer in [1, n-1]")
    return scalar_mul_ladder(d, G)


def serialize_public_key(point: Point, compressed: bool = True) -> bytes:
    """SEC1 encoding: 02/03 || x (33 bytes) or 04 || x || y (65 bytes)."""
    if point.is_infinity:
        raise ValueError("the point at infinity has no SEC1 public-key encoding")
    x = point.x.to_bytes(32, "big")
    if compressed:
        return bytes([0x03 if point.y & 1 else 0x02]) + x
    return b"\x04" + x + point.y.to_bytes(32, "big")


def deserialize_public_key(data: bytes) -> Point:
    """Parse SEC1, recovering y from x for compressed keys.

    Every result is checked to lie on the curve: accepting an off-curve point
    is the entry condition for invalid-curve attacks.
    """
    if len(data) == 33 and data[0] in (0x02, 0x03):
        x = int.from_bytes(data[1:], "big")
        if x >= P:
            raise ValueError("x coordinate is not a field element")
        y = sqrt_mod(x * x * x + B)
        if y is None:
            raise ValueError("x does not correspond to a point on the curve")
        if (y & 1) != (data[0] & 1):
            y = P - y
        point = Point(x, y)
    elif len(data) == 65 and data[0] == 0x04:
        point = Point(int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:], "big"))
    else:
        raise ValueError("unrecognised SEC1 public-key encoding")
    if not is_on_curve(point):
        raise ValueError("point is not on the curve")
    return point
