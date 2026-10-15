"""BIP-39 mnemonics, BIP-32 hierarchical derivation, BIP-44 paths.

mnemonic --PBKDF2-HMAC-SHA512 (2048 rounds, salt "mnemonic"+passphrase)--> 512-bit seed
seed --HMAC-SHA512(key="Bitcoin seed")--> master (k, c)
(k, c) --CKD--> children, along m / 44' / 60' / account' / change / index
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from dataclasses import dataclass, replace

from Crypto.Hash import RIPEMD160

from .curve import (
    G,
    N,
    Point,
    add,
    deserialize_public_key,
    private_to_public,
    scalar_mul,
    serialize_public_key,
)

HARDENED_OFFSET = 0x80000000

_XPRV_VERSION = bytes.fromhex("0488ADE4")
_XPUB_VERSION = bytes.fromhex("0488B21E")
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# --------------------------------------------------------------------------- #
# BIP-39
# --------------------------------------------------------------------------- #


def _nfkd(text: str) -> str:
    return unicodedata.normalize("NFKD", text)


def mnemonic_to_seed(mnemonic: str | list[str], passphrase: str = "") -> bytes:
    """512-bit seed. The passphrase goes into the *salt*: every passphrase is
    "correct" and opens its own wallet, so a typo is indistinguishable from theft."""
    if isinstance(mnemonic, list):
        mnemonic = " ".join(mnemonic)
    password = _nfkd(mnemonic).encode("utf-8")
    salt = ("mnemonic" + _nfkd(passphrase)).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", password, salt, 2048, dklen=64)


def entropy_to_mnemonic(entropy: bytes, wordlist: list[str]) -> list[str]:
    """ENT bits + first ENT/32 bits of SHA-256(entropy), split into 11-bit indices."""
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise ValueError("entropy must be 128, 160, 192, 224 or 256 bits")
    if len(wordlist) != 2048:
        raise ValueError("wordlist must contain 2048 words")
    ent_bits = len(entropy) * 8
    cs_bits = ent_bits // 32
    checksum = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    value = (int.from_bytes(entropy, "big") << cs_bits) | checksum
    n_words = (ent_bits + cs_bits) // 11
    return [wordlist[(value >> (11 * (n_words - 1 - i))) & 0x7FF] for i in range(n_words)]


def mnemonic_to_entropy(words: list[str] | str, wordlist: list[str]) -> bytes:
    """Inverse of entropy_to_mnemonic, verifying the checksum."""
    if isinstance(words, str):
        words = words.split()
    if len(words) not in (12, 15, 18, 21, 24):
        raise ValueError("mnemonic must have 12, 15, 18, 21 or 24 words")
    index = {w: i for i, w in enumerate(wordlist)}
    value = 0
    for w in words:
        if w not in index:
            raise ValueError(f"word not in wordlist: {w!r}")
        value = (value << 11) | index[w]
    total_bits = 11 * len(words)
    cs_bits = total_bits // 33
    ent_bits = total_bits - cs_bits
    entropy = (value >> cs_bits).to_bytes(ent_bits // 8, "big")
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - cs_bits)
    if (value & ((1 << cs_bits) - 1)) != expected:
        raise ValueError("invalid mnemonic: checksum mismatch")
    return entropy


# --------------------------------------------------------------------------- #
# BIP-32
# --------------------------------------------------------------------------- #


def hash160(data: bytes) -> bytes:
    return RIPEMD160.new(hashlib.sha256(data).digest()).digest()


def _b58check(payload: bytes) -> str:
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = _B58[rem] + out
    pad = len(data) - len(data.lstrip(b"\x00"))
    return "1" * pad + out


@dataclass(frozen=True)
class ExtendedKey:
    """A BIP-32 node. ``key`` is the private scalar, or None for a public-only node."""

    chain_code: bytes
    public_point: Point
    key: int | None = None
    depth: int = 0
    parent_fingerprint: bytes = b"\x00\x00\x00\x00"
    child_index: int = 0

    @classmethod
    def from_private(cls, key: int, chain_code: bytes, **meta) -> ExtendedKey:
        return cls(chain_code, private_to_public(key), key, **meta)

    @property
    def is_private(self) -> bool:
        return self.key is not None

    @property
    def public_key_bytes(self) -> bytes:
        return serialize_public_key(self.public_point, compressed=True)

    @property
    def fingerprint(self) -> bytes:
        return hash160(self.public_key_bytes)[:4]

    def neuter(self) -> ExtendedKey:
        """The xpub: same public key and chain code, private key removed."""
        return replace(self, key=None)

    def serialize(self) -> str:
        """Base58Check xprv/xpub string (mainnet versions)."""
        head = (
            (_XPRV_VERSION if self.is_private else _XPUB_VERSION)
            + bytes([self.depth])
            + self.parent_fingerprint
            + self.child_index.to_bytes(4, "big")
            + self.chain_code
        )
        body = b"\x00" + self.key.to_bytes(32, "big") if self.is_private else self.public_key_bytes
        return _b58check(head + body)

    def __repr__(self) -> str:  # never print the private key by accident
        kind = "xprv" if self.is_private else "xpub"
        return f"ExtendedKey({kind}, depth={self.depth}, index={format_index(self.child_index)})"


def master_key_from_seed(seed: bytes) -> ExtendedKey:
    if not 16 <= len(seed) <= 64:
        raise ValueError("seed must be 128 to 512 bits")
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(i[:32], "big")
    if not 1 <= k < N:
        raise ValueError("invalid master key; use another seed")
    return ExtendedKey.from_private(k, i[32:])


def _ckd_hmac(parent: ExtendedKey, index: int) -> tuple[int, bytes]:
    """I = HMAC-SHA512(c_par, data); returns (I_L as int, I_R)."""
    if not 0 <= index < 2**32:
        raise ValueError("child index out of range")
    if index >= HARDENED_OFFSET:
        if not parent.is_private:
            raise ValueError("cannot derive a hardened child from a public key (xpub)")
        data = b"\x00" + parent.key.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = parent.public_key_bytes + index.to_bytes(4, "big")
    i = hmac.new(parent.chain_code, data, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    if il >= N:
        raise ValueError("I_L >= n: invalid child, use the next index")
    return il, i[32:]


def derive_child(parent: ExtendedKey, index: int) -> ExtendedKey:
    """CKDpriv for private parents, CKDpub for public ones."""
    il, chain_code = _ckd_hmac(parent, index)
    meta = dict(depth=parent.depth + 1, parent_fingerprint=parent.fingerprint, child_index=index)
    if parent.is_private:
        k = (il + parent.key) % N
        if k == 0:
            raise ValueError("derived key is zero; use the next index")
        return ExtendedKey.from_private(k, chain_code, **meta)
    point = add(scalar_mul(il, G), parent.public_point)
    if point.is_infinity:
        raise ValueError("derived point is infinity; use the next index")
    return ExtendedKey(chain_code, point, None, **meta)


def format_index(index: int) -> str:
    return f"{index - HARDENED_OFFSET}'" if index >= HARDENED_OFFSET else str(index)


def parse_path(path: str) -> list[int]:
    parts = path.strip().split("/")
    if parts[0] not in ("m", "M"):
        raise ValueError("path must start with 'm'")
    out = []
    for part in parts[1:]:
        if not part:
            raise ValueError("empty path component")
        hardened = part[-1] in "'hH"
        number = part[:-1] if hardened else part
        if not number.isdigit():
            raise ValueError(f"bad path component: {part!r}")
        value = int(number)
        if value >= HARDENED_OFFSET:
            raise ValueError("path index too large")
        out.append(value + HARDENED_OFFSET if hardened else value)
    return out


def format_path(indices: list[int]) -> str:
    return "/".join(["m", *(format_index(i) for i in indices)])


def derive_path(root: ExtendedKey, path: str | list[int]) -> ExtendedKey:
    node = root
    for index in parse_path(path) if isinstance(path, str) else path:
        node = derive_child(node, index)
    return node


def ethereum_account(
    mnemonic: str, index: int = 0, passphrase: str = "", account: int = 0
) -> ExtendedKey:
    """m/44'/60'/account'/0/index — the path MetaMask and Ganache use."""
    root = master_key_from_seed(mnemonic_to_seed(mnemonic, passphrase))
    return derive_path(root, f"m/44'/60'/{account}'/0/{index}")


# --------------------------------------------------------------------------- #
# The parent-key recovery attack
# --------------------------------------------------------------------------- #


def recover_parent_private_key(parent_xpub: ExtendedKey, child_key: int, index: int) -> int:
    """parent = (child - I_L) mod n, where I_L = HMAC(c, serP(K_par) || i)[:32].

    Everything needed for I_L is in the xpub, so one leaked non-hardened child
    key plus the published xpub gives the parent private key -- and with it
    every sibling. For a hardened child I_L = HMAC(c, 0x00 || k_par || i),
    which needs the very key being sought, so the attack cannot even start.
    """
    if index >= HARDENED_OFFSET:
        raise ValueError(
            "hardened children are immune to this attack: I_L depends on the parent private key"
        )
    il, _ = _ckd_hmac(parent_xpub.neuter(), index)
    parent = (child_key - il) % N
    if parent == 0 or private_to_public(parent) != parent_xpub.public_point:
        raise ValueError("child key does not belong to this xpub at this index")
    return parent


def parse_extended_public_key(xpub_point: bytes, chain_code: bytes) -> ExtendedKey:
    """Build a public node from a 33-byte SEC1 key and a 32-byte chain code."""
    return ExtendedKey(chain_code, deserialize_public_key(xpub_point))
