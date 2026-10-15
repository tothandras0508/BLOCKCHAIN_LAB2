"""Demonstrations. Usage: python -m crypto_lab [curve|ecdsa|wallet|pqc]"""

from __future__ import annotations

import hashlib
import secrets
import sys

from . import address, ecdsa, hdwallet, pqc
from .curve import (
    G,
    INFINITY,
    N,
    add,
    double,
    is_on_curve,
    private_to_public,
    scalar_mul,
    scalar_mul_ladder,
)

DEMO_KEY = 0xC0FFEE00BADC0DE1234567890ABCDEF1122334455667788990AABBCCDDEEFF00
TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


def _title(text: str) -> None:
    print(f"\n{'=' * 72}\n{text}\n{'=' * 72}")


def demo_curve() -> None:
    _title("Part A -- secp256k1 group law")
    print(f"G on curve                        : {is_on_curve(G)}")
    print(f"n*G is the identity               : {scalar_mul(N, G).is_infinity}")
    print(f"(n-1)*G + G is the identity       : {add(scalar_mul(N - 1, G), G).is_infinity}")
    print(f"G + G == 2*G                      : {add(G, G) == double(G) == scalar_mul(2, G)}")
    agree = all(
        scalar_mul(k, G) == scalar_mul_ladder(k, G)
        for k in (secrets.randbelow(N - 1) + 1 for _ in range(20))
    )
    print(f"double-and-add == Montgomery ladder (20 random k): {agree}")
    print(f"P + O == P                        : {add(G, INFINITY) == G}")
    two_g = double(G)
    print(f"2G.x = 0x{two_g.x:064x}")
    print(f"2G.y = 0x{two_g.y:064x}")


def demo_ecdsa() -> None:
    _title("Part B -- ECDSA and the nonce")
    d = DEMO_KEY
    pub = private_to_public(d)
    msg = hashlib.sha256(b"Lab 02: hello, secp256k1").digest()
    other = hashlib.sha256(b"Lab 02: a different message").digest()
    print(f"private key d : 0x{d:064x}")
    print(f"address       : {address.address_from_private_key(d)}")

    sig = ecdsa.sign(d, msg)
    print(f"r = 0x{sig.r:064x}\ns = 0x{sig.s:064x}\nrecovery id = {sig.recovery_id}")
    print(f"verifies                        : {ecdsa.verify(pub, msg, sig)}")
    print(f"reproducible across runs        : {ecdsa.sign(d, msg) == sig}")
    print(f"rejects a different message     : {not ecdsa.verify(pub, other, sig)}")
    print(f"low-s enforced (s <= n/2)       : {sig.s <= N // 2}")
    print(f"recovered key matches signer    : {ecdsa.recover_public_key(msg, sig) == pub}")
    flipped = ecdsa.Signature(sig.r, N - sig.s, sig.recovery_id ^ 1)
    print(f"(r, n-s) also verifies          : {ecdsa.verify(pub, msg, flipped)}")

    print("\n-- The attack: two messages signed with the same k --")
    k = secrets.randbelow(N - 1) + 1
    m1 = hashlib.sha256(b"pay Alice 1 ETH").digest()
    m2 = hashlib.sha256(b"pay Bob 2 ETH").digest()
    s1 = ecdsa.sign(d, m1, nonce=k)
    s2 = ecdsa.sign(d, m2, nonce=k)
    print(f"r1 = 0x{s1.r:064x}\nr2 = 0x{s2.r:064x}")
    print(f"nonce reuse: identical r        : {ecdsa.looks_like_nonce_reuse(s1, s2)}")
    recovered = ecdsa.recover_private_key_from_nonce_reuse(s1.r, s1.s, m1, s2.s, m2)
    print(f"original  d = 0x{d:064x}")
    print(f"recovered d = 0x{recovered:064x}")
    print(f"attack succeeded                : {recovered == d}")


def demo_wallet() -> None:
    _title("Part C -- BIP-39 / BIP-32 / BIP-44 and EIP-55")
    seed = hdwallet.mnemonic_to_seed(TEST_MNEMONIC)
    print(f"mnemonic : {TEST_MNEMONIC}")
    print(f"seed     : {seed.hex()}")
    root = hdwallet.master_key_from_seed(seed)
    for i in range(3):
        node = hdwallet.derive_path(root, f"m/44'/60'/0'/0/{i}")
        print(f"m/44'/60'/0'/0/{i} : {address.to_checksum_address(address.public_key_to_address(node.public_point))}")

    print("\n-- Passphrase enters the salt: every passphrase is 'valid' --")
    for pw in ("correct horse", "correct horse "):
        node = hdwallet.ethereum_account(TEST_MNEMONIC, 0, passphrase=pw)
        addr = address.to_checksum_address(address.public_key_to_address(node.public_point))
        print(f"passphrase {pw!r:<18}: {addr}")

    print("\n-- Parent-key recovery from xpub + one leaked non-hardened child --")
    account = hdwallet.derive_path(root, "m/44'/60'/0'/0")
    xpub = account.neuter()
    print(f"published xpub : {xpub.serialize()}")
    leaked = hdwallet.derive_child(account, 5)
    recovered = hdwallet.recover_parent_private_key(xpub, leaked.key, 5)
    print(f"matches the real parent : {recovered == account.key}")
    try:
        hdwallet.recover_parent_private_key(xpub, 1, hdwallet.HARDENED_OFFSET + 5)
    except ValueError as exc:
        print(f"hardened child          : refused ({exc})")
    watch = hdwallet.derive_child(xpub, 0).public_point == hdwallet.derive_child(account, 0).public_point
    print(f"watch-only derivation: xpub-derived address matches : {watch}")


def demo_pqc() -> None:
    _title("Part D -- Post-quantum cost")
    print(pqc.comparison_table())
    print()
    print(pqc.exposure_report())


DEMOS = {"curve": demo_curve, "ecdsa": demo_ecdsa, "wallet": demo_wallet, "pqc": demo_pqc}


def main(argv: list[str]) -> int:
    if not argv:
        for fn in DEMOS.values():
            fn()
        return 0
    if argv[0] not in DEMOS:
        print(__doc__)
        return 2
    DEMOS[argv[0]]()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
