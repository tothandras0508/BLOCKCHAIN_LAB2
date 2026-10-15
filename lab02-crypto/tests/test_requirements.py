"""Tests for the "Done when" column of the [STUDENT TASK] table that the
provided suite (test_crypto.py, kept unchanged) does not already cover."""

from __future__ import annotations

import hashlib
import secrets

import pytest

from crypto_lab import address, ecdsa, hdwallet
from crypto_lab.curve import (
    G,
    INFINITY,
    N,
    P,
    Point,
    add,
    deserialize_public_key,
    double,
    negate,
    private_to_public,
    scalar_mul,
    scalar_mul_ladder,
    serialize_public_key,
)

PRIV = 0xC0FFEE00BADC0DE1234567890ABCDEF1122334455667788990AABBCCDDEEFF00
TEST_MNEMONIC = "abandon " * 11 + "about"

# ---------------------------------------------------------------- Req 1 -- #


def test_req1_n_minus_one_times_g_plus_g_is_identity() -> None:
    assert add(scalar_mul(N - 1, G), G).is_infinity


def test_req1_identity_and_inverse_for_random_points() -> None:
    for _ in range(5):
        pt = private_to_public(secrets.randbelow(N - 1) + 1)
        assert add(pt, INFINITY) == pt
        assert add(pt, negate(pt)).is_infinity


def test_req1_doubling_a_point_with_y_zero_gives_identity() -> None:
    # secp256k1 has no point of order 2, so a synthetic one is the only way to hit
    # this branch; the vertical tangent must give O regardless.
    assert double(Point(5, 0)).is_infinity


def test_req1_ladder_agrees_on_at_least_20_random_scalars() -> None:
    for _ in range(20):
        k = secrets.randbelow(N - 1) + 1
        assert scalar_mul(k, G) == scalar_mul_ladder(k, G)
    for k in (1, 2, 3, N - 1, N):  # edges
        assert scalar_mul(k, G) == scalar_mul_ladder(k, G)


# ---------------------------------------------------------------- Req 2 -- #


def test_req2_compressed_and_uncompressed_g() -> None:
    comp = serialize_public_key(G, compressed=True)
    assert comp.hex() == "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    assert len(comp) == 33
    unc = serialize_public_key(G, compressed=False)
    assert unc[0] == 0x04 and len(unc) == 65
    assert deserialize_public_key(comp) == G == deserialize_public_key(unc)


def test_req2_roundtrip_random_points_both_forms() -> None:
    for _ in range(10):
        pt = private_to_public(secrets.randbelow(N - 1) + 1)
        for compressed in (True, False):
            assert deserialize_public_key(serialize_public_key(pt, compressed)) == pt


def test_req2_off_curve_uncompressed_point_is_rejected() -> None:
    bad = b"\x04" + G.x.to_bytes(32, "big") + ((G.y + 1) % P).to_bytes(32, "big")
    with pytest.raises(ValueError):
        deserialize_public_key(bad)


# ---------------------------------------------------------------- Req 3 -- #


def test_req3_rfc6979_published_vector() -> None:
    """Widely used secp256k1/RFC 6979 vector: d = 1, m = "Satoshi Nakamoto"."""
    h = hashlib.sha256(b"Satoshi Nakamoto").digest()
    assert ecdsa.rfc6979_nonce(1, h) == 0x8F8A276C19F4149656B280621E358CCE24F5F52542772691EE69063B74F15D15
    sig = ecdsa.sign(1, h)
    assert sig.r == 0x934B1EA10A4B3C1757E2B0C017D0B6143CE3C9A7E6A4A49860D7A6AB210EE3D8
    assert sig.s == 0x2442CE9D2B916064108014783E923EC36B49743E2FFA1C4496F01A512AAFD9E5


def test_req3_every_signature_low_s_and_recoverable() -> None:
    for i in range(30):
        d = secrets.randbelow(N - 1) + 1
        h = hashlib.sha256(f"r3-{i}".encode()).digest()
        sig = ecdsa.sign(d, h)
        assert sig.s <= N // 2
        assert 1 <= ecdsa.rfc6979_nonce(d, h) < N
        assert ecdsa.recover_public_key(h, sig) == private_to_public(d)
        # a wrong recovery id must not silently give the right key
        wrong = ecdsa.Signature(sig.r, sig.s, sig.recovery_id ^ 1)
        assert ecdsa.recover_public_key(h, wrong) != private_to_public(d)


# ---------------------------------------------------------------- Req 4 -- #


@pytest.mark.parametrize(
    ("flip1", "flip2"), [(False, False), (True, False), (False, True), (True, True)]
)
def test_req4_nonce_reuse_in_all_four_sign_combinations(flip1: bool, flip2: bool) -> None:
    h1 = hashlib.sha256(b"first").digest()
    h2 = hashlib.sha256(b"second").digest()
    for _ in range(3):
        k = secrets.randbelow(N - 1) + 1
        a = ecdsa.sign(PRIV, h1, nonce=k, enforce_low_s=False)
        b = ecdsa.sign(PRIV, h2, nonce=k, enforce_low_s=False)
        s1 = N - a.s if flip1 else a.s
        s2 = N - b.s if flip2 else b.s
        assert ecdsa.recover_private_key_from_nonce_reuse(a.r, s1, h1, s2, h2) == PRIV


# ---------------------------------------------------------------- Req 5 -- #


def test_req5_seed_vector_without_passphrase() -> None:
    assert hdwallet.mnemonic_to_seed(TEST_MNEMONIC).hex().startswith(
        "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    )


def test_req5_bip32_test_vector_1_master() -> None:
    """BIP-32 test vector 1, chain m."""
    root = hdwallet.master_key_from_seed(bytes.fromhex("000102030405060708090a0b0c0d0e0f"))
    assert root.serialize() == (
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    )
    assert root.neuter().serialize() == (
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"
    )


def test_req5_watch_only_address_equals_private_address() -> None:
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    account = hdwallet.derive_path(root, "m/44'/60'/0'/0")
    for i in range(3):
        via_xpub = address.public_key_to_address(hdwallet.derive_child(account.neuter(), i).public_point)
        via_xprv = address.public_key_to_address(hdwallet.derive_child(account, i).public_point)
        assert via_xpub == via_xprv


def test_req5_xpub_cannot_derive_hardened_path() -> None:
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    with pytest.raises(ValueError, match="hardened"):
        hdwallet.derive_path(root.neuter(), "m/44'")


# ---------------------------------------------------------------- Req 6 -- #


def test_req6_recovery_for_several_indices() -> None:
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    account = hdwallet.derive_path(root, "m/44'/60'/0'/0")
    for i in (0, 3, 1000):
        child = hdwallet.derive_child(account, i)
        assert hdwallet.recover_parent_private_key(account.neuter(), child.key, i) == account.key


def test_req6_hardened_child_is_refused() -> None:
    """Our implementation REFUSES (raises) rather than returning a wrong key."""
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    account = hdwallet.derive_path(root, "m/44'/60'/0'")
    hardened_index = hdwallet.HARDENED_OFFSET + 0
    child = hdwallet.derive_child(account, hardened_index)
    with pytest.raises(ValueError, match="immune"):
        hdwallet.recover_parent_private_key(account.neuter(), child.key, hardened_index)


def test_req6_and_naive_formula_gives_wrong_key_for_hardened_child() -> None:
    """Even forcing the non-hardened formula on a hardened child yields garbage."""
    root = hdwallet.master_key_from_seed(hdwallet.mnemonic_to_seed(TEST_MNEMONIC))
    account = hdwallet.derive_path(root, "m/44'/60'/0'")
    child = hdwallet.derive_child(account, hdwallet.HARDENED_OFFSET)
    with pytest.raises(ValueError, match="does not belong"):
        # pretend it was index 0: I_L is computed from the public data, so it is wrong
        hdwallet.recover_parent_private_key(account.neuter(), child.key, 0)


# ---------------------------------------------------------------- Req 7 -- #


def test_req7_keccak_empty_and_differs_from_sha3() -> None:
    k = address.keccak256(b"").hex()
    assert k == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    assert k != hashlib.sha3_256(b"").hexdigest()


def test_req7_demo_key_address() -> None:
    assert address.address_from_private_key(PRIV) == "0xa0f598084F711360A38D861F8Fb2100949170C09"
