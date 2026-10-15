"""Post-quantum cost: signature sizes, transaction sizes, throughput, exposure.

Model: a single-input, single-output transaction whose non-signature overhead
is fixed (outpoint, amounts, scripts, framing); 1 MB of transactions per block,
one block every 10 minutes.
"""

from __future__ import annotations

from dataclasses import dataclass

TX_OVERHEAD_BYTES = 110  # everything in the transaction except pk + sig
BLOCK_BYTES = 1_000_000
BLOCK_INTERVAL_S = 600


@dataclass(frozen=True)
class Scheme:
    label: str
    quantum_safe: bool
    pk_bytes: int
    sig_bytes: int
    standard: str

    @property
    def tx_bytes(self) -> int:
        return TX_OVERHEAD_BYTES + self.pk_bytes + self.sig_bytes


SCHEMES: dict[str, Scheme] = {
    "ecdsa": Scheme("ECDSA (secp256k1)", False, 33, 72, "SEC 2 / DER"),
    "schnorr": Scheme("Schnorr (BIP-340)", False, 32, 64, "BIP-340"),
    "ml-dsa-44": Scheme("ML-DSA-44", True, 1312, 2420, "FIPS 204"),
    "ml-dsa-65": Scheme("ML-DSA-65", True, 1952, 3309, "FIPS 204"),
    "slh-dsa-128s": Scheme("SLH-DSA-128s", True, 32, 7856, "FIPS 205"),
    "fn-dsa-512": Scheme("FN-DSA-512", True, 897, 666, "FIPS 206"),
}


def size_multiplier(name: str) -> float:
    return SCHEMES[name].tx_bytes / SCHEMES["ecdsa"].tx_bytes


def throughput_tps(name: str) -> float:
    return BLOCK_BYTES / SCHEMES[name].tx_bytes / BLOCK_INTERVAL_S


def comparison_table() -> str:
    header = f"{'Scheme':<20}{'PQ':<5}{'pk (B)':>8}{'sig (B)':>9}{'tx (B)':>8}{'x ECDSA':>9}{'tps':>7}"
    lines = [header, "-" * len(header)]
    for name, s in SCHEMES.items():
        lines.append(
            f"{s.label:<20}{'yes' if s.quantum_safe else 'no':<5}{s.pk_bytes:>8}{s.sig_bytes:>9}"
            f"{s.tx_bytes:>8}{size_multiplier(name):>8.1f}x{throughput_tps(name):>7.2f}"
        )
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Exposure: Shor needs the public key. What does the chain reveal?
# --------------------------------------------------------------------------- #

PROTECTED = "PROTECTED (for now)"
EXPOSED = "EXPOSED"


@dataclass(frozen=True)
class Exposure:
    status: str
    reason: str


EXPOSURE: dict[str, Exposure] = {
    "p2pkh_unspent": Exposure(
        PROTECTED, "only HASH160(pubkey) is on chain; Shor has no public key to attack"
    ),
    "p2pk": Exposure(EXPOSED, "the public key itself is in the output script (early coinbase)"),
    "reused_address": Exposure(
        EXPOSED, "a previous spend revealed the public key; remaining funds sit behind it"
    ),
    "mempool_transaction": Exposure(
        EXPOSED + " (briefly)",
        "the spend reveals the key; a fast attacker could race it before confirmation",
    ),
    "ethereum_any_active": Exposure(
        EXPOSED, "ecrecover derives the public key from any signature the account has sent"
    ),
}


def exposure_report() -> str:
    lines = ["Exposure to a cryptographically relevant quantum computer", ""]
    width = max(map(len, EXPOSURE))
    for name, e in EXPOSURE.items():
        lines.append(f"  {name:<{width}}  {e.status:<22}  {e.reason}")
    lines += [
        "",
        "Harvest Now, Decrypt Later: the ledger is permanent and public. Every public key",
        "published today can be collected now and broken whenever the hardware exists,",
        "so the deadline is set by (secure lifetime + migration time), not by a forecast.",
    ]
    return "\n".join(lines)


def migration_is_overdue(secure_years: float, migration_years: float, years_to_crqc: float) -> bool:
    """Mosca's inequality: act now if x + y > z."""
    return secure_years + migration_years > years_to_crqc
