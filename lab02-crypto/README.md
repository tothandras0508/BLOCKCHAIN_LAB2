# Lab 02 — secp256k1, ECDSA, HD wallets, post-quantum cost

Own implementation of the `[STUDENT TASK]` requirements 1–7. Only `pycryptodome`
(Keccak-256, RIPEMD-160) and the standard library (`hashlib`, `hmac`) are used; no
`ecdsa`, `coincurve`, `eth-keys` or `bip_utils`.

> **Teaching code only.** Not constant-time, not audited. Never protect value with it.

## Run

```bash
uv sync
uv run pytest                      # 86 tests: the 64-test spec unchanged + 22 requirement tests
uv run python -m crypto_lab        # all demos (curve | ecdsa | wallet | pqc)
```

## Layout

| Module | Requirement |
|---|---|
| `crypto_lab/curve.py` | 1 field & group law, Double-and-Add, Montgomery ladder · 2 SEC1 |
| `crypto_lab/ecdsa.py` | 3 sign / verify / RFC 6979 / low-s / recovery · 4 nonce-reuse attack |
| `crypto_lab/hdwallet.py` | 5 BIP-39/32/44, xpub derivation · 6 parent-key recovery |
| `crypto_lab/address.py` | 7 Keccak-256, Ethereum address, EIP-55 |
| `crypto_lab/pqc.py` | Part D size/throughput table, exposure report |
| `tests/test_crypto.py` | Provided specification (unchanged) |
| `tests/test_requirements.py` | Each "Done when" criterion not covered by the spec |

## Notes on design choices

- **Nonce reuse after low-s (req 4).** Flipping both `s` values is the same as `k → −k`
  and yields the same `d`, so only the relative sign matters. The attack tries `s2` and
  `n − s2` and keeps the candidate whose `k·G` reproduces `r`.
- **Recovery id (req 3).** Bit 0 is the parity of `R.y`, bit 1 flags `R.x ≥ n`. When low-s
  replaces `s` with `n − s`, `R` becomes `−R`, so bit 0 is flipped.
- **Hardened recovery (req 6).** `recover_parent_private_key` *refuses* hardened indices
  with `ValueError("... immune ...")`; a test also shows that forcing the non-hardened
  formula on a hardened child produces a key that fails the xpub check.
- **Known leak in this code.** `scalar_mul` branches on key bits (used only for public
  scalars in `verify`/recovery); `sign` and `private_to_public` use `scalar_mul_ladder`,
  but Python big-int arithmetic and `pow` are still variable-time, so a timing channel
  remains in both.
