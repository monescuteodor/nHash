<p align="center">
  <img src="nhash_logo.png" alt="nHash" width="96" height="96">
</p>

<h1 align="center">nHash</h1>

<p align="center">A from-scratch, CPU-mineable cryptocurrency built in C++ — no forks, no dependencies.</p>

---

nHash is a small, transparent UTXO cryptocurrency written from the ground up in C++17. Its
proof-of-work, **CoreHash v2**, is a memory-latency-bound, CPU-friendly algorithm designed to
resist ASICs and GPUs so that anyone with an ordinary PC can mine. The whole stack — consensus,
P2P networking, wallet, miner, mining pool, and block explorer — lives in this repository with no
third-party libraries.

> **Status:** experimental. The chain runs and is self-tested, but the CoreHash algorithm has
> **not** had external cryptanalysis or a professional audit. Treat it as a serious engineering
> project, not a store of value. Nothing here is financial advice.

## Highlights

- **CoreHash v2 PoW** — AES-NI scratchpad fill + a dual-lane, latency-bound mix (4 MiB working
  set). CPU-only by design; a data-dependent branch forces SIMD/GPU divergence.
- **Transparent UTXO ledger** — Bitcoin-style inputs/outputs with Ed25519 signatures.
- **Constant-time Ed25519** — branchless scalar multiply and reduction (RFC 8032 vectors pass).
- **LWMA-1 difficulty** retargeting, median-time-past and future-drift timestamp rules.
- **Fee-prioritized, size-bounded block templates** + a minimum-relay-fee mempool policy.
- **Checkpoints** so deep history can't be rewritten; **per-peer rate limiting + ban scoring**;
  **flow-controlled batched block sync**; self-dial avoidance.
- **BIP39** 24-word seed-phrase wallet backup (standard wordlist, cross-compatible).
- **Crash-safe storage** (atomic write + fsync + rename, corruption-tolerant load).
- A **block explorer** (charts, block/tx/address lookup, mempool, pool stats) and a **mining pool**.

## Economics

| Parameter | Value |
|---|---|
| Base unit | 1 nHash = 100,000,000 (1e8) |
| Block reward | 50 nHash, halving every 210,000 blocks |
| Max supply | 21,000,000 nHash |
| Target block time | 300 s (mainnet) |
| Coinbase maturity | 100 blocks |

## Build

**Requirements:** a 64-bit x86 CPU with **AES-NI** (anything since ~2011) and a C++17 compiler.

**Linux (g++):**
```bash
CORE="src/corehash.cpp src/block.cpp src/blockchain.cpp src/utxo.cpp src/ed25519.cpp src/wallet.cpp src/storage.cpp src/params.cpp"
G="g++ -O2 -std=c++17 -maes -pthread"
$G -o nhash-wallet $CORE src/net.cpp src/cli.cpp src/bip39.cpp
$G -o nhashd       $CORE src/net.cpp src/daemon.cpp src/daemon_main.cpp
$G -o nhash-miner  src/corehash.cpp src/block.cpp src/net.cpp src/miner.cpp src/miner_main.cpp
$G -o nhash-pool   src/corehash.cpp src/block.cpp src/net.cpp src/wallet.cpp src/ed25519.cpp src/params.cpp src/pool.cpp
$G -o nhash-web    src/net.cpp src/params.cpp src/web.cpp
```

**Windows (MSVC):** run `build_node.bat` from a Developer prompt — it produces `nhashd.exe`,
`nhash-wallet.exe`, `nhash-miner.exe`, `nhash-pool.exe`, `nhash-web.exe` in `build\`.

## Quick start

```bash
# 1) create a wallet and note your address (24-word backup: nhash-wallet backup me)
nhash-wallet newwallet me
nhash-wallet address me

# 2) run a node (listens on 9333; set COREHASH_NET=regtest for an isolated local chain)
nhashd 9333

# 3) mine to your address (solo against the node's RPC, or a pool's port)
nhash-miner <host:rpcport> <your-address-hex> [threads]
```

## Tests

```bash
./run-tests.sh      # Linux   (run-tests.bat on Windows)
```
Covers Ed25519 (RFC 8032), BIP39, CoreHash vectors, reorg/consensus, transactions,
block-template fee/size + checkpoints, PoW statistical audits, and a fuzzer.

## Repository layout

| Path | What |
|---|---|
| `src/` | All sources: consensus, PoW, net, wallet, miner, pool, explorer, tests |
| `SPEC.md` | Protocol & algorithm specification |
| `reference/`, `remote/` | A Python reference of CoreHash and host benchmark scripts |
| `build_node.bat`, `run-tests.*` | Build and test runners |

## License

MIT — see [LICENSE](LICENSE).
