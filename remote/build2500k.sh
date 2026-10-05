#!/usr/bin/env bash
cd /tmp/corehash || exit 1
CORE="src/corehash.cpp src/block.cpp src/blockchain.cpp src/utxo.cpp src/ed25519.cpp src/wallet.cpp src/storage.cpp src/params.cpp"
set -e
g++ -O2 -std=c++17 -pthread -o corehash        $CORE src/cli.cpp && echo CLI_OK
g++ -O2 -std=c++17 -pthread -o corehashd       $CORE src/net.cpp src/daemon.cpp src/daemon_main.cpp && echo DAEMON_OK
g++ -O2 -std=c++17 -pthread -o corehash-miner  src/corehash.cpp src/block.cpp src/net.cpp src/miner.cpp src/miner_main.cpp && echo MINER_OK
g++ -O2 -std=c++17 -pthread -o corehash-pool   src/corehash.cpp src/block.cpp src/net.cpp src/wallet.cpp src/ed25519.cpp src/params.cpp src/pool.cpp && echo POOL_OK
g++ -O2 -std=c++17 -pthread -o coremine        $CORE src/net.cpp src/daemon.cpp src/miner.cpp src/coremine.cpp && echo COREMINE_OK
ls -la corehash corehashd corehash-miner corehash-pool coremine
