#!/usr/bin/env bash
# nHash full test + hardening suite (Linux). Builds the test tools with g++ (-maes) and runs
# them. For the deep sanitizer runs use src/run_fuzz.sh (ASan+UBSan) and src/tsan_run.sh (TSan).
set -u
cd "$(dirname "$0")" || exit 1
CORE="src/corehash.cpp src/block.cpp src/blockchain.cpp src/utxo.cpp src/ed25519.cpp src/wallet.cpp src/storage.cpp src/params.cpp"
G="g++ -O2 -std=c++17 -maes -pthread"
mkdir -p build
echo "building test tools..."
$G -o build/ed25519_test     src/ed25519.cpp src/ed25519_test.cpp
$G -o build/bip39_test       src/bip39.cpp src/bip39_test.cpp
$G -o build/corehash_vectors $CORE src/corehash_vectors.cpp
$G -o build/reorg_test       $CORE src/reorg_test.cpp
$G -o build/demo_tx          $CORE src/tx_demo.cpp
$G -o build/block_template_test $CORE src/block_template_test.cpp
$G -o build/corehash_analyze $CORE src/corehash_analyze.cpp
$G -o build/corehash_audit   $CORE src/corehash_audit.cpp
$G -o build/corehash_battery $CORE src/corehash_battery.cpp
$G -o build/fuzz             $CORE src/fuzz.cpp

pass=0; fail=0
run() { if "$@" >/tmp/nht.out 2>&1; then return 0; else return 1; fi; }
chk() { local name="$1"; shift; if "$@"; then echo "  [PASS] $name"; pass=$((pass+1)); else echo "  [FAIL] $name"; fail=$((fail+1)); fi; }

echo "============================================"
echo "  nHash test suite"
echo "============================================"
chk "ed25519 signatures (RFC 8032)" bash -c "build/ed25519_test 2>/dev/null | grep -q 'ALL TESTS PASSED'"
chk "BIP39 mnemonic (vectors+roundtrip)" bash -c "build/bip39_test 2>/dev/null | grep -q 'ALL TESTS PASSED'"
chk "CoreHash v2 test vectors"      bash -c "build/corehash_vectors 2>/dev/null | grep -q a57de1ac579e73be1b2663623ae406d2cd9cd2801c4d08cd257cc0b9766d5774"
chk "reorg / consensus / rollback"  bash -c "build/reorg_test >/dev/null 2>&1"
chk "transactions: double-spend+maturity" bash -c "build/demo_tx 2>/dev/null | grep -q 're-validation: OK'"
chk "block template: fee priority + size cap" bash -c "build/block_template_test 2>/dev/null | grep -q 'ALL TESTS PASSED'"
chk "avalanche + output uniformity" bash -c "build/corehash_analyze 300 1000 2>/dev/null | grep -q PASS"
chk "scratchpad coverage + diffusion" bash -c "build/corehash_audit 4 100 2>/dev/null | grep -q PASS"
chk "statistical randomness battery" bash -c "build/corehash_battery 1 2>/dev/null | grep -q 'indistinguishable from random'"
chk "fuzzer 50k iters, no crash"    bash -c "build/fuzz 50000 7 >/dev/null 2>&1"
echo "--------------------------------------------"
echo "  Result: $pass passed, $fail failed"
echo "============================================"
[ "$fail" -eq 0 ]
