@echo off
REM nHash full test + hardening suite. Build first with build_node.bat, then run this.
setlocal enabledelayedexpansion
cd /d "%~dp0"
set PASS=0
set FAIL=0
echo ============================================
echo   nHash test suite
echo ============================================

build\ed25519_test.exe 2>nul | findstr /C:"ALL TESTS PASSED" >nul && (echo   [PASS] ed25519 signatures ^(RFC 8032^) & set /a PASS+=1) || (echo   [FAIL] ed25519 & set /a FAIL+=1)

build\bip39_test.exe 2>nul | findstr /C:"ALL TESTS PASSED" >nul && (echo   [PASS] BIP39 mnemonic ^(vectors + round-trip + checksum^) & set /a PASS+=1) || (echo   [FAIL] BIP39 mnemonic & set /a FAIL+=1)

build\corehash_vectors.exe 2>nul | findstr /C:"a57de1ac579e73be1b2663623ae406d2cd9cd2801c4d08cd257cc0b9766d5774" >nul && (echo   [PASS] CoreHash v2 test vectors & set /a PASS+=1) || (echo   [FAIL] CoreHash test vectors & set /a FAIL+=1)

build\reorg_test.exe >nul 2>&1 && (echo   [PASS] reorg / consensus / rollback & set /a PASS+=1) || (echo   [FAIL] reorg / consensus & set /a FAIL+=1)

build\demo_tx.exe 2>nul | findstr /C:"re-validation: OK" >nul && (echo   [PASS] transactions: double-spend + maturity & set /a PASS+=1) || (echo   [FAIL] transactions & set /a FAIL+=1)

build\block_template_test.exe 2>nul | findstr /C:"ALL TESTS PASSED" >nul && (echo   [PASS] block template: fee priority + size cap & set /a PASS+=1) || (echo   [FAIL] block template & set /a FAIL+=1)

build\corehash_analyze.exe 300 1000 2>nul | findstr /C:"PASS" >nul && (echo   [PASS] avalanche + output uniformity & set /a PASS+=1) || (echo   [FAIL] avalanche/uniformity & set /a FAIL+=1)

build\corehash_audit.exe 4 100 2>nul | findstr /C:"PASS" >nul && (echo   [PASS] scratchpad coverage + diffusion margin & set /a PASS+=1) || (echo   [FAIL] coverage/diffusion & set /a FAIL+=1)

build\corehash_battery.exe 1 2>nul | findstr /C:"indistinguishable from random" >nul && (echo   [PASS] statistical randomness battery & set /a PASS+=1) || (echo   [FAIL] statistical battery & set /a FAIL+=1)

build\fuzz.exe 50000 7 >nul 2>&1 && (echo   [PASS] fuzzer 50k iters, no crash & set /a PASS+=1) || (echo   [FAIL] fuzzer & set /a FAIL+=1)

echo --------------------------------------------
echo   Result: !PASS! passed, !FAIL! failed
echo   ^(deep runs: fuzz/TSan under sanitizers on Linux - see reference/ and src/^)
echo ============================================
endlocal
