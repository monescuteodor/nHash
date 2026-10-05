@echo off
REM Build the nHash coin binaries into build\.
setlocal
set VCVARS="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
call %VCVARS% >nul 2>&1
if not exist build mkdir build
set CORE=src\corehash.cpp src\block.cpp src\blockchain.cpp src\utxo.cpp src\ed25519.cpp src\wallet.cpp src\storage.cpp src\params.cpp
rc /nologo /fo build\wallet.res src\wallet.rc
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\nhash-wallet.exe /Fo:build\ %CORE% src\net.cpp src\cli.cpp src\bip39.cpp build\wallet.res
if not %errorlevel%==0 (echo WALLET BUILD FAILED & endlocal & exit /b 1)
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\nhashd.exe /Fo:build\ %CORE% src\net.cpp src\daemon.cpp src\daemon_main.cpp
if not %errorlevel%==0 (echo DAEMON BUILD FAILED & endlocal & exit /b 1)
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\nhash-miner.exe /Fo:build\ src\corehash.cpp src\block.cpp src\net.cpp src\miner.cpp src\miner_main.cpp
if not %errorlevel%==0 (echo MINER BUILD FAILED & endlocal & exit /b 1)
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\nhash-pool.exe /Fo:build\ src\corehash.cpp src\block.cpp src\net.cpp src\wallet.cpp src\ed25519.cpp src\params.cpp src\pool.cpp
if not %errorlevel%==0 (echo POOL BUILD FAILED & endlocal & exit /b 1)
rc /nologo /fo build\nhash.res src\coremine.rc
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\nhash.exe /Fo:build\ %CORE% src\net.cpp src\daemon.cpp src\miner.cpp src\coremine.cpp build\nhash.res
if not %errorlevel%==0 (echo NHASH BUILD FAILED & endlocal & exit /b 1)
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\nhash-pay.exe /Fo:build\ src\corehash.cpp src\block.cpp src\ed25519.cpp src\wallet.cpp src\net.cpp src\pay.cpp
if not %errorlevel%==0 (echo PAY BUILD FAILED & endlocal & exit /b 1)
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\nhash-web.exe /Fo:build\ src\net.cpp src\params.cpp src\web.cpp
if not %errorlevel%==0 (echo WEB BUILD FAILED & endlocal & exit /b 1)
REM --- dev demos / tests ---
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\demo_node.exe /Fo:build\ %CORE% src\node_demo.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\demo_tx.exe /Fo:build\ %CORE% src\tx_demo.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\ed25519_test.exe /Fo:build\ src\ed25519.cpp src\ed25519_test.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\bip39_test.exe /Fo:build\ src\bip39.cpp src\bip39_test.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\block_template_test.exe /Fo:build\ %CORE% src\block_template_test.cpp >nul
REM --- PoW benchmarks (avx2_attack needs AVX2) ---
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\corehash_bench.exe /Fo:build\ src\corehash_bench.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /arch:AVX2 /Fe:build\avx2_attack.exe /Fo:build\ src\corehash.cpp src\avx2_attack.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\latency_test.exe /Fo:build\ src\corehash.cpp src\latency_test.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /arch:AVX512 /Fe:build\avx512_attack.exe /Fo:build\ src\corehash.cpp src\avx512_attack.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\corehash_analyze.exe /Fo:build\ src\corehash.cpp src\corehash_analyze.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\corehash_audit.exe /Fo:build\ src\corehash.cpp src\corehash_audit.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\corehash_battery.exe /Fo:build\ src\corehash.cpp src\corehash_battery.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\corehash_vectors.exe /Fo:build\ src\corehash.cpp src\corehash_vectors.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\reorg_test.exe /Fo:build\ %CORE% src\reorg_test.cpp >nul
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\fuzz.exe /Fo:build\ %CORE% src\fuzz.cpp >nul
echo BUILD OK -^> nhash.exe, nhashd.exe, nhash-wallet.exe, nhash-miner.exe, nhash-pool.exe, nhash-pay.exe, nhash-web.exe
endlocal
