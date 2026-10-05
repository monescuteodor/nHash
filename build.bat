@echo off
REM Build CoreHash benchmark with MSVC. Output: build\corehash_bench.exe
REM x64 / SSE2 baseline (no AVX) so the binary also runs on Sandy Bridge (i5-2500K).
setlocal
set VCVARS="C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvars64.bat"
if not exist %VCVARS% (
  echo vcvars64.bat not found - adjust the path in build.bat
  exit /b 1
)
call %VCVARS% >nul 2>&1
if not exist build mkdir build
cl /nologo /O2 /std:c++17 /EHsc /Fe:build\corehash_bench.exe /Fo:build\ src\corehash_bench.cpp
if %errorlevel%==0 (echo BUILD OK -^> build\corehash_bench.exe) else (echo BUILD FAILED)
endlocal
