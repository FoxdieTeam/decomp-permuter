@echo off

rem config
rem --------------------------

set G=8

set PSYQ=4.4

rem if this is not set in your env vars, uncomment this and set it here
rem (this is relative to decomp-permuter)
rem set PSYQ_SDK=..\..\psyq_sdk

rem --------------------------

if not defined PSYQ_SDK (
    echo PSYQ_SDK not set
    exit 1
)

set INPUT=%1
set OUTPUT=%3
set ASM=%3.asm

set CPPPSX=%PSYQ_SDK%\psyq_%PSYQ%\bin\CPPPSX.EXE -undef -D__GNUC__=2   ^
    -D__OPTIMIZE__ -lang-c -Dmips -D__mips__ -D__mips -Dpsx -D__psx__ ^
    -D__psx -D_PSYQ -D__EXTENSIONS__ -D_MIPSEL -D__CHAR_UNSIGNED__    ^
    -D_LANGUAGE_C -DLANGUAGE_C %INPUT%
set CC1PSX=%PSYQ_SDK%\psyq_%PSYQ%\bin\CC1PSX.EXE -quiet -O2 -G%G% -g0 -o %ASM%
set ASPSX=%PSYQ_SDK%\psyq_%PSYQ%\bin\aspsx.exe -q -G%G% -g0 %ASM% -o %OUTPUT%

%CPPPSX% | %CC1PSX%
%ASPSX%

del %ASM%
