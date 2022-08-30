#!/bin/sh

# config
# --------------------------

G=8
# G=0

PSYQ=4.4
# PSYQ=4.3

# --------------------------

if [ -z "$PSYQ_SDK" ]; then
    echo "PSYQ_SDK not set"
    exit 1
fi

INPUT="$1"
OUTPUT="$3"
ASM="${INPUT}.asm"

CPPPSX="cpp -nostdinc -undef -D__GNUC__=2 -D__OPTIMIZE__ -lang-c -Dmips  \
    -D__mips__ -D__mips -Dpsx -D__psx__ -D__psx -D_PSYQ -D__EXTENSIONS__ \
    -D_MIPSEL -D__CHAR_UNSIGNED__ -D_LANGUAGE_C -DLANGUAGE_C ${INPUT}"
CC1PSX="wine ${PSYQ_SDK}/psyq_${PSYQ}/bin/CC1PSX.EXE -quiet -O2 -G${G} -g0 -o ${ASM}"
ASPSX="wibo ${PSYQ_SDK}/psyq_${PSYQ}/bin/aspsx.exe -q -G${G} -g0 $ASM -o ${OUTPUT}"

$($CPPPSX | $CC1PSX)
$($ASPSX)

rm "$ASM"
