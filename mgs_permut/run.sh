#!/bin/sh

cd ..
./permuter.py -j$(nproc) --no-context-output mgs_permut
