# Instructions for fuzzing
## Setup
- clone https://github.com/mirrorer/afl somewhere and apply afl.patch on it (patch -p1) (the patch applies to commit 2fb5a3482ec27b593c57258baae7089ebdc89043)
- do the same for https://github.com/RUB-SysSec/ijon.git (the patch applies to commit 56ebfe34709dd93f5da7871624ce6eadacc3ae4c)
- set the variables aflpath, ijonpath and vpppath at the beginning of run.sh
- Build the fuzzers:
  - ./run.sh fuzzmake afl
  - ./run.sh fuzzmake ijon
## Use
- use ./run.sh vppmake ... to build VPP with instrumentation from a fuzzer
- use ./run.sh fuzz ... to run fuzzing
