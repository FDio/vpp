## Setup
- clone https://github.com/mirrorer/afl somewhere and apply afl.patch on it (patch -p1)
- optionally the same for IJON: https://github.com/RUB-SysSec/ijon with ijon.patch
- set the variables aflpath, ijonpath and vpppath at the beginning of run.sh
- also set the same variables in global_values.py (unfortunate code duplication due to an unfinished migration process from bash to Python).
