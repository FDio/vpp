#!/bin/bash
cd boringssl
cmake -GNinja -B build
ninja -C build
