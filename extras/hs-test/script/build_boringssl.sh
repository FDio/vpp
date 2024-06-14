#!/bin/bash
cd boringssl || exit 1
cmake -GNinja -B build
ninja -C build
