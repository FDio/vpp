# VPP Swanstrong Testing Recipe {#strongswan_test_doc}

Simple test framework for VPP and strongSwan scenarios.

## setup and run

`docker` is needed to run the tests.

Create `~/.vpp_sswan` file and set `VPP_BIN` and `VPPCTL` variables that points to vpp and vppctl binaries, like follows:
```
export VPP_BIN=/path/to/vpp
export VPPCTL=/path/to/vppctl
```

To run all test
```
./run.sh
```

or specific test
```
./test_responder.sh
```
