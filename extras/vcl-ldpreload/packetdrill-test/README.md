# Architecture

```
  +---------------+
  |  packetdrill  +--------------------------------+
  +---------------+                                |
  |     VCL       |                                |
  +---------------+                                |
          |                                        | inject & fetch packet
  +---------------+                                |
  |               | vppvethout       vppvethhost   |
  |     VPP       +<------------------------------>+
  |               |
  +---------------+
```
# HowTo

## 1. Build packetdrill 

NOTE:  Compiling packetdrill may need to install some extra packages, such as flex & bison

```
pushd packetdrill/gtests/net/packetdrill
make -f Makefile.Linux
popd
```

## 2. Config packetdrill runtime parameters

You can configure packetdrill runtime parameters at the beginning of the 'packetdrill_test.sh'.

## 3. Run the script

### 3.1 Create veth pair

```
bash packetdrill_test.sh createVeth
```

### 3.2 Startup VPP
```
bash packetdrill_test.sh startVpp
```

### 3.3 Run testcase
```
bash packetdrill_test.sh runTest
```

### 3.4 Stop VPP and delete veth pair

```
bash packetdrill_test.sh stopVpp
```

### 4. Notes

Not all packetdrill cases are supported now, this is mainly due to the following reasons:

1. Some TCP/IP socket options are not supported.
2. The test results of some cases are obtained by observing the kernel.
3. VPP differs from the kernel in some implementations, eg. epoll.
