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

### 1.1 Download and patch

```
git clone https://github.com/google/packetdrill.git packetdrill
cd packetdrill
git checkout -b v2.0 packetdrill-v2.0
cd ../
git am patcketdrill-patches/v2.0
```

### 3.2 Compile

```
pushd packetdrill/gtests/net/packetdrill
make -f Makefile.Linux
popd
```
NOTE:  Compiling packetdrill may need to install some extra packages, such as flex & bison

## 2. Build VPP adpter shared object (*.so) file

```
cd vpp_adapter
make
cd ../
```
## 3. Run the script

### 3.1 Create veth pair
```
bash script.sh createVeth
```
### 3.2 Startup VPP
```
bash script.sh startVpp
```
### 3.3 Run testcase
```
bash script.sh runTest
```

### 3.4 Stop VPP and delete veth pair

```
bash script.sh stopVpp
```

### 4. Notes

Not all packetdrill cases are supported now, this is mainly due to the following reasons:

1. Some TCP/IP socket options are not supported.
2. The test results of some cases are obtained by observing the kernel.
3. VPP differs from the kernel in some implementations, eg. epoll.
