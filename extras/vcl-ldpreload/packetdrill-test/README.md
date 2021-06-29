# Introduction

Here, we use the Packetdrill from Google to verify the correctness
of the protocol stack. The framework of the entire system is shown
in the figure below.

**vpp\_adapter.so** in the figure is the protocol stack to be tested.

```
  +---------------+
  |  packetdrill  +
  +---------------+
          |
          | dlopen("vpp_adapter.so")
          |
  +---------------+  packet socket
  |  vpp_adapter  |--------------------------------+
  +---------------+                                |
          |                                        |
          | dlopen("vcl_ldpreload.so")             |
          |                                        |
  +---------------+                                |
  |      ldp      |                                |
  +---------------+                                |
  +---------------+                                |
  |               | vppvethout       vppvethhost   |
  |     VPP       +<------------------------------>+
  |               |
  +---------------+
```
# HowToUse
## 1. Download and build packetdrill
```
bash packetdrill.sh download
bash packetdrill.sh build
```
**NOTE**: Compiling packetdrill may need to install some extra packages, such as flex & bison
## 2. Run the script

Make sure iproute2 and iptables are installed.

### 2.1 Create veth pair
```
bash script.sh createVeth
```
### 2.2 Startup VPP
```
bash script.sh startVpp
```
### 2.3 Run testcase
```
bash script.sh runTest
```
### 2.4 Stop VPP and delete veth pair
```
bash script.sh stopVpp
```
## 3. Clean
```
bash packetdrill.sh clean
```
## 4. Notes

Not all packetdrill cases are supported now, this is mainly due to the following reasons:

1. Some TCP/IP socket options are not supported.
2. The test results of some cases are obtained by observing the kernel.
3. VPP differs from the kernel in some implementations, eg. epoll.
