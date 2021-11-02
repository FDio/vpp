# Build RPM for openSUSE

## Introduction

This is to describe how to compile and create installable RPM packages for openSUSE leap.
In general you should visit [Pulling, Building,
Running, Hacking, Pushing](https://wiki.fd.io/view/VPP/Pulling,_Building,_Run
ning,_Hacking_and_Pushing_VPP_Code) which provides full description for other type of system (Ubuntu,Centos or Redhat).

## Get the VPP Sources

To get the VPP sources that are used to create the build, run the following commands:

```bash
# git clone https://gerrit.fd.io/r/vpp
# cd vpp
```

There are two ways to continue:

* Build by docker
* Build on your own openSUSE system

## Build by Docker

Run the following docker command:

```bash
docker build -f extras/rpm/opensuse/Dockerfile .
```

The packages now can be copied from the docker image and can be installed on openSUSE.
An example how to extend the Dockerfile to install vpp:

'''dockerfile
FROM opensuse/leap:${SUSE_VERSION} as vppinstall
COPY --from=vppbuild /vpp/build-root/*rpm /rpms/
RUN VPP_INSTALL_SKIP_SYSCTL=false zypper install --allow-unsigned-rpm -y --no-recommends /rpms/*.rpm;\
...
'''

## Build on openSUSE

### Build VPP Dependencies

Before building a VPP image, make sure there are no FD.io VPP or DPDK packages installed, by entering the following commands:

```bash
# rpm -ql vpp
package vpp is not installed
# rpm -ql dpdk
package dpdk is not installed

```

Run the following make command to install the dependencies for FD.io VPP.

```bash
make install-dep
```

Run the following make command to install the external dependencies for FD.io VPP.

```bash
ln -s /usr/bin/cmake /usr/bin/cmake3 # some thirdparty checking for cmake3 binary
make install-ext-dep
```

### Build RPM Packages

Create packages for openSUSE by running:

```bash
make pkg-rpm
```

Once the packages are built they can be found in the build-root directory.

```bash
# ls *.rpm
```

If the packages are built correctly, then this should be the corresponding output:

```bash
build-root/libvpp0-21.10-rc0~200_gb89ae9670.x86_64.rpm	    build-root/vpp-api-python-21.10-rc0~200_gb89ae9670.x86_64.rpm
build-root/vpp-21.10-rc0~200_gb89ae9670.x86_64.rpm	    build-root/vpp-devel-21.10-rc0~200_gb89ae9670.x86_64.rpm
build-root/vpp-api-lua-21.10-rc0~200_gb89ae9670.x86_64.rpm  build-root/vpp-plugins-21.10-rc0~200_gb89ae9670.x86_64.rpm
```
