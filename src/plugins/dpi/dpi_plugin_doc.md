# Hyperscan plugin for VPP    {#dpi_plugin_doc}

## Overview

Hyperscan is a high-performance multiple regex matching library.
Please refer to below for details:
http://intel.github.io/dpi/dev-reference/

This plugin provides Hyperscan support on VPP, so can implement DPI/IPS/IDS etc.

## Hyperscan Installation on Ubuntu
1).Install binary prerequisites
apt-get install cmake ragel
apt-get install libboost-dev
apt-get install python-dev libbz2-dev

2).Download Hyperscan sources
wget https://github.com/intel/dpi/archive/v4.7.0.tar.gz
tar -xf v4.7.0.tar.gz

3).Download boost headers
wget https://dl.bintray.com/boostorg/release/1.67.0/source/boost_1_67_0.tar.gz
tar -xf boost_1_67_0.tar.gz
cp -r boost_1_67_0/boost dpi-4.7.0/include

4).Build and install Hyperscan shared library.
   Just follow the instruction from here. Compilation can take a long time.
cd dpi-4.7.0
mkdir build
cd build
cmake -DBUILD_SHARED_LIBS=true ..
make
make install


## Configuration

### Configure ip_dpi_bypass

The dpi plugin need to redirct packets to dpi-scan graph node:

	hs set interface ip4 dpi-bypass <interface> [del]

interface: the interface that you want to enable dpi.


### Configure and compile Hyperscan

The dpi plugin need to configure regular matching patterns
and compile them into database.

    hs compile mode [block|stream] flags [imsHV8W\r] \
               patterns <patterns>

mode: Compiler mode.
      HS_MODE_BLOCK or HS_MODE_STREAM or HS_MODE_VECTORED must be supplied.
flags: Flags which modify the behaviour of the expression.
       Multiple flags may be used by ORing them together.
patterns: The NULL-terminated expression to parse

