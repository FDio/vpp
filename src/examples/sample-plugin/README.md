# VPP Sample Plugin

The sample plugin implements a single node which exchanges packets' source and
destination ethernet addresses for all packets received on a given interface
and sends the packet back to the interface.

### Compilation

In the sample-plugin directory, execute:
```bash
libtoolize
aclocal
autoconf
automake --add-missing
```

If VPP is installed on your system, use:
```bash
./configure
make
sudo make install
```

If VPP is only compiled for development in /path/to/vpp/, use:
```bash
./configure VPP_DIR=/path/to/vpp/
make
sudo make install
```

The ./configure script also accepts --enable-debug in order to compile with
debug flags and logs.
