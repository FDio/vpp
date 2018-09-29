# Netlink library for VPP plugins

This VPP package provides a rtnetlink-based library to be used by [VPP](http://fd.io/) plugins and other extensions.

## HowTo

The library and test plugin can be compiled by running the following commands from the plugin directory:
```bash
libtoolize
aclocal
autoconf
automake --add-missing
./configure
make
sudo make install
```

If VPP is not installed, but rather built in a separate directory, you can use the VPP_DIR 'configure' argument.

```bash
./configure VPP_DIR=<path/to/vpp/directory>
make
make install
```

You can also enable debug with the 'configure' --enable-debug option.



## Administrativa

### Current status

This library is currently looking for some maintainers.

### Objective

This effort intends to be a building block for a better integration of VPP into Linux.
It will evolve depending on the needs of the VPP community while focusing on the relations between VPP plugins and the Linux networking stack.

### Main contributors

Pierre Pfister - LF-ID:ppfister


