# VPP Top Installation {#vpp_top_doc}

[VPPTop]((https://github.com/PANTHEONtech/vpptop)) is a real-time data viewer for VPP interfaces and metrics displayed in dynamic terminal user interface, written in GO.

Following make targets are available:

**install** downloads and installs VPPTop including all external dependencies, binary API generator and latest version of GO. Running `make install-dep` (from the VPP top-level Makefile)
is recommended.

**cleanup** removes VPPTop repository from the target directory (/build-root/vpptop)

**start** runs the VPPTop if installed

**help** shows information about available commands

The VPPTop is installed to be compatible with the given VPP version and may not work with other versions with different API. In that case, the VPPTop has to be re-installed.

### GO variables management

The installer depends on Golang environment variables GOROOT (for the GO installation) and GOPATH (for other binaries). Those variables are read from the environment and set to following values if not found:

GOROOT=/root/.go/
GOPATH=/root/go/

If you have the GO already installed and have to run the installer with `sudo`, use the `-E` switch to provide those variables to the installer.
