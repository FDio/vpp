# Marvel device plugin for VPP    {#marvel_plugin_doc}

##Overview
This plugins provides native device support for Marvell PP2 network device, by use of Marvel Usermode SDK ([MUSDK][1]).
Code is developed and tested on [MACCHIATObin][2] board.

##Prerequisites
Plugins depends on installed MUSDK and Marvell provided linux [kernel][3] with MUSDK provided kernel patches (see `patches/linux` in musdk repo and relevant documentation.
Kernel version used: **4.14.22 armada-18.09.3**
MUSDK version used: **armada-18.09.3**
Following kernel modules from MUSDK must be loaded for plugin to work:
* `musdk_cma.ko`
* `mv_pp_uio.ko`

##Musdk 18.09.3 compilation steps

```
./bootstrap
./configure --prefix=/opt/vpp/external/aarch64/ CFLAGS="-Wno-error=unused-result -g -fPIC" --enable-shared=no
sed -i -e  's/marvell,mv-pp-uio/generic-uio/' modules/pp2/mv_pp_uio.c
sed -i -e  's/O_CREAT/O_CREAT, S_IRUSR | S_IWUSR/' src/lib/file_utils.c
make
sudo make install
```

## Usage
### Interface Cration
Interfaces are dynamically created with following CLI:
```
create interface marvell pp2 name eth0
set interface state mv-ppio-0/0 up
```

Where `eth0` is linux interface name  and `mv-ppio-X/Y` is VPP interface name where X is PP2 device ID and Y is PPIO ID
Interface needs to be assigned to MUSDK in FDT configuration and linux interface state must be up.

### Interface Deletion
Interface can be deleted with following CLI:
```
delete interface marvell pp2 <interface name>
```


### Interface Statistics
Interface statistics can be displayed with `sh hardware-interface mv-ppio0/0`
command.

### Interaction with DPDK plugin
This plugin doesn't have any dependency on DPDK or DPDK plugin but it can
work with DPDK plugin enabled or disabled. It is observed that performace is
better around 30% when DPDK plugin is disabled, as DPDK plugin registers 
own buffer manager, which needs to deal with additional metadata in each packet.

DPKD plugin can be disabled by adding following config to the startup.conf.

```
plugins {
  dpdk_plugin.so { disable }
}
```


[1]: https://github.com/MarvellEmbeddedProcessors/musdk-marvell
[2]: http://macchiatobin.net
[3]: https://github.com/MarvellEmbeddedProcessors/linux-marvell
