# VPP stats segment FUSE filesystem  {#stats_fs_doc}

The statfs binary allows to create a FUSE filesystem to expose and to browse the stats segment.
It relies on the Go-FUSE library and requires Go-VPP stats bindings to work.

The binary mounts a filesystem on the local machine whith the data from the stats segments.
The counters can be opened and read as files (e.g. in a Unix shell).
Note that the value of a counter is determined when the corresponding file is opened (as for /proc/interrupts).

Directories update their contents on epoch changes so that new counters get added to the filesystem.

The script `install.sh` is responsible for buildiing and installing the filesystem.

## Usage

The local Makefile contains targets for all the possible intercations with the stats_f binary.

### Help
A basic help menu
```bash
make help
```

### Install
Building the binary
```bash
make install
```

### Start
Starts the filesystem. Requires a running VPP instance using the default socket /run/vpp/stats.sock.

May require a privileged user (sudo)
```bash
make start
```

### Stop
Stops and unmounts the filesystem if it is not busy.

May require a privileged user (sudo)
```bash
make stop
```

### Force unmount
Forces the unmount of the filesystem even if it is busy.

May require a privileged user (sudo)
```bash
make force-unmount
```

### Cleanup
Cleaning stats_fs binary.

May require a privileged user (sudo).
```bash
make clean
```

## Browsing the filesystem

The default mountpoint is /run/vpp/stats_fs_dir.
You can browse the filesystem as a regular user.
Example:

```bash
cd /run/vpp/stats_fs_dir
cd sys/node
ls -al
cat names
```

## Building and mounting the filesystem manually

For more modularity, you can build and mount the filesystem manually.

### Building
Inside the local directory, you can build the go binary:
```bash
go build
```

### Mounting
Then, ou can mount the filesystem with the local binary.

May require a privileged user (sudo).

The basic usage is:
```bash
./stats_fs <MOUNT_POINT>
```

**Options:**
 - debug \<true|false\> (default is false)
 - socket \<statSocket\> (default is /run/vpp/stats.sock) : VPP socket for stats


### Unmounting the file system

You can unmount the filesystem with the fusermount command.

May require a privileged user (sudo)

```bash
fusermount -u /path/to/mountpoint
```

To force the unmount even if the resource  is busy, add the -z option:
```bash
fusermount -uz /path/to/mountpoint
```
