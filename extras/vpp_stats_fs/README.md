# VPP stats segment FUSE filesystem

The statfs binary allows to create a FUSE filesystem to expose and to browse the stats segment.
Is is leaned on the Go-FUSE library and requires Go-VPP stats bindings to work.

The binary mounts a filesystem on the local machine whith the data from the stats segments.
The counters can be opened and read as files (e.g. in a Unix shell).
Note that the value of a counter is determined when the corresponding file is opened (as for /proc/interrupts).

Directories regularly update their contents so that new counters get added to the filesystem.

## Prerequisites (for building)

**GoVPP** library (master branch)
**Go-FUSE** library
vpp, vppapi

## Building

Here, we add the Go librairies before building the binary
```bash
go mod init stats_fs
go get git.fd.io/govpp.git@master
go get git.fd.io/govpp.git/adapter/statsclient@master
go get github.com/hanwen/go-fuse/v2
go build
```

## Usage

The basic usage is:
```bash
sudo ./statfs <MOUNT_POINT> &
```
**Options:**
 - debug \<true|false\> (default is false)
 - socket \<statSocket\> (default is /run/vpp/stats.sock)

## Browsing the filesystem

You can browse the filesystem as a regular user.
Example:

```bash
cd /path/to/mountpoint
cd sys/node
ls -al
cat names
```

## Unmounting the file system

You can unmount the filesystem with the fusermount command.
```bash
sudo fusermount -uz /path/to/mountpoint
```