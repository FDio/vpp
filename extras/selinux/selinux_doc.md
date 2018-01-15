# SELinux - VPP Custom SELinux Policy    {#selinux_doc}

## Overview

Security-enhanced Linux (SELinux) is a security feature in the Linux kernel. At
a very high level, SELinux implements mandatory access controls (MAC), as
opposed to discretionary access control (DAC) implemented in standard Linux. MAC
defines how processes can interact with other system components (Files,
Directories, Other Processes, Pipes, Sockets, Network Ports). Each system
component is assigned a label, and then the SELinux Policy defines which labels
and which actions on each label a process is able to perform. The VPP Custom
SELinux Policy defines the actions VPP is allowed to perform on which labels.

The VPP Custom SELinux Policy is intended to be installed on RPM based platforms
(tested on CentOS 7 and RHEL 7). Though SELinux can run on Debian platforms, it
typically is not and therefore is not currently being built for Debian.

The VPP Custom SELinux Policy does not enable or disable SELinux, only allows
VPP to run when SELinux is enabled. A fresh install of either Fedora, CentOS or
RHEL will have SELinux enabled by default. To determine if SELinux is enabled on
a given system and enable it if needed, run:

```
   $ getenforce
   Permissive

   $ sudo setenforce 1

   $ getenforce
   Enforcing
```

To make the change persistent, modify the following file to set
`SELINUX=enforcing`:

```
   $ sudo vi /etc/selinux/config
   :
   # This file controls the state of SELinux on the system.
   # SELINUX= can take one of these three values:
   #     enforcing - SELinux security policy is enforced.
   #     permissive - SELinux prints warnings instead of enforcing.
   #     disabled - No SELinux policy is loaded.
   SELINUX=enforcing
   :
```

## Installation

To install VPP, see the installation instructions on the VPP Wiki
(https://wiki.fd.io/view/VPP/Installing_VPP_binaries_from_packages). The VPP
Custom SELinux Policy is packaged in its own RPM starting in 18.04,
`vpp-selinux-policy-<VERSION>-<RELEASE>.rpm`. It is packaged and installed along
with the other VPP RPMs.

### Fresh Install of VPP

If VPP has never been installed on a system, then starting in 18.04, the VPP
Custom SELinux Policy will be installed with the other RPMs and all the system
components managed by VPP will be labeled properly.

### Fix SELinux Labels for VPP
In the case where the VPP Custom Policy is being installed for the first time,
either because VPP has been upgraded or packages were removed and then
reinstalled, several directories and files will not not be properly labeled. The
labels on these files will need to be fixed for VPP to run properly with SELinux
enabled. After the VPP Custom SELinux Policy is installed, run the following
commands to fix the labels. If VPP is already running, make sure to restart
VPP after the labels are fixed. This change is persistent for the life of the
file. Once the VPP Custom Policy is installed on the system, subsequent files
created by VPP will be labeled properly. This is only to fix files created by
VPP prior to the VPP Custom Policy being installed.

```
  $ sudo restorecon -Rv /etc/vpp/
  $ sudo restorecon -Rv /usr/lib/vpp_api_test_plugins/
  $ sudo restorecon -Rv /usr/lib/vpp_plugins/
  $ sudo restorecon -Rv /usr/share/vpp/
  $ sudo restorecon -Rv /var/run/vpp/

  $ sudo chcon -t vpp_tmp_t /tmp/vpp_*
  $ sudo chcon -t vpp_var_run_t /var/run/.vpp_*
```

**NOTE:** Because the VPP APIs allow custom filenames in certain scenarios, the
above commands may not handle all files. Inspect your system and correct any
files that are mislabeled. For example, to verify all VPP files in `/tmp/` are
labeled properly, run:

```
  $ sudo ls -alZ /tmp/
```

Any files not properly labeled with `vpp_tmp_t`, run:

```
  $ sudo chcon -t vpp_tmp_t /tmp/<filename>
```

## VPP Files

### Recommended Default File Directories

Documentation in the VPP Wiki (https://wiki.fd.io/view/VPP/) and doxygen
generated documentation have examples with files located in certain directories.
Some of the recommend file locations have been moved to satisfy SELinux. Most of
the documentation has been updated, but links to older documentation still exist
and there may have been instances that were missed. Use the file locations
described below to allow SELinux to properly label the given files.

File locations that have changed:
* VPP Debug CLI Script Files
* vHost Sockets
* VPP Log Files

#### VPP Debug CLI Script Files

The VPP Debug CLI, `vppctl`, allows a sequence of CLI commands to be read from a
file and executed. To avoid from having to grant VPP access to all of `/tmp/` and
possibly `/home/` sub-directories, it is recommended that any VPP Debug CLI script
files be placed in a common directory such as `/usr/share/vpp/`.

For example:
```
$ cat /usr/share/vpp/scripts/gigup.txt
set interface state GigabitEthernet0/8/0 up
set interface state GigabitEthernet0/9/0 up
```

To execute:
```
$ vppctl exec /usr/share/vpp/scripts/gigup.txt
```
Or
```
$ vppctl
    _______    _        _   _____  ___
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/

vpp# exec /usr/share/vpp/scripts/gigup.txt
vpp# quit

```

If the file is not labeled properly, you will see something similar to:
```
$ vppctl exec /home/<user>/dev/vpp/scripts/vppctl/gigup.txt
exec: failed to open `/home/<user>/dev/vpp/scripts/vppctl/gigup.txt': Permission denied

$ ls -alZ
drwxrwxr-x. <user> <user> unconfined_u:object_r:user_home_t:s0 .
drwxrwxr-x. <user> <user> unconfined_u:object_r:user_home_t:s0 ..
-rw-r--r--. <user> <user> unconfined_u:object_r:user_home_t:s0 gigup.txt
```

##### Original Documentation

Some of the original documentation showed script files being executed out of
`/tmp/`. Convenience also may lead to script files being placed in
`/home/<user>/` subdirectories. If a file is generated by the VPP process in
`/tmp/`, for example a trace file or pcap file, it will get properly labeled
with the SELinux label `vpp_tmp_t`. When a file is created, unless a rule is in
place for the process that created it, the file will inherit the SELinux label
of the parent directory. So if a user creates a file themselves in `/tmp/`, it
will get the SELinux label `tmp_t`, which VPP does not have permission to
access. Therefore it is recommended that script files are located as described
above.

#### vHost Sockets

vHost sockets are created from VPP perspective in either Server or Client mode.
In Server mode, the socket name is provided to VPP and VPP creates the socket.
In Client mode, the socket name is provided to VPP and the hypervisor creates
the socket. In order for VPP and hypervisor to share the socket resource with
SELinux enabled, a rule in the VPP Custom SELinux Policy has been added. This
rules allows processes with the `svirt_t` label (the hypervisor) to access
sockets with the `vpp_var_run_t` label. As such, when SELinux is enabled,
vHost sockets should be created in the directory `/var/run/vpp/`.

##### Original Documentation

Some of the original documentation showed vHost sockets being created in the
directory `/tmp/`. To work properly with SELinux enabled, vHost sockets should be
created as described above.

#### VPP Log Files

The VPP log file location is set by updating the `/etc/vpp/startup.conf` file:

```
vi /etc/vpp/startup.conf
unix {
:
  log /var/log/vpp/vpp.log
:
}

```

By moving the log file to `/var/log/vpp/`, it will get the label `vpp_log_t`,
which indicates that the files are log files so they benefit from the
associated rules (for example granting rights to logrotate so that it can
manipulate them).

##### Original Documentation

The default `startup.conf` file creates the VPP log file in `/tmp/vpp.log`. By
leaving the log file in `/tmp/`, it will get the label `vpp_tmp_t`. Moving it
to `/var/log/vpp/`, it will get the label `vpp_log_t`.

### Use of Non-default File Directories

VPP installs multiple files on the system.
Some files have fixed directory and file names:
- /etc/bash_completion.d/vppctl_completion
- /etc/sysctl.d/80-vpp.conf
- /usr/lib/systemd/system/vpp.service

Others files have default directory and file names but the default can be
overwritten:
- /etc/vpp/startup.conf
  - Can be changed via the `/usr/lib/systemd/system/vpp.service` file by
    changing the -c option on the VPP command line:

```
ExecStart=/usr/bin/vpp -c /etc/vpp/startup.conf
```

- /run/vpp/cli.sock
  - Can be changed via the `/etc/vpp/startup.conf` file by changing the
    cli-listen setting:

```
unix {
:
  cli-listen /run/vpp/cli.sock
:
}
```


- /var/log/vpp/vpp.log
  - Can be changed via the `/etc/vpp/startup.conf` file by changing the log
    setting:

```
unix {
  :
  log /var/log/vpp/vpp.log
  :
}

```

If the directory of any VPP installed files is changed from the default, ensure
that the proper SELiunx label is applied. The SELinux label can be determined by
passing the -Z option to many common Linux commands:

```
ls -alZ /run/vpp/
drwxr-xr-x. root vpp  system_u:object_r:vpp_var_run_t:s0 .
drwxr-xr-x. root root system_u:object_r:var_run_t:s0     ..
srwxrwxr-x. root vpp  system_u:object_r:vpp_var_run_t:s0 cli.sock
```

### VPP SELinux Types ###

The following SELinux types are created by the VPP Custom SELinux Policy:
- `vpp_t` - Applied to:
  - VPP process and spawned threads.

- `vpp_config_rw_t` - Applied to:
  - `/etc/vpp/*`

- `vpp_tmp_t` - Applied to:
  - `/tmp/*`

- `vpp_exec_t` - Applied to:
  - `/usr/bin/*`

- `vpp_lib_t` - Applied to:
  - `/usr/lib/vpp_api_test_plugins/*`
  - `/usr/lib/vpp_plugins/*`

- `vpp_unit_file_t` - Applied to:
  - `/usr/lib/systemd/system/vpp.*`

- `vpp_log_t` - Applied to:
  - `/var/log/vpp/*`

- `vpp_var_run_t` - Applied to:
  - `/var/run/vpp/*`
