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

## Debug SELinux Issues

If SELinux issues are suspected, there are a few steps that can be taken to
debug the issue. This section provides a few pointers on on those steps. Any
SELinux JIRAs will need this information to properly address the issue.

### Additional SELinux Packages and Setup

First, install the SELinux troubleshooting packages:

```
$ sudo yum -y install setroubleshoot setroubleshoot-server setools-console
-- OR --
$ sudo dnf -y install setroubleshoot setroubleshoot-server setools-console
```

To enable proper logging, restart auditd:

```
$ sudo service auditd restart
```

While debugging issues, it is best to set SELinux to `Permissive` mode. In
`Permissive` mode, SELinux will still detect and flag errors, but will allow
processes to continue normal operation. This allows multiple errors to be
collected at once as opposed to breaking on each individual error. To set
SELinux to `Permissive` mode (until next reboot or it is set back), use:

```
$ sudo setenforce 0

$ getenforce
Permissive
```

After debugging, to set SELinux back to `Enforcing` mode, use:

```
$ sudo setenforce 1

$ getenforce
Enforcing
```

### Debugging

Once the SELinux troubleshooting packages are installed, perform the actions
that are suspected to be blocked by SELinux. Either `tail` the log during
these actions or `grep` the log for additional SELinux logs:

```
sudo tail -f /var/log/messages
-- OR --
sudo journalctl -f
```

Below are some examples of SELinux logs that are generated:

```
May 14 11:28:34 svr-22 setroubleshoot: SELinux is preventing /usr/bin/vpp from read access on the file hostCreate.txt. For complete SELinux messages run: sealert -l a418f869-f470-4c8a-b8e9-bdd41f2dd60b
May 14 11:28:34 svr-22 python: SELinux is preventing /usr/bin/vpp from read access on the file hostCreate.txt.#012#012*****  Plugin catchall (100. confidence) suggests   **************************#012#012If you believe that vpp should be allowed read access on the hostCreate.txt file by default.#012Then you should report this as a bug.#012You can generate a local policy module to allow this access.#012Do#012allow this access for now by executing:#012# ausearch -c 'vpp_main' --raw | audit2allow -M my-vppmain#012# semodule -i my-vppmain.pp#012
May 14 11:28:34 svr-22 setroubleshoot: SELinux is preventing /usr/bin/vpp from read access on the file hostCreate.txt. For complete SELinux messages run: sealert -l a418f869-f470-4c8a-b8e9-bdd41f2dd60b
May 14 11:28:34 svr-22 python: SELinux is preventing /usr/bin/vpp from read access on the file hostCreate.txt.#012#012*****  Plugin catchall (100. confidence) suggests   **************************#012#012If you believe that vpp should be allowed read access on the hostCreate.txt file by default.#012Then you should report this as a bug.#012You can generate a local policy module to allow this access.#012Do#012allow this access for now by executing:#012# ausearch -c 'vpp_main' --raw | audit2allow -M my-vppmain#012# semodule -i my-vppmain.pp#012
May 14 11:28:37 svr-22 setroubleshoot: SELinux is preventing vpp_main from map access on the packet_socket packet_socket. For complete SELinux messages run: sealert -l ab6667d9-3f14-4dbd-96a0-7a655f7b4eb1
May 14 11:28:37 svr-22 python: SELinux is preventing vpp_main from map access on the packet_socket packet_socket.#012#012*****  Plugin catchall (100. confidence) suggests   **************************#012#012If you believe that vpp_main should be allowed map access on the packet_socket packet_socket by default.#012Then you should report this as a bug.#012You can generate a local policy module to allow this access.#012Do#012allow this access for now by executing:#012# ausearch -c 'vpp_main' --raw | audit2allow -M my-vppmain#012# semodule -i my-vppmain.pp#012
May 14 11:28:51 svr-22 setroubleshoot: SELinux is preventing vpp_main from map access on the packet_socket packet_socket. For complete SELinux messages run: sealert -l ab6667d9-3f14-4dbd-96a0-7a655f7b4eb1
May 14 11:28:51 svr-22 python: SELinux is preventing vpp_main from map access on the packet_socket packet_socket.#012#012*****  Plugin catchall (100. confidence) suggests   **************************#012#012If you believe that vpp_main should be allowed map access on the packet_socket packet_socket by default.#012Then you should report this as a bug.#012You can generate a local policy module to allow this access.#012Do#012allow this access for now by executing:#012# ausearch -c 'vpp_main' --raw | audit2allow -M my-vppmain#012# semodule -i my-vppmain.pp#012
```

From the logs above, there are two sets of commands that are recommended to be
run. The first is to run the `sealert` command. The second is to run the
`ausearch | audit2allow` commands and the `semodule` command.

#### sealert Command

This `sealert` command provides a more detailed output for the given issue
detected.

```
$ sealert -l a418f869-f470-4c8a-b8e9-bdd41f2dd60b
SELinux is preventing /usr/bin/vpp from 'read, write' accesses on the chr_file noiommu-0.

*****  Plugin device (91.4 confidence) suggests   ****************************

If you want to allow vpp to have read write access on the noiommu-0 chr_file
Then you need to change the label on noiommu-0 to a type of a similar device.
Do
# semanage fcontext -a -t SIMILAR_TYPE 'noiommu-0'
# restorecon -v 'noiommu-0'

*****  Plugin catchall (9.59 confidence) suggests   **************************

If you believe that vpp should be allowed read write access on the noiommu-0 chr_file by default.
Then you should report this as a bug.
You can generate a local policy module to allow this access.
Do
allow this access for now by executing:
# ausearch -c 'vpp' --raw | audit2allow -M my-vpp
# semodule -i my-vpp.pp


Additional Information:
Source Context                system_u:system_r:vpp_t:s0
Target Context                system_u:object_r:device_t:s0
Target Objects                noiommu-0 [ chr_file ]
Source                        vpp
Source Path                   /usr/bin/vpp
Port                          <Unknown>
Host                          vpp_centos7_selinux
Source RPM Packages           vpp-19.01.2-rc0~17_gcfd3086.x86_64
Target RPM Packages
Policy RPM                    selinux-policy-3.13.1-229.el7_6.12.noarch
Selinux Enabled               True
Policy Type                   targeted
Enforcing Mode                Permissive
Host Name                     vpp_centos7_selinux
Platform                      Linux vpp_centos7_selinux
                              3.10.0-957.12.1.el7.x86_64 #1 SMP Mon Apr 29
                              14:59:59 UTC 2019 x86_64 x86_64
Alert Count                   1
First Seen                    2019-05-13 18:10:50 EDT
Last Seen                     2019-05-13 18:10:50 EDT
Local ID                      a418f869-f470-4c8a-b8e9-bdd41f2dd60b

Raw Audit Messages
type=AVC msg=audit(1557785450.964:257): avc:  denied  { read write } for  pid=5273 comm="vpp" name="noiommu-0" dev="devtmpfs" ino=36022 scontext=system_u:system_r:vpp_t:s0 tcontext=system_u:object_r:device_t:s0 tclass=chr_file permissive=1


type=AVC msg=audit(1557785450.964:257): avc:  denied  { open } for  pid=5273 comm="vpp" path="/dev/vfio/noiommu-0" dev="devtmpfs" ino=36022 scontext=system_u:system_r:vpp_t:s0 tcontext=system_u:object_r:device_t:s0 tclass=chr_file permissive=1


type=SYSCALL msg=audit(1557785450.964:257): arch=x86_64 syscall=open success=yes exit=ENOTBLK a0=7fb395ffd7f0 a1=2 a2=7fb395ffd803 a3=7fb395ffe2a0 items=0 ppid=1 pid=5273 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=993 sgid=0 fsgid=993 tty=(none) ses=4294967295 comm=vpp exe=/usr/bin/vpp subj=system_u:system_r:vpp_t:s0 key=(null)

Hash: vpp,vpp_t,device_t,chr_file,read,write
```

In general, this command pumps out too much info and is only needed for
additional debugging for tougher issues. Also note that once the process being
tested is restarted, this command loses it's context and will not provide any
information:

```
$ sealert -l a418f869-f470-4c8a-b8e9-bdd41f2dd60b
Error
query_alerts error (1003): id (a418f869-f470-4c8a-b8e9-bdd41f2dd60b) not found
```

#### ausearch | audit2allow and semodule Commands

These set of commands are more useful for basic debugging. The
`ausearch | audit2allow` commands generate a set files. It may be worthwhile to
run the commands in a temporary subdirectory:

```
$ mkdir test-01/; cd test-01/

$ sudo ausearch -c 'vpp_main' --raw | audit2allow -M my-vppmain

$ ls
my-vpp.pp  my-vpp.te

$ cat my-vpp.te
module my-vpp 1.0;

require {
        type user_home_t;
        type vpp_t;
        class packet_socket map;
        class file { open read };
}

#============= vpp_t ==============
allow vpp_t self:packet_socket map;
allow vpp_t user_home_t:file { open read };
```

As shown above, the file `my-vpp.te` has been generated. This file shows
possible changes to the SELinux policy that may fix the issue. If an SELinux
policy was being created from scratch, this policy could be applied using the
`semodule -i my-vpp.pp` command. HOWEVER, VPP already has a policy in place. So
these changes need to be incorporated into the existing policy. The VPP SELinux
policy is located in the following files:

```
$ ls extras/selinux/
selinux_doc.md  vpp-custom.fc  vpp-custom.if  vpp-custom.te
```

In this example, `map` needs to be added to the `packet_socket` class. If the
`vpp-custom.te` is examined (prior to this fix), then one would see that the
`packet_socket` class is already defined and just needs to be updated:

```
$ vi extras/selinux/vpp-custom.te
:
allow vpp_t self:process { execmem execstack setsched signal }; # too benevolent
allow vpp_t self:packet_socket { bind create setopt ioctl };  <---
allow vpp_t self:tun_socket { create relabelto relabelfrom };
:
```

Before blindly applying the changes proposed by the `ausearch | audit2allow`
commands, try to determine what is being allowed by the policy and determine if
this is desired, or if the code can be reworked to no longer require the
suggested permission. In the `my-vpp.te` file from above, it is suggested to
allow `vpp_t` (i.e. the VPP process) access to all files in the home directory
(`allow vpp_t user_home_t:file { open read };`). This was because a
`vppctl exec` command was executed calling a script located in the
`/home/<user>/` directory. Once this script was run from the `/usr/share/vpp/`
directory as described in a section above, these permissions were no longer
needed.
