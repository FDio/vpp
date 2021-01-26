General
-------

The external dependency package will not build in the snapcraft
vm. The path of least resistance is to copy it to the root of the
(original) workspace before running the prep script.

Snapcraft has mount issues except under /home. Run the prep script and
copy the entire directory (including the .tgz file) under
/home/yourself.

Environment Variables
---------------------

More or less mandatory settings:

```
  SNAPCRAFT_BUILD_ENVIRONMENT_MEMORY=16G
  SNAPCRAFT_BUILD_ENVIRONMENT_DISK=32G
```

Optional settings:

```
  SNAPCRAFT_BUILD_ENVIRONMENT_CPU=8
  SNAPCRAFT_ENABLE_DEVELOPER_DEBUG=yes
```

Run the prep script
-------------------

Run snapcraft
-------------

With luck, simply running snapcraft will produce the snap

```
  $ <environment-variable-settings> snapcraft --debug
```

Rerunning snapcraft phases
--------------------------

Here's how to (re)run individual phases, to avoid starting from
scratch N times in case of errors:

```
  snapcraft pull [<part-name>]
  snapcraft build [<part-name>]
  snapcraft stage [<part-name>]
  snapcraft prime [<part-name>]
  snapcraft snap or snapcraft
```

Restart without rebuilding VM
-----------------------------

To restart from scratch without rebuilding the VM:

```
  snapcraft clean vpp
```

Delete (all) snapcraft VMs
--------------------------

```
  for vm in $(multipass list | awk '{print $1}' | grep ^snapcraft-); do
  	multipass delete $vm --purge
  done
```
