### Setting up a Node with a Single NIC

#### Installing the STN Daemon
The STN (Steal the NIC) daemon must be installed on every node in the cluster that has only 
one NIC. The STN daemon installation(*) should be performed before deployment 
of the Contiv-VPP plugin.

\* Docker daemon must be present when installing STN.  Also, Docker must be configured to allow shared mount.
On CentOS, this may not be the case by default.  You can enable it by following the instructions at
[https://docs.portworx.com/knowledgebase/shared-mount-propagation.html](https://docs.portworx.com/knowledgebase/shared-mount-propagation.html).


Run as root (not using sudo):
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh)
```
The install script should output the following:
```
Installing Contiv STN daemon.
Starting contiv-stn Docker container:
550334308f85f05b2690f5cfb5dd945bd9c501ab9d074231f15c14d7098ef212
```

Check that the STN daemon is running:
```
docker ps -a 
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS               NAMES
550334308f85        contivvpp/stn       "/stn"              33 seconds ago      Up 33 seconds                           contiv-stn
```

Check that the STN daemon is operational:
```
docker logs contiv-stn
```
The expected logs would look like the following excerpt:
```
2018/02/23 10:08:34 Starting the STN GRPC server at port 50051
```

For more details, please read the Go documentation for [contiv-stn](https://github.com/contiv/vpp/blob/master/cmd/contiv-stn/doc.go)
and [contiv-init](https://github.com/contiv/vpp/blob/master/cmd/contiv-init/doc.go).

#### Creating a VPP Interface Configuration
Create the VPP configuration for the hardware interface as described 
[here](https://github.com/contiv/vpp/blob/master/docs/VPP_CONFIG.md#single-nic-configuration).

#### Configuring STN in Contiv-VPP K8s Deployment Files
The STN feature is disabled by default. It needs to be enabled either globally,
or individually for every node in the cluster. 

##### Global Configuration:
Global configuration is used in homogeneous environments where all nodes in 
a given cluster have the same hardware configuration, for example only a single
Network Adapter. To enable the STN feature globally, put the `StealFirstNIC: True`
stanza into the \[`contiv-vpp.yaml`\]\[1\] deployment file, for example:
```
data:
  contiv.yaml: |-
    TCPstackDisabled: true
    ...
    StealFirstNIC: True
    ...
    IPAMConfig:
```

Setting `StealFirstNIC` to `True` will tell the STN Daemon on every node in the 
cluster to steal the first NIC from the kernel and assign it to VPP. Note that
the Network Adapters on different nodes do not need to be of the same type. You
still need to create the respective vswitch configurations on every node in the
cluster, as shown \[above\](#creating-a-vpp-interface-configuration).

##### Individual Configuration:
Individual configuration is used in heterogeneous environments where each node
in a given cluster may be configured differently. To enable the STN feature 
for a specific node in the cluster, put the following stanza into its Node
Configuration in the \[`contiv-vpp.yaml`\]\[1\] deployment file, for example:
```
...
    NodeConfig:
    - NodeName: "ubuntu-1"
      StealInterface: "enp0s8"
    - NodeName: "ubuntu-2"
      StealInterface: "enp0s8"
...
``` 
Note that you still have to create the vswitch configuration on the node as
shown [here](#creating-a-vpp-interface-configuration).



#### Uninstalling the STN Daemon

Run as root (not using sudo):
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh) --uninstall
```
The install script should output the following:
```
Uninstalling Contiv STN daemon.
Stopping contiv-stn Docker container:
contiv-stn
contiv-stn
contiv-stn
```
Make sure that the STN daemon has been uninstalled:
```
docker ps -q -f name=contiv-stn
```
No containers should be listed.

[1]: ../k8s/contiv-vpp.yaml
