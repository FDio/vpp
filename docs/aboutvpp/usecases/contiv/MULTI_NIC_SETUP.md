### Setting Up a Node with Multiple NICs

* First, configure hardware interfaces in the VPP startup config, as
described [here](https://github.com/contiv/vpp/blob/master/docs/VPP_CONFIG.md#multi-nic-configuration).

* For each interface owned by Linux, you need to provide individual
  configuration for each interface used by VPP in the Node Configuration 
  for the node in the `contiv-vpp.yaml`. For example, if both `ens3` and
  `ens4` are known to Linux, then put the following stanza into the node's
  NodeConfig:
```
...
    NodeConfig:
    - NodeName: "ubuntu-1"
      StealInterface: "ens3"
      StealInterface: "ens4"
...
``` 
  If only `ens3` is known to Linux, you only put a line for `ens3` into the 
  above NodeConfig.

