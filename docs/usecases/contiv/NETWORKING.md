# Contiv/VPP Network Operation

This document describes the network operation of the Contiv/VPP k8s network plugin. It
elaborates the operation and config options of the Contiv IPAM, as well as 
details on how the VPP gets programmed by Contiv/VPP control plane.

The following picture shows 2-node k8s deployment of Contiv/VPP, with a VXLAN tunnel
established between the nodes to forward inter-node POD traffic. The IPAM options
are depicted on the Node 1, whereas the VPP programming is depicted on the Node 2.

![Contiv/VPP Architecture](/_images/contiv-networking.png "contiv-networking.png")

## Contiv/VPP IPAM (IP Address Management)

IPAM in Contiv/VPP is based on the concept of **Node ID**. The Node ID is a number
that uniquely identifies a node in the k8s cluster. The first node is assigned
the ID of 1, the second node 2, etc. If a node leaves the cluster, its 
ID is released back to the pool and will be re-used by the next node.

The Node ID is used to calculate per-node IP subnets for PODs
and other internal subnets that need to be unique on each node. Apart from the Node ID,
the input for IPAM calculations is a set of config knobs, which can be specified
in the `IPAMConfig` section of the \[Contiv/VPP deployment YAML\](../../../k8s/contiv-vpp.yaml):

- **PodSubnetCIDR** (default `10.1.0.0/16`): each pod gets an IP address assigned 
from this range. The size of this range (default `/16`) dictates upper limit of 
POD count for the entire k8s cluster (default 65536 PODs).

- **PodNetworkPrefixLen** (default `24`): per-node dedicated podSubnet range. 
From the allocatable range defined in `PodSubnetCIDR`, this value will dictate the 
allocation for each node. With the default value (`24`) this indicates that each node 
has a `/24` slice of the `PodSubnetCIDR`. The Node ID is used to address the node. 
In case of `PodSubnetCIDR = 10.1.0.0/16`, `PodNetworkPrefixLen = 24` and `NodeID = 5`,
the resulting POD subnet for the node would be `10.1.5.0/24`.

- **PodIfIPCIDR** (default `10.2.1.0/24`): VPP-internal addresses put the VPP interfaces 
facing towards the PODs into L3 mode. This IP range will be reused 
on each node, thereby it is never externally addressable outside of the node itself.
The only requirement is that this subnet should not collide with any other IPAM subnet.

- **VPPHostSubnetCIDR** (default `172.30.0.0/16`): used for addressing 
the interconnect of VPP with the Linux network stack, within the same node. 
Since this subnet needs to  be unique on each node, the Node ID is used to determine 
the actual subnet used on the node with the combination of `VPPHostNetworkPrefixLen`, `PodSubnetCIDR` and `PodNetworkPrefixLen`.

- **VPPHostNetworkPrefixLen** (default `24`): used to calculate the subnet 
for addressing the interconnect of VPP with the Linux network stack, within the same node.
With `VPPHostSubnetCIDR = 172.30.0.0/16`, `VPPHostNetworkPrefixLen = 24` and
`NodeID = 5` the resulting subnet for the node would be `172.30.5.0/24`.

- **NodeInterconnectCIDR** (default `192.168.16.0/24`): range for the addresses 
assigned to the data plane interfaces managed by VPP. Unless DHCP is used 
(`NodeInterconnectDHCP = True`), the Contiv/VPP control plane automatically assigns
an IP address from this range to the DPDK-managed ethernet interface bound to VPP 
on each node. The actual IP address will be calculated from the Node ID (e.g., with 
`NodeInterconnectCIDR = 192.168.16.0/24` and `NodeID = 5`, the resulting IP
address assigned to the ethernet interface on VPP will be `192.168.16.5` ).

- **NodeInterconnectDHCP** (default `False`): instead of assigning the IPs
for the data plane interfaces, which are managed by VPP from `NodeInterconnectCIDR` by the Contiv/VPP
control plane, DHCP assigns the IP addresses. The DHCP must be running in the network where the data
plane interface is connected, in case `NodeInterconnectDHCP = True`,
`NodeInterconnectCIDR` is ignored.

- **VxlanCIDR** (default `192.168.30.0/24`): in order to provide inter-node
POD to POD connectivity via any underlay network (not necessarily an L2 network),
Contiv/VPP sets up a VXLAN tunnel overlay between each of the 2 nodes within the cluster. Each node needs its unique IP address of the VXLAN BVI interface. This IP address
is automatically calculated from the Node ID, (e.g., with `VxlanCIDR = 192.168.30.0/24`
and `NodeID = 5`, the resulting IP address assigned to the VXLAN BVI interface will be `192.168.30.5`).

## VPP Programming
This section describes how the Contiv/VPP control plane programs VPP,  based on the
events it receives from k8s. This section is not necessarily for understanding
basic Contiv/VPP operation, but is very useful for debugging purposes.

Contiv/VPP currently uses a single VRF to forward the traffic between PODs on a node,
PODs on different nodes, host network stack, and DPDK-managed dataplane interface. The forwarding
between each of them is purely L3-based, even for cases of communication
between 2 PODs within the same node.

#### DPDK-Managed Data Interface
In order to allow inter-node communication between PODs on different
nodes and between PODs and outside world, Contiv/VPP uses data-plane interfaces
bound to VPP using DPDK. Each node should have one "main" VPP interface,
which is unbound from the host network stack and bound to VPP.
The Contiv/VPP control plane automatically configures the interface either
via DHCP, or with a statically assigned address (see `NodeInterconnectCIDR` and
`NodeInterconnectDHCP` yaml settings). 

#### PODs on the Same Node
PODs are connected to VPP using virtio-based TAP interfaces created by VPP,
with the POD-end of the interface placed into the POD container network namespace.
Each POD is assigned an IP address from the `PodSubnetCIDR`. The allocated IP
is configured with the prefix length `/32`. Additionally, a static route pointing 
towards the VPP is configured in the POD network namespace. 
The  prefix length `/32` means that all IP traffic will be forwarded to the
default route - VPP. To get rid of unnecessary broadcasts between POD and VPP,
a static ARP entry is configured for the gateway IP in the POD namespace, as well
as for POD IP on VPP. Both ends of the TAP interface have a static (non-default) 
MAC address applied.

#### PODs with hostNetwork=true
PODs with a `hostNetwork=true` attribute are not placed into a separate network namespace, they instead use the main host Linux network namespace; therefore, they are not directly connected to the VPP. They rely on the interconnection between the VPP and the host Linux network stack,
which is described in the next paragraph. Note, when these PODs access some service IP, their network communication will be NATed in Linux (by iptables rules programmed by kube-proxy)
as opposed to VPP, which is the case for the PODs connected to VPP directly.

#### Linux Host Network Stack
In order to interconnect the Linux host network stack with VPP (to allow access
to the cluster resources from the host itself, as well as for the PODs with `hostNetwork=true`),
VPP creates a TAP interface between VPP and the main network namespace. The TAP interface  is configured with IP addresses from the `VPPHostSubnetCIDR` range, with `.1` in the latest octet on the VPP side, and `.2` on the host side. The name of the host interface is `vpp1`. The host has static routes pointing to VPP configured with: 
- A route to the whole `PodSubnetCIDR` to route traffic targeting PODs towards VPP.
- A route to `ServiceCIDR` (default `10.96.0.0/12`), to route service IP targeted traffic that has not been translated by kube-proxy for some reason towards VPP. 
- The host also has a static ARP entry configured for the IP of the VPP-end TAP interface, to get rid of unnecessary broadcasts between the main network namespace and VPP.

#### VXLANs to Other Nodes
In order to provide inter-node POD to POD connectivity via any underlay network 
(not necessarily an L2 network), Contiv/VPP sets up a VXLAN tunnel overlay between 
each 2 nodes within the cluster (full mesh). 

All VXLAN tunnels are terminated in one bridge domain on each VPP. The bridge domain
has learning and flooding disabled, the l2fib of the bridge domain contains a static entry for each VXLAN tunnel. Each bridge domain has a BVI interface, which
interconnects the bridge domain with the main VRF (L3 forwarding). This interface needs
a unique IP address, which is assigned from the `VxlanCIDR` as describe above.

The main VRF contains several static routes that point to the BVI IP addresses of other nodes.
For each node, it is a route to PODSubnet and VppHostSubnet of the remote node, as well as a route
to the management IP address of the remote node. For each of these routes, the next hop IP is the
BVI interface IP of the remote node, which goes via the BVI interface of the local node.

The VXLAN tunnels and the static routes pointing to them are added/deleted on each VPP,
whenever a node is added/deleted in the k8s cluster.


#### More Info
Please refer to the \[Packet Flow Dev Guide\](../dev-guide/PACKET_FLOW.html) for more 
detailed description of paths traversed by request and response packets 
inside Contiv/VPP Kubernetes cluster under different situations.