### Setting Up a Custom Management Network on Multi-Homed Nodes

If the interface you use for Kubernetes management traffic (for example, the
IP address used for `kubeadm join`) is not the one that contains the default
route out of the host, then you need to specify the management node IP address in
the Kubelet config file. Add the following line to:
(`/etc/systemd/system/kubelet.service.d/10-kubeadm.conf`):
```
Environment="KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=<node-management-ip-address>"
```
#### Example
Consider a 2 node deployment where each node is connected to 2 networks -
`10.0.2.0/24` and `192.168.56.0/24`, and the default route on each node points
to the interface connected to the `10.0.2.0/24` subnet. We want to use subnet
`192.168.56.0/24` for Kubernetes management traffic. Assume the addresses of
nodes connected to `192.168.56.0/24` are `192.168.56.105` and `192.168.56.106`.

On the `192.168.56.105` node you add the following line to `10-kubeadm.conf`:
```
Environment="KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=192.168.56.105"
```
On the `192.168.56.106` node you add the following line to `10-kubeadm.conf`:
```
Environment="KUBELET_EXTRA_ARGS=--fail-swap-on=false --node-ip=192.168.56.106"
```

