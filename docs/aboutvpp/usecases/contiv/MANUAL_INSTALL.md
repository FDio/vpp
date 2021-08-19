# Manual Installation
This document describes how to clone the Contiv repository and then use [kubeadm][1] to manually install Kubernetes
with Contiv-VPP networking on one or more bare metal or VM hosts. 

## Clone the Contiv Repository
To clone the Contiv repository enter the following command:
```
git clone https://github.com/contiv/vpp/<repository-name>
```
**Note:** Replace *<repository-name>* with the name you want assigned to your cloned contiv repository.

The cloned repository has important folders that contain content that are referenced in this Contiv documentation; those folders are noted below:
```
vpp-contiv2$ ls
build       build-root  doxygen  gmod       LICENSE      Makefile   RELEASE.md   src
build-data  docs        extras   INFO.yaml  MAINTAINERS  README.md  sphinx_venv  test
```
## Preparing Your Hosts

### Host-specific Configurations
- **VmWare VMs**: the vmxnet3 driver is required on each interface that will
  be used by VPP. Please see [here][13] for instructions how to install the 
  vmxnet3 driver on VmWare Fusion.
  
### Setting up Network Adapter(s)
#### Setting up DPDK
DPDK setup must be completed **on each node** as follows:

- Load the PCI UIO driver:
  ```
  $ sudo modprobe uio_pci_generic
  ```

- Verify that the PCI UIO driver has loaded successfully:
  ```
  $ lsmod | grep uio
  uio_pci_generic        16384  0
  uio                    20480  1 uio_pci_generic
  ```

  Please note that this driver needs to be loaded upon each server bootup,
  so you may want to add `uio_pci_generic` into the `/etc/modules` file, 
  or a file in the `/etc/modules-load.d/` directory. For example, the 
  `/etc/modules` file could look as follows:
  ```
  # /etc/modules: kernel modules to load at boot time.
  #
  # This file contains the names of kernel modules that should be loaded
  # at boot time, one per line. Lines beginning with "#" are ignored.
  uio_pci_generic
  ```
#### Determining Network Adapter PCI Addresses
You need the PCI address of the network interface that VPP will use for the multi-node pod interconnect. On Debian-based
distributions, you can use `lshw`(*):

```
$ sudo lshw -class network -businfo
Bus info          Device      Class      Description
====================================================
pci@0000:00:03.0  ens3        network    Virtio network device
pci@0000:00:04.0  ens4        network    Virtio network device
```
**Note:** On CentOS/RedHat/Fedora distributions, `lshw` may not be available by default, install it by issuing the following command:
    ```
    yum -y install lshw
    ```

#### Configuring vswitch to Use Network Adapters
Finally, you need to set up the vswitch to use the network adapters:

- [Setup on a node with a single NIC][14]
- [Setup a node with multiple NICs][15]

### Using a Node Setup Script
You can perform the above steps using the [node setup script][17].

## Installing Kubernetes with Contiv-VPP CNI plugin
After the nodes you will be using in your K8s cluster are prepared, you can 
install the cluster using [kubeadm][1].

### (1/4) Installing Kubeadm on Your Hosts
For first-time installation, see [Installing kubeadm][6]. To update an
existing installation,  you should do a `apt-get update && apt-get upgrade`
or `yum update` to get the latest version of kubeadm.

On each host with multiple NICs where the NIC that will be used for Kubernetes
management traffic is not the one pointed to by the default route out of the 
host, a [custom management network][12] for Kubernetes must be configured.

#### Using Kubernetes 1.10 and Above
In K8s 1.10, support for huge pages in a pod has been introduced. For now, this
feature must be either disabled or memory limit must be defined for vswitch container.

To disable huge pages, perform the following
steps as root:
* Using your favorite editor, disable huge pages in the kubelet configuration 
  file (`/etc/systemd/system/kubelet.service.d/10-kubeadm.conf` or `/etc/default/kubelet` for version 1.11+):
```
  Environment="KUBELET_EXTRA_ARGS=--feature-gates HugePages=false"
```
* Restart the kubelet daemon:
```
  systemctl daemon-reload
  systemctl restart kubelet
```

To define memory limit, append the following snippet to vswitch container in deployment yaml file:
```
			resources:
              limits:
                hugepages-2Mi: 1024Mi
                memory: 1024Mi

```
or set `contiv.vswitch.defineMemoryLimits` to `true` in [helm values](https://github.com/contiv/vpp/blob/master/k8s/contiv-vpp/README.md).

### (2/4) Initializing Your Master
Before initializing the master, you may want to [remove][8] any
previously installed K8s components. Then, proceed with master initialization
as described in the [kubeadm manual][3]. Execute the following command as
root:
```
kubeadm init --token-ttl 0 --pod-network-cidr=10.1.0.0/16
```
**Note:** `kubeadm init` will autodetect the network interface to advertise
the master on as the interface with the default gateway. If you want to use a
different interface (i.e. a custom management network setup), specify the
`--apiserver-advertise-address=<ip-address>` argument to kubeadm init. For
example:
```
kubeadm init --token-ttl 0 --pod-network-cidr=10.1.0.0/16 --apiserver-advertise-address=192.168.56.106
```
**Note:** The CIDR specified with the flag `--pod-network-cidr` is used by
kube-proxy, and it **must include** the `PodSubnetCIDR` from the `IPAMConfig`
section in the Contiv-vpp config map in Contiv-vpp's deployment file 
[contiv-vpp.yaml](https://github.com/contiv/vpp/blob/master/k8s/contiv-vpp/values.yaml). Pods in the host network namespace
are a special case; they share their respective interfaces and IP addresses with
the host. For proxying to work properly it is therefore required for services
with backends running on the host to also **include the node management IP** 
within the `--pod-network-cidr` subnet. For example, with the default 
`PodSubnetCIDR=10.1.0.0/16` and `PodIfIPCIDR=10.2.1.0/24`, the subnet 
`10.3.0.0/16` could be allocated for the management network and 
`--pod-network-cidr` could be defined as `10.0.0.0/8`, so as to include IP 
addresses of all pods in all network namespaces:
```
kubeadm init --token-ttl 0 --pod-network-cidr=10.0.0.0/8 --apiserver-advertise-address=10.3.1.1
```

If Kubernetes was initialized successfully, it prints out this message:
```
Your Kubernetes master has initialized successfully!
```

After successful initialization, don't forget to set up your .kube directory
as a regular user (as instructed by `kubeadm`):
```bash
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
```

### (3/4) Installing the Contiv-VPP Pod Network
If you have already used the Contiv-VPP plugin before, you may need to pull
the most recent Docker images on each node:
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/pull-images.sh)
```

Install the Contiv-VPP network for your cluster as follows:

- If you do not use the STN feature, install Contiv-vpp as follows: 
  ```
  kubectl apply -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml
  ```
  
- If you use the STN feature, download the `contiv-vpp.yaml` file:
  ```
  wget https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml
  ```
  Then edit the STN configuration as described [here][16]. Finally, create 
  the Contiv-vpp deployment from the edited file:
  ```
  kubectl apply -f ./contiv-vpp.yaml
  ``` 

Beware contiv-etcd data is persisted in `/var/etcd` by default. It has to be cleaned up manually after `kubeadm reset`.
Otherwise outdated data will be loaded by a subsequent deployment.

You can also generate random subfolder, alternatively:

```
curl --silent https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml | sed "s/\/var\/etcd\/contiv-data/\/var\/etcd\/contiv-data\/$RANDOM/g" | kubectl apply -f -
```

#### Deployment Verification
After some time, all contiv containers should enter the running state:
```
root@cvpp:/home/jan# kubectl get pods -n kube-system -o wide | grep contiv
NAME                           READY     STATUS    RESTARTS   AGE       IP               NODE
...
contiv-etcd-gwc84              1/1       Running   0          14h       192.168.56.106   cvpp
contiv-ksr-5c2vk               1/1       Running   2          14h       192.168.56.106   cvpp
contiv-vswitch-l59nv           2/2       Running   0          14h       192.168.56.106   cvpp
```
In particular, make sure that the Contiv-VPP pod IP addresses are the same as
the IP address specified in the `--apiserver-advertise-address=<ip-address>`
argument to kubeadm init.

Verify that the VPP successfully grabbed the network interface specified in
the VPP startup config (`GigabitEthernet0/4/0` in our case):
```
$ sudo vppctl
vpp# sh inter
              Name               Idx       State          Counter          Count
GigabitEthernet0/4/0              1         up       rx packets                  1294
                                                     rx bytes                  153850
                                                     tx packets                   512
                                                     tx bytes                   21896
                                                     drops                        962
                                                     ip4                         1032
host-40df9b44c3d42f4              3         up       rx packets                126601
                                                     rx bytes                44628849
                                                     tx packets                132155
                                                     tx bytes                27205450
                                                     drops                         24
                                                     ip4                       126585
                                                     ip6                           16
host-vppv2                        2         up       rx packets                132162
                                                     rx bytes                27205824
                                                     tx packets                126658
                                                     tx bytes                44634963
                                                     drops                         15
                                                     ip4                       132147
                                                     ip6                           14
local0                            0        down
```

You should also see the interface to kube-dns (`host-40df9b44c3d42f4`) and to the
node's IP stack (`host-vppv2`).

#### Master Isolation (Optional)
By default, your cluster will not schedule pods on the master for security
reasons. If you want to be able to schedule pods on the master, (e.g., for a
single-machine Kubernetes cluster for development), then run:

```
kubectl taint nodes --all node-role.kubernetes.io/master-
```
More details about installing the pod network can be found in the
[kubeadm manual][4].

### (4/4) Joining Your Nodes
To add a new node to your cluster, run as root the command that was output
by kubeadm init. For example:
```
kubeadm join --token <token> <master-ip>:<master-port> --discovery-token-ca-cert-hash sha256:<hash>
```
More details can be found int the [kubeadm manual][5].

#### Deployment Verification
After some time, all contiv containers should enter the running state:
```
root@cvpp:/home/jan# kubectl get pods -n kube-system -o wide | grep contiv
NAME                           READY     STATUS    RESTARTS   AGE       IP               NODE
contiv-etcd-gwc84              1/1       Running   0          14h       192.168.56.106   cvpp
contiv-ksr-5c2vk               1/1       Running   2          14h       192.168.56.106   cvpp
contiv-vswitch-h6759           2/2       Running   0          14h       192.168.56.105   cvpp-slave2
contiv-vswitch-l59nv           2/2       Running   0          14h       192.168.56.106   cvpp
etcd-cvpp                      1/1       Running   0          14h       192.168.56.106   cvpp
kube-apiserver-cvpp            1/1       Running   0          14h       192.168.56.106   cvpp
kube-controller-manager-cvpp   1/1       Running   0          14h       192.168.56.106   cvpp
kube-dns-545bc4bfd4-fr6j9      3/3       Running   0          14h       10.1.134.2       cvpp
kube-proxy-q8sv2               1/1       Running   0          14h       192.168.56.106   cvpp
kube-proxy-s8kv9               1/1       Running   0          14h       192.168.56.105   cvpp-slave2
kube-scheduler-cvpp            1/1       Running   0          14h       192.168.56.106   cvpp
```
In particular, verify that a vswitch pod and a kube-proxy pod is running on
each joined node, as shown above.

On each joined node, verify that the VPP successfully grabbed the network
interface specified in the VPP startup config (`GigabitEthernet0/4/0` in
our case):
```
$ sudo vppctl
vpp# sh inter
              Name               Idx       State          Counter          Count
GigabitEthernet0/4/0              1         up
...
```
From the vpp CLI on a joined node you can also ping kube-dns to verify
node-to-node connectivity. For example:
```
vpp# ping 10.1.134.2
64 bytes from 10.1.134.2: icmp_seq=1 ttl=64 time=.1557 ms
64 bytes from 10.1.134.2: icmp_seq=2 ttl=64 time=.1339 ms
64 bytes from 10.1.134.2: icmp_seq=3 ttl=64 time=.1295 ms
64 bytes from 10.1.134.2: icmp_seq=4 ttl=64 time=.1714 ms
64 bytes from 10.1.134.2: icmp_seq=5 ttl=64 time=.1317 ms

Statistics: 5 sent, 5 received, 0% packet loss
```
### Deploying Example Applications
#### Simple Deployment
You can go ahead and create a simple deployment:
```
$ kubectl run nginx --image=nginx --replicas=2
```

Use `kubectl describe pod` to get the IP address of a pod, e.g.:
```
$ kubectl describe pod nginx | grep IP
```
You should see two ip addresses, for example:
```
IP:		10.1.1.3
IP:		10.1.1.4
```

You can check the pods' connectivity in one of the following ways:
* Connect to the VPP debug CLI and ping any pod:
```
  sudo vppctl
  vpp# ping 10.1.1.3
```
* Start busybox and ping any pod:
```
  kubectl run busybox --rm -ti --image=busybox /bin/sh
  If you don't see a command prompt, try pressing enter.
  / #
  / # ping 10.1.1.3

```
* You should be able to ping any pod from the host:
```
  ping 10.1.1.3
```

#### Deploying Pods on Different Nodes
to enable pod deployment on the master, untaint the master first:
```
kubectl taint nodes --all node-role.kubernetes.io/master-
```

In order to verify inter-node pod connectivity, we need to tell Kubernetes
to deploy one pod on the master node and one POD on the worker. For this,
we can use node selectors.

In your deployment YAMLs, add the `nodeSelector` sections that refer to
preferred node hostnames, e.g.:
```
  nodeSelector:
    kubernetes.io/hostname: vm5
```

Example of whole JSONs:
```
apiVersion: v1
kind: Pod
metadata:
  name: nginx1
spec:
  nodeSelector:
    kubernetes.io/hostname: vm5
  containers:
    - name: nginx
      
	  : nginx
```

```
apiVersion: v1
kind: Pod
metadata:
  name: nginx2
spec:
  nodeSelector:
    kubernetes.io/hostname: vm6
  containers:
    - name: nginx
      image: nginx
```

After deploying the JSONs, verify they were deployed on different hosts:
```
$ kubectl get pods -o wide
NAME      READY     STATUS    RESTARTS   AGE       IP           NODE
nginx1    1/1       Running   0          13m       10.1.36.2    vm5
nginx2    1/1       Running   0          13m       10.1.219.3   vm6
```

Now you can verify the connectivity to both nginx PODs from a busybox POD:
```
kubectl run busybox --rm -it --image=busybox /bin/sh

/ # wget 10.1.36.2
Connecting to 10.1.36.2 (10.1.36.2:80)
index.html           100% |*******************************************************************************************************************************************************************|   612   0:00:00 ETA

/ # rm index.html

/ # wget 10.1.219.3
Connecting to 10.1.219.3 (10.1.219.3:80)
index.html           100% |*******************************************************************************************************************************************************************|   612   0:00:00 ETA
```

### Uninstalling Contiv-VPP
To uninstall the network plugin itself, use `kubectl`:
```
kubectl delete -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp.yaml
```

### Tearing down Kubernetes
* First, drain the node and make sure that the node is empty before
shutting it down:
```
  kubectl drain <node name> --delete-local-data --force --ignore-daemonsets
  kubectl delete node <node name>
```
* Next, on the node being removed, reset all kubeadm installed state:
```
  rm -rf $HOME/.kube
  sudo su
  kubeadm reset
```

* If you added environment variable definitions into
  `/etc/systemd/system/kubelet.service.d/10-kubeadm.conf`, this would have been a process from the [Custom Management Network file][10], then remove the definitions now.

### Troubleshooting
Some of the issues that can occur during the installation are:

- Forgetting to create and initialize the `.kube` directory in your home
  directory (As instructed by `kubeadm init --token-ttl 0`). This can manifest
  itself as the following error:
  ```
  W1017 09:25:43.403159    2233 factory_object_mapping.go:423] Failed to download OpenAPI (Get https://192.168.209.128:6443/swagger-2.0.0.pb-v1: x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "kubernetes")), falling back to swagger
  Unable to connect to the server: x509: certificate signed by unknown authority (possibly because of "crypto/rsa: verification error" while trying to verify candidate authority certificate "kubernetes")
  ```
- Previous installation lingering on the file system.
  `'kubeadm init --token-ttl 0` fails to initialize kubelet with one or more
  of the following error messages:
  ```
  ...
  [kubelet-check] It seems like the kubelet isn't running or healthy.
  [kubelet-check] The HTTP call equal to 'curl -sSL http://localhost:10255/healthz' failed with error: Get http://localhost:10255/healthz: dial tcp [::1]:10255: getsockopt: connection refused.
  ...
  ```

If you run into any of the above issues, try to clean up and reinstall as root:
```
sudo su
rm -rf $HOME/.kube
kubeadm reset
kubeadm init --token-ttl 0
rm -rf /var/etcd/contiv-data
rm -rf /var/bolt/bolt.db
```

## Contiv-specific kubeadm installation on Aarch64
Supplemental instructions apply when using Contiv-VPP for Aarch64. Most
installation steps for Aarch64 are the same as that described earlier in this
chapter, so you should firstly read it before you start the installation on
Aarch64 platform.

Use the [Aarch64-specific kubeadm install instructions][18] to manually install
Kubernetes with Contiv-VPP networking on one or more bare-metals of Aarch64 platform.

[1]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/
[3]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#initializing-your-master
[4]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#pod-network
[5]: https://kubernetes.io/docs/setup/independent/create-cluster-kubeadm/#joining-your-nodes
[6]: https://kubernetes.io/docs/setup/independent/install-kubeadm/
[8]: #tearing-down-kubernetes
[10]: https://github.com/contiv/vpp/blob/master/docs/CUSTOM_MGMT_NETWORK.md#setting-up-a-custom-management-network-on-multi-homed-nodes
[11]: ../vagrant/README.md
[12]: https://github.com/contiv/vpp/tree/master/docs/CUSTOM_MGMT_NETWORK.md
[13]: https://github.com/contiv/vpp/tree/master/docs/VMWARE_FUSION_HOST.md
[14]: https://github.com/contiv/vpp/tree/master/docs/SINGLE_NIC_SETUP.md
[15]: https://github.com/contiv/vpp/tree/master/docs/MULTI_NIC_SETUP.md
[16]: https://github.com/contiv/vpp/tree/master/docs/SINGLE_NIC_SETUP.md#configuring-stn-in-contiv-vpp-k8s-deployment-files
[17]: https://github.com/contiv/vpp/tree/master/k8s/README.md#setup-node-sh
[18]: https://github.com/contiv/vpp/blob/master/docs/arm64/MANUAL_INSTALL_ARM64.md
