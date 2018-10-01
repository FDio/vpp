## Contiv-VPP Vagrant Installation

### Prerequisites
The following items are prerequisites before installing vagrant:
- Vagrant 2.0.1 or later
- Hypervisors:
  - VirtualBox 5.2.8 or later 
  - VMWare Fusion 10.1.0 or later or VmWare Workstation 14
    - For VmWare Fusion, you will need the [Vagrant VmWare Fusion plugin](https://www.vagrantup.com/vmware/index.html)
- Laptop or server with at least 4 CPU cores and 16 Gig of RAM    

### Creating / Shutting Down / Destroying the Cluster
This folder contains the Vagrant file that is used to create a single or multi-node 
Kubernetes cluster using Contiv-VPP as a Network Plugin. 

The folder is organized into two subfolders:

 - (config) - contains the files that share cluster information, which are used
   during the provisioning stage (master IP address, Certificates, hash-keys).
   **CAUTION:** Editing is not recommended!
 - (vagrant) - contains scripts that are used for creating, destroying, rebooting
    and shutting down the VMs that host the K8s cluster.

To create and run a K8s cluster with a *contiv-vpp CNI* plugin, run the 
`vagrant-start` script, located in the [vagrant folder](https://github.com/contiv/vpp/tree/master/vagrant). The `vagrant-start`
script prompts the user to select the number of worker nodes for the kubernetes cluster. 
Zero (0) worker nodes mean that a single-node cluster (with one kubernetes master node) will be deployed. 

Next, the user is prompted to select either the *production environment* or the *development environment*.
Instructions on how to build the development *contiv/vpp-vswitch* image can be found below in the
[development environment](#building-and-deploying-the-dev-contiv-vswitch-image) command section. 

The last option asks the user to select either *Without StealTheNIC* or *With StealTheNIC*.
Using option *With StealTheNIC* has the plugin "steal" interfaces owned by Linux and uses their configuration in VPP.

For the production environment, enter the following commands:
```
| => ./vagrant-start
Please provide the number of workers for the Kubernetes cluster (0-50) or enter [Q/q] to exit: 1

Please choose Kubernetes environment:
1) Production
2) Development
3) Quit
--> 1
You chose Development environment

Please choose deployment scenario:
1) Without StealTheNIC
2) With StealTheNIC
3) Quit
--> 1 
You chose deployment without StealTheNIC

Creating a production environment, without STN and 1 worker node(s)
```

For the development environment, enter the following commands:
```
| => ./vagrant-start
Please provide the number of workers for the Kubernetes cluster (0-50) or enter [Q/q] to exit: 1

Please choose Kubernetes environment:
1) Production
2) Development
3) Quit
--> 2
You chose Development environment

Please choose deployment scenario:
1) Without StealTheNIC
2) With StealTheNIC
3) Quit
--> 1
You chose deployment without StealTheNIC

Creating a development environment, without STN and 1 worker node(s)
```

To destroy and clean-up the cluster, run the *vagrant-cleanup* script, located
[inside the vagrant folder](https://github.com/contiv/vpp/tree/master/vagrant):
```
cd vagrant/
./vagrant-cleanup
```

To shutdown the cluster, run the *vagrant-shutdown* script, located [inside the vagrant folder](https://github.com/contiv/vpp/tree/master/vagrant):
```
cd vagrant/
./vagrant-shutdown
```

- To reboot the cluster, run the *vagrant-reload* script, located [inside the vagrant folder](https://github.com/contiv/vpp/tree/master/vagrant):
```
cd vagrant/
./vagrant-reload
```

- From a suspended state, or after a reboot of the host machine, the cluster
can be brought up by running the *vagrant-up* script.


### Building and Deploying the dev-contiv-vswitch Image
If you chose the optional development-environment-deployment option, then perform the
following instructions on how to build a modified *contivvpp/vswitch* image:

- Make sure changes in the code have been saved. From the k8s-master node, 
   build the new *contivvpp/vswitch* image (run as sudo):

```
vagrant ssh k8s-master
cd /vagrant/config
sudo ./save-dev-image
```

- The newly built *contivvpp/vswitch* image is now tagged as *latest*. Verify the
build with `sudo docker images`; the *contivvpp/vswitch* should have been created a few
seconds ago. The new image with all the changes must become available to all
the nodes in the K8s cluster. To make the changes available to all, load the docker image into the running
worker nodes (run as sudo):

```
vagrant ssh k8s-worker1
cd /vagrant/config
sudo ./load-dev-image
```

- Verify with `sudo docker images`; the old *contivvpp/vswitch* should now be tagged as
`<none>` and the latest tagged  *contivvpp/vswitch* should have been created a
few seconds ago.

### Exploring the Cluster
Once the cluster is up, perform the following steps:
- Log into the master:
```
cd vagrant

vagrant ssh k8s-master

Welcome to Ubuntu 16.04 LTS (GNU/Linux 4.4.0-21-generic x86_64)

 * Documentation:  https://help.ubuntu.com/
vagrant@k8s-master:~$ 
```
- Verify the Kubernetes/Contiv-VPP installation. First, verify the nodes
in the cluster:

```
vagrant@k8s-master:~$ kubectl get nodes -o wide

NAME          STATUS    ROLES     AGE       VERSION   EXTERNAL-IP   OS-IMAGE           KERNEL-VERSION     CONTAINER-RUNTIME
k8s-master    Ready     master    22m       v1.9.2    <none>        Ubuntu 16.04 LTS   4.4.0-21-generic   docker://17.12.0-ce
k8s-worker1   Ready     <none>    15m       v1.9.2    <none>        Ubuntu 16.04 LTS   4.4.0-21-generic   docker://17.12.0-ce
```

- Next, verify that all pods are running correctly:

```
vagrant@k8s-master:~$ kubectl get pods -n kube-system -o wide

NAME                                 READY     STATUS             RESTARTS   AGE       IP             NODE
contiv-etcd-2ngdc                    1/1       Running            0          17m       192.169.1.10   k8s-master
contiv-ksr-x7gsq                     1/1       Running            3          17m       192.169.1.10   k8s-master
contiv-vswitch-9bql6                 2/2       Running            0          17m       192.169.1.10   k8s-master
contiv-vswitch-hpt2x                 2/2       Running            0          10m       192.169.1.11   k8s-worker1
etcd-k8s-master                      1/1       Running            0          16m       192.169.1.10   k8s-master
kube-apiserver-k8s-master            1/1       Running            0          16m       192.169.1.10   k8s-master
kube-controller-manager-k8s-master   1/1       Running            0          15m       192.169.1.10   k8s-master
kube-dns-6f4fd4bdf-62rv4             2/3       CrashLoopBackOff   14         17m       10.1.1.2       k8s-master
kube-proxy-bvr74                     1/1       Running            0          10m       192.169.1.11   k8s-worker1
kube-proxy-v4fzq                     1/1       Running            0          17m       192.169.1.10   k8s-master
kube-scheduler-k8s-master            1/1       Running            0          16m       192.169.1.10   k8s-master
```

- If you want your pods to be scheduled on both the master and the workers,
you have to untaint the master node:
```

```

- Check VPP and its interfaces:
```
vagrant@k8s-master:~$ sudo vppctl
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# sh interface
              Name               Idx       State          Counter          Count     
GigabitEthernet0/8/0              1         up       rx packets                    14
                                                     rx bytes                    3906
                                                     tx packets                    18
                                                     tx bytes                    2128
                                                     drops                          3
                                                     ip4                           13
...
                                                     
```
- Make sure that `GigabitEthernet0/8/0` is listed and that its status is `up`. 

- Next, create an example deployment of nginx pods:
```
vagrant@k8s-master:~$ kubectl run nginx --image=nginx --replicas=2
deployment "nginx" created
```
- Check the status of the deployment:

```
vagrant@k8s-master:~$ kubectl get deploy -o wide

NAME      DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE       CONTAINERS   IMAGES    SELECTOR
nginx     2         2         2            2           2h        nginx        nginx     run=nginx
```

- Verify that the pods in the deployment are up and running:
```
vagrant@k8s-master:~$ kubectl get pods -o wide

NAME                   READY     STATUS    RESTARTS   AGE       IP         NODE
nginx-8586cf59-6kx2m   1/1       Running   1          1h        10.1.2.3   k8s-worker1
nginx-8586cf59-j5vf9   1/1       Running   1          1h        10.1.2.2   k8s-worker1
```

- Issue an HTTP GET request to a pod in the deployment:

```
vagrant@k8s-master:~$ wget 10.1.2.2

--2018-01-19 12:34:08--  http://10.1.2.2/
Connecting to 10.1.2.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 612 [text/html]
Saving to: ‘index.html.1’

index.html.1                100%[=========================================>]     612  --.-KB/s    in 0s      

2018-01-19 12:34:08 (1.78 MB/s) - ‘index.html.1’ saved [612/612]
```

#### How to SSH into k8s Worker Node
To SSH into k8s Worker Node, perform the following steps:

```
cd vagrant

vagrant status

vagrant ssh k8s-worker1
```
