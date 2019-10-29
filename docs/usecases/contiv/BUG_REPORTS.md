# Debugging and Reporting Bugs in Contiv-VPP

## Bug Report Structure

- [Deployment description](#describe-deployment):
Briefly describes the deployment, where an issue was spotted,
number of k8s nodes, is DHCP/STN/TAP used.

- [Logs](#collecting-the-logs):
Attach corresponding logs, at least from the vswitch pods.

- [VPP config](#inspect-vpp-config):
Attach output of the show commands.

- [Basic Collection Example](#basic-example)

### Describe Deployment
Since contiv-vpp can be used with different configurations, it is helpful 
to attach the config that was applied. Either attach `values.yaml` passed to the helm chart,
or attach the [corresponding part](https://github.com/contiv/vpp/blob/42b3bfbe8735508667b1e7f1928109a65dfd5261/k8s/contiv-vpp.yaml#L24-L38) from the deployment yaml file.

```
  contiv.yaml: |-
    TCPstackDisabled: true
    UseTAPInterfaces: true
    TAPInterfaceVersion: 2
    NatExternalTraffic: true
    MTUSize: 1500
    IPAMConfig:
      PodSubnetCIDR: 10.1.0.0/16
      PodNetworkPrefixLen: 24
      PodIfIPCIDR: 10.2.1.0/24
      VPPHostSubnetCIDR: 172.30.0.0/16
      VPPHostNetworkPrefixLen: 24
      NodeInterconnectCIDR: 192.168.16.0/24
      VxlanCIDR: 192.168.30.0/24
      NodeInterconnectDHCP: False
```

Information that might be helpful:
 - Whether node IPs are statically assigned, or if DHCP is used
 - STN is enabled
 - Version of TAP interfaces used
 - Output of `kubectl get pods -o wide --all-namespaces`
 

### Collecting the Logs

The most essential thing that needs to be done when debugging and **reporting an issue**
in Contiv-VPP is **collecting the logs from the contiv-vpp vswitch containers**.

#### a) Collecting Vswitch Logs Using kubectl
In order to collect the logs from individual vswitches in the cluster, connect to the master node
and then find the POD names of the individual vswitch containers:

```
$ kubectl get pods --all-namespaces | grep vswitch
kube-system   contiv-vswitch-lqxfp               2/2       Running   0          1h
kube-system   contiv-vswitch-q6kwt               2/2       Running   0          1h
```

Then run the following command, with *pod name* replaced by the actual POD name:
```
$ kubectl logs <pod name> -n kube-system -c contiv-vswitch
```

Redirect the output to a file to save the logs, for example:

```
kubectl logs contiv-vswitch-lqxfp -n kube-system -c contiv-vswitch > logs-master.txt
```

#### b) Collecting Vswitch Logs Using Docker
If option a) does not work, then you can still collect the same logs using the plain docker
command. For that, you need to connect to each individual node in the k8s cluster, and find the container ID of the vswitch container:

```
$ docker ps | grep contivvpp/vswitch
b682b5837e52        contivvpp/vswitch                                        "/usr/bin/supervisor…"   2 hours ago         Up 2 hours                              k8s_contiv-vswitch_contiv-vswitch-q6kwt_kube-system_d09b6210-2903-11e8-b6c9-08002723b076_0
```

Now use the ID from the first column to dump the logs into the `logs-master.txt` file:
```
$ docker logs b682b5837e52 > logs-master.txt
```

#### Reviewing the Vswitch Logs

In order to debug an issue, it is good to start by grepping the logs for the `level=error` string, for example:
```
$ cat logs-master.txt | grep level=error
```

Also, VPP or contiv-agent may crash with some bugs. To check if some process crashed, grep for the string `exit`, for example:
```
$ cat logs-master.txt | grep exit
2018-03-20 06:03:45,948 INFO exited: vpp (terminated by SIGABRT (core dumped); not expected)
2018-03-20 06:03:48,948 WARN received SIGTERM indicating exit request
```

#### Collecting the STN Daemon Logs
In STN (Steal The NIC) deployment scenarios, often need to collect and review the logs
from the STN daemon. This needs to be done on each node:
```
$ docker logs contiv-stn > logs-stn-master.txt
```

#### Collecting Logs in Case of Crash Loop
If the vswitch is crashing in a loop (which can be determined by increasing the number in the `RESTARTS`
column of the `kubectl get pods --all-namespaces` output), the `kubectl logs` or `docker logs` would
give us the logs of the latest incarnation of the vswitch. That might not be the original root cause
of the very first crash, so in order to debug that, we need to disable k8s health check probes to not
restart the vswitch after the very first crash. This can be done by commenting-out the `readinessProbe`
and `livenessProbe` in the contiv-vpp deployment YAML:

```diff
diff --git a/k8s/contiv-vpp.yaml b/k8s/contiv-vpp.yaml
index 3676047..ffa4473 100644
--- a/k8s/contiv-vpp.yaml
+++ b/k8s/contiv-vpp.yaml
@@ -224,18 +224,18 @@ spec:
           ports:
             # readiness + liveness probe
             - containerPort: 9999
-          readinessProbe:
-            httpGet:
-              path: /readiness
-              port: 9999
-            periodSeconds: 1
-            initialDelaySeconds: 15
-          livenessProbe:
-            httpGet:
-              path: /liveness
-              port: 9999
-            periodSeconds: 1
-            initialDelaySeconds: 60
+ #         readinessProbe:
+ #           httpGet:
+ #             path: /readiness
+ #             port: 9999
+ #           periodSeconds: 1
+ #           initialDelaySeconds: 15
+ #         livenessProbe:
+ #           httpGet:
+ #             path: /liveness
+ #             port: 9999
+ #           periodSeconds: 1
+ #           initialDelaySeconds: 60
           env:
             - name: MICROSERVICE_LABEL
               valueFrom:
```

If VPP is the crashing process, please follow the \[CORE_FILES\](CORE_FILES.html) guide and provide the coredump file.


### Inspect VPP Config
Inspect the following areas:
- Configured interfaces (issues related basic node/pod connectivity issues):
```
vpp# sh int addr
GigabitEthernet0/9/0 (up):
  192.168.16.1/24
local0 (dn):
loop0 (up):
  l2 bridge bd_id 1 bvi shg 0
  192.168.30.1/24
tapcli-0 (up):
  172.30.1.1/24
```

- IP forwarding table:
```
vpp# sh ip fib
ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport proto ] locks:[src:(nil):2, src:adjacency:3, src:default-route:1, ]
0.0.0.0/0
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:1 buckets:1 uRPF:0 to:[7:552]]
    [0] [@0]: dpo-drop ip4
0.0.0.0/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:2 buckets:1 uRPF:1 to:[0:0]]
    [0] [@0]: dpo-drop ip4

... 
...

255.255.255.255/32
  unicast-ip4-chain
  [@0]: dpo-load-balance: [proto:ip4 index:5 buckets:1 uRPF:4 to:[0:0]]
    [0] [@0]: dpo-drop ip4
```
- ARP Table:
```
vpp# sh ip arp
    Time           IP4       Flags      Ethernet              Interface       
    728.6616  192.168.16.2     D    08:00:27:9c:0e:9f GigabitEthernet0/8/0
    542.7045  192.168.30.2     S    1a:2b:3c:4d:5e:02 loop0
      1.4241   172.30.1.2      D    86:41:d5:92:fd:24 tapcli-0
     15.2485    10.1.1.2      SN    00:00:00:00:00:02 tapcli-1
    739.2339    10.1.1.3      SN    00:00:00:00:00:02 tapcli-2
    739.4119    10.1.1.4      SN    00:00:00:00:00:02 tapcli-3
```
- NAT configuration (issues related to services):
```
DBGvpp# sh nat44 addresses
NAT44 pool addresses:
192.168.16.10
  tenant VRF independent
  0 busy udp ports
  0 busy tcp ports
  0 busy icmp ports
NAT44 twice-nat pool addresses:
```
```
vpp# sh nat44 static mappings 
NAT44 static mappings:
 tcp local 192.168.42.1:6443 external 10.96.0.1:443 vrf 0  out2in-only
 tcp local 192.168.42.1:12379 external 192.168.42.2:32379 vrf 0  out2in-only
 tcp local 192.168.42.1:12379 external 192.168.16.2:32379 vrf 0  out2in-only
 tcp local 192.168.42.1:12379 external 192.168.42.1:32379 vrf 0  out2in-only
 tcp local 192.168.42.1:12379 external 192.168.16.1:32379 vrf 0  out2in-only
 tcp local 192.168.42.1:12379 external 10.109.143.39:12379 vrf 0  out2in-only
 udp local 10.1.2.2:53 external 10.96.0.10:53 vrf 0  out2in-only
 tcp local 10.1.2.2:53 external 10.96.0.10:53 vrf 0  out2in-only
```
```
vpp# sh nat44 interfaces
NAT44 interfaces:
 loop0 in out
 GigabitEthernet0/9/0 out
 tapcli-0 in out
```
```
vpp# sh nat44 sessions
NAT44 sessions:
  192.168.20.2: 0 dynamic translations, 3 static translations
  10.1.1.3: 0 dynamic translations, 0 static translations
  10.1.1.4: 0 dynamic translations, 0 static translations
  10.1.1.2: 0 dynamic translations, 6 static translations
  10.1.2.18: 0 dynamic translations, 2 static translations
```
- ACL config (issues related to policies):
```
vpp# sh acl-plugin acl
```
- "Steal the NIC (STN)" config (issues related to host connectivity when STN is active):
```
vpp# sh stn rules 
- rule_index: 0
  address: 10.1.10.47
  iface: tapcli-0 (2)
  next_node: tapcli-0-output (410)
```
- Errors:
```
vpp# sh errors
```
- Vxlan tunnels:
```
vpp# sh vxlan tunnels
```
- Vxlan tunnels:
```
vpp# sh vxlan tunnels
```
- Hardware interface information:
```
vpp# sh hardware-interfaces
```

### Basic Example

[contiv-vpp-bug-report.sh][1] is an example of a script that may be a useful starting point to gathering the above information using kubectl.  

Limitations: 
- The script does not include STN daemon logs nor does it handle the special
  case of a crash loop
  
Prerequisites:
- The user specified in the script must have passwordless access to all nodes
  in the cluster; on each node in the cluster the user must have passwordless
  access to sudo.
  
#### Setting up Prerequisites
To enable logging into a node without a password, copy your public key to the following
node:
```
ssh-copy-id <user-id>@<node-name-or-ip-address>
```

To enable running sudo without a password for a given user, enter:
```
$ sudo visudo
```

Append the following entry to run ALL command without a password for a given
user:
```
<userid> ALL=(ALL) NOPASSWD:ALL
```

You can also add user `<user-id>` to group `sudo` and edit the `sudo`
entry as follows:

```
# Allow members of group sudo to execute any command
%sudo	ALL=(ALL:ALL) NOPASSWD:ALL
```

Add user `<user-id>` to group `<group-id>` as follows:
```
sudo adduser <user-id> <group-id>
```
or as follows:
```
usermod -a -G <group-id> <user-id>
```
#### Working with the Contiv-VPP Vagrant Test Bed 
The script can be used to collect data from the [Contiv-VPP test bed created with Vagrant][2].
To collect debug information from this Contiv-VPP test bed, do the
following steps:
* In the directory where you created your vagrant test bed, do:
```
  vagrant ssh-config > vagrant-ssh.conf
```
* To collect the debug information do:
```
  ./contiv-vpp-bug-report.sh -u vagrant -m k8s-master -f <path-to-your-vagrant-ssh-config-file>/vagrant-ssh.conf
```

[1]: https://github.com/contiv/vpp/tree/master/scripts/contiv-vpp-bug-report.sh
[2]: https://github.com/contiv/vpp/blob/master/vagrant/README.md
