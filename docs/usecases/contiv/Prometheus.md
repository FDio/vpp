# Prometheus Statistics

Each contiv-agent exposes statistics in Prometheus format at port `9999` by default. 
Exposed data is split into two groups:
- `/stats`  provides statistics for VPP interfaces managed by contiv-agent
   Prometheus data is a set of counters with labels. For each interface,
   the following counters are exposed: 
   * *inPackets* 
   * *outPackets* 
   * *inBytes*
   * *outBytes*
   * *ipv4Packets*
   * *ipv6Packets*
   * *outErrorPackets*
   * *dropPackets*
   * *inMissPackets*
   * *inNobufPackets*
   * *puntPackets*
   
   Labels let you add additional information to a counter. The *interfaceName* and *node*
   labels are specified for all counters. If an interface is associated with a particular 
   pod, then the *podName* and *podNamespace* labels are also specified for its counters; 
   otherwise, a placeholder value (`--`) is used (for example, for node interconnect 
   interfaces).
- `/metrics` provides general go runtime statistics

To access Prometheus stats of a node you can use `curl localhost:9999/stats` from the node. The output of contiv-agent running at k8s master node looks similar to the following:

```
$ curl localhost:9999/stats
# HELP dropPackets Number of dropped packets for interface
# TYPE dropPackets gauge
dropPackets{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
dropPackets{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 52
dropPackets{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 9
dropPackets{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 12
dropPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP inBytes Number of received bytes for interface
# TYPE inBytes gauge
inBytes{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
inBytes{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 24716
inBytes{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 726
inBytes{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 6113
inBytes{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP inErrorPackets Number of received packets with error for interface
# TYPE inErrorPackets gauge
inErrorPackets{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
inErrorPackets{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 0
inErrorPackets{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 0
inErrorPackets{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 0
inErrorPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP inMissPackets Number of missed packets for interface
# TYPE inMissPackets gauge
inMissPackets{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
inMissPackets{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 0
inMissPackets{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 0
inMissPackets{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 0
inMissPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP inNobufPackets Number of received packets ??? for interface
# TYPE inNobufPackets gauge
inNobufPackets{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
inNobufPackets{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 0
inNobufPackets{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 0
inNobufPackets{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 0
inNobufPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP inPackets Number of received packets for interface
# TYPE inPackets gauge
inPackets{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
inPackets{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 97
inPackets{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 9
inPackets{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 60
inPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP ipv4Packets Number of ipv4 packets for interface
# TYPE ipv4Packets gauge
ipv4Packets{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
ipv4Packets{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 68
ipv4Packets{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 0
ipv4Packets{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 52
ipv4Packets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP ipv6Packets Number of ipv6 packets for interface
# TYPE ipv6Packets gauge
ipv6Packets{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
ipv6Packets{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 26
ipv6Packets{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 9
ipv6Packets{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 8
ipv6Packets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP outBytes Number of transmitted bytes for interface
# TYPE outBytes gauge
outBytes{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
outBytes{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 5203
outBytes{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 0
outBytes{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 17504
outBytes{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP outErrorPackets Number of transmitted packets with error for interface
# TYPE outErrorPackets gauge
outErrorPackets{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
outErrorPackets{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 0
outErrorPackets{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 0
outErrorPackets{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 0
outErrorPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP outPackets Number of transmitted packets for interface
# TYPE outPackets gauge
outPackets{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
outPackets{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 49
outPackets{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 0
outPackets{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 45
outPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP puntPackets Number of punt packets for interface
# TYPE puntPackets gauge
puntPackets{interfaceName="GigabitEthernet0/9/0",node="dev",podName="--",podNamespace="--"} 0
puntPackets{interfaceName="tap-vpp2",node="dev",podName="--",podNamespace="--"} 0
puntPackets{interfaceName="tap0e6439a7a934336",node="dev",podName="web-667bdcb4d8-pxkfs",podNamespace="default"} 0
puntPackets{interfaceName="tap5338a3285ad6bd7",node="dev",podName="kube-dns-6f4fd4bdf-rsz9b",podNamespace="kube-system"} 0
puntPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0

```


In order to browse stats in web UI Prometheus, it must be started locally by following the information in 
the [Prometheus Getting Started Guide](https://prometheus.io/docs/prometheus/latest/getting_started/).

If you start Prometheus on a node, the following sample config can be used:
```yaml 
global:
  scrape_interval:     15s

scrape_configs:
  - job_name: 'contiv_stats'
    metrics_path: '/stats'
    static_configs:
      - targets: ['localhost:9999']
  - job_name: 'contiv_agent'
    # metrics_path defaults to '/metrics'
    static_configs:
      - targets: ['localhost:9999']
```

Once Prometheus is started with the specified config, you should be able access its web UI at
`localhost:9090`.
```
tester@dev:~/Downloads/prometheus-2.1.0.linux-amd64$ ./prometheus --config.file=config.yml
```

If security features are enabled for the HTTP endpoint, then the config must be adjusted:
```yaml
 - job_name: 'contiv_secured'

     scheme: https
     basic_auth:
        username: user
        password: pass
     metrics_path: /stats
     tls_config:
       insecure_skip_verify: true
       # CA certificate to validate API server certificate with.
       #[ ca_file: <filename> ]
     static_configs:
       - targets: ['localhost:9191']
```