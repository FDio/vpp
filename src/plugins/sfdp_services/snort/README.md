
# build VPP with Snort DAQ Integration
make build-release

# To run vpp with snort daq
make run-release

# VPP Configuration File
set logging class snort level debug
vcdp tenant add 0 context 0
vcdp snort create-instance name vpp0 queue-size 1024

# The above command will create (1 + number of VPP worker threads) qpairs for Snort instance named vpp0. User can add all of the created qpairs to given Snort thread using '-i vpp0:0.0,1.0,2.0' or distribute them across multiple snort threads '-i vpp0:0.0 -i vpp0:1.0,2.0'.
 
# To run snort with VPP DAQ
sudo ./snort -Q --max-packet-threads 1 --daq-dir /Path/to/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu/daq --daq vpp -i vpp0:1.0

# VPP Configuration to create TAP interfaces
create tap host-ns ns1 host-ip4-addr 192.168.10.2/24 host-ip4-gw 192.168.10.1
create tap host-ns ns2 host-ip4-addr 192.168.20.2/24 host-ip4-gw 192.168.20.1
set int ip addr tap0 192.168.10.1/24
set int ip addr tap1 192.168.20.1/24

# VPP Configuration to connect TAP interfaces to Snort Service
set vcdp interface-input tap0 tenant 0
set vcdp interface-input tap1 tenant 0

# VPP SFDP service chain configuration
set vcdp services tenant 0 vcdp-snort-input  vcdp-l4-lifecycle ip4-lookup forward
set vcdp services tenant 0 vcdp-snort-input vcdp-l4-lifecycle ip4-lookup reverse
# Bring up the TAP interfaces
set int st tap0 up
set int st tap1 up
