.. _Snort_SFDP_Service:

Snort SFDP Service Integration with VPP
This document describes the steps to integrate Snort with VPP using the Snort DAQ (Data Acquisition) module and VPP's SFDP (Service Function Data Plane) framework.


 Prerequisites
- VPP built with SFDP support.
- Snort built with DAQ support.
- Basic understanding of VPP configuration and Snort operation.

 Steps to Integrate Snort with VPP
1. Build VPP with Snort DAQ Integration

::

    # make build-release

2. Run VPP with Snort DAQ

::

    # make run-release

3. Configure VPP to Create Snort Instance

::

    # set logging class snort level debug
    # sfdp tenant add 0 context 0
    # sfdp snort create-instance name vpp0 queue-size 1024

The above command will create (1 + number of VPP worker threads) qpairs for Snort instance named vpp0. User can add all of the created qpairs to given Snort thread using '-i vpp0:0.0,1.0,2.0' or distribute them across multiple snort threads '-i vpp0:0.0 -i vpp0:1.0,2.0'.

4. Configure Snort to Use VPP DAQ
Run Snort with VPP DAQ module on a separate terminal.

::

    # sudo ./snort -Q --max-packet-threads 1 --daq-dir /Path/to/vpp/build-root/install-vpp_debug-native/vpp/lib/x86_64-linux-gnu/daq --daq vpp -i vpp0:1.0


5. VPP Configuration to create TAP interfaces

::

    # create tap host-ns ns1 host-ip4-addr 192.168.10.2/24 host-ip4-gw 192.168.10.1
    # create tap host-ns ns2 host-ip4-addr 192.168.20.2/24 host-ip4-gw 192.168.20.1
    # set int ip addr tap0 192.168.10.1/24
    # set int ip addr tap1 192.168.20.1/24


6. VPP Configuration to connect TAP interfaces to Snort Service

::

    # set sfdp interface-input tap0 tenant 0
    # set sfdp interface-input tap1 tenant 0


7. VPP Configuration to create SFDP service chain for Snort

::

    # set sfdp services tenant 0 sfdp-snort-input  sfdp-l4-lifecycle ip4-lookup forward
    # set sfdp services tenant 0 sfdp-snort-input sfdp-l4-lifecycle ip4-lookup reverse

8. VPP Configuration to bring up the TAP interfaces

::

    # set int st tap0 up
    # set int st tap1 up


Testing the Integration
To test the integration, you can generate (ping, iperf etc) traffic between the two namespaces (ns1 and ns2) created earlier. Snort should be able to inspect the traffic passing through the TAP interfaces.

::

    # ip netns exec ns1 iperf3 -s
    # ip netns exec ns2 iperf3 -c 192.168.10.2

Troubleshooting
- Ensure that VPP and Snort logs are checked for any errors or warnings.
- Verify that the DAQ module is correctly loaded in Snort.
- Make sure that the SFDP service chain is correctly configured in VPP.
- Packet trace in VPP can be enabled to debug packet flow issues.
- Debug logging can be enabled for DAQ module in Snort by adding the following '--daq-var debug' to debug simple ring buffer issues or '--daq-var debug-msg' for detailed packet dump.
