import framework

import config_lark


class TestConfigLark(unittest.TestCase):

    def test_dpdk(self):
        snippet = """ dpdk {
	 # Change default settings for all interfaces
#	 dev default {
#		 #Number of receive queues, enables RSS
#		 #Default is 1
#		 num-rx-queues 3
#
#		 #Number of transmit queues, Default is equal
#		 #to number of worker threads or 1 if no workers treads
#		 num-tx-queues 3
#
#		 #Number of descriptors in transmit and receive rings
#		 #increasing or reducing number can impact performance
#		 #Default is 1024 for both rx and tx
#		 num-rx-desc 512
#		 num-tx-desc 512
#
#		 #VLAN strip offload mode for interface
#		 #Default is off
#		 vlan-strip-offload on
#	 }

	 # Whitelist specific interface by specifying PCI address
	 dev 0000:02:00.0

	 # Blacklist specific device type by specifying PCI vendor:device
     #    Whitelist entries take precedence
	 blacklist 8086:10fb

	 # Set interface name
	 dev 0000:02:00.1 {
		name eth0
	 }

	 # Whitelist specific interface by specifying PCI address and in
	 # addition specify custom parameters for this interface
	 dev 0000:02:00.1 {
		num-rx-queues 2
	 }

	 #Specify bonded interface and its slaves via PCI addresses
	
	 #Bonded interface in XOR load balance mode (mode 2) with L3 and L4 headers
	 vdev eth_bond0,mode=2,slave=0000:02:00.0,slave=0000:03:00.0,xmit_policy=l34
	 vdev eth_bond1,mode=2,slave=0000:02:00.1,slave=0000:03:00.1,xmit_policy=l34
	
	 #Bonded interface in Active-Back up mode (mode 1)
	 vdev eth_bond0,mode=1,slave=0000:02:00.0,slave=0000:03:00.0
	 vdev eth_bond1,mode=1,slave=0000:02:00.1,slave=0000:03:00.1

	 #Change UIO driver used by VPP, Options are: igb_uio, vfio-pci,
	 #uio_pci_generic or auto (default)
	 uio-driver vfio-pci

	 #Disable multi-segment buffers, improves performance but
	 #disables Jumbo MTU support
	 no-multi-seg

	 #Change hugepages allocation per-socket, needed only if there is need for
	 #larger number of mbufs. Default is 256M on each detected CPU socket
	 socket-mem 2048,2048

	 #Disables UDP / TCP TX checksum offload. Typically needed for use
	 #faster vector PMDs (together with no-multi-seg)
	 no-tx-checksum-offload
 }
"""
        p = config_lark.ConfigParser()
        p.parser.parse(snippet)


if __name__ == "__main__":
    framework.main(verbosity=2)
