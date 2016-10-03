## @package util
#  Module with common functions that should be used by the test cases.
#
#  The module provides a set of tools for setup the test environment

from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr


## Util class
#
#  Test cases that want to use methods defined in Util class should
#  inherit this class.
#
#  class Example(Util, VppTestCase):
#      pass
class Util(object):

    ## Class method to send ARP Request for each VPP IPv4 address in
    #  order to determine VPP interface MAC address to IPv4 bindings.
    #
    #  Resolved MAC address is saved to the VPP_MACS dictionary with interface
    #  index as a key. ARP Request is sent from MAC in MY_MACS dictionary with
    #  interface index as a key.
    #  @param cls The class pointer.
    #  @param args List variable to store indices of VPP interfaces.
    @classmethod
    def resolve_arp(cls, args):
        for i in args:
            ip = cls.VPP_IP4S[i]
            cls.log("Sending ARP request for %s on port %u" % (ip, i))
            arp_req = (Ether(dst="ff:ff:ff:ff:ff:ff", src=cls.MY_MACS[i]) /
                       ARP(op=ARP.who_has, pdst=ip,
                           psrc=cls.MY_IP4S[i], hwsrc=cls.MY_MACS[i]))
            cls.pg_add_stream(i, arp_req)
            cls.pg_enable_capture([i])

            cls.cli(2, "trace add pg-input 1")
            cls.pg_start()
            arp_reply = cls.pg_get_capture(i)[0]
            if arp_reply[ARP].op == ARP.is_at:
                cls.log("VPP pg%u MAC address is %s " % (i, arp_reply[ARP].hwsrc))
                cls.VPP_MACS[i] = arp_reply[ARP].hwsrc
            else:
                cls.log("No ARP received on port %u" % i)
            cls.cli(2, "show trace")
            ## @var ip
            #  <TODO add description>
            ## @var arp_req
            #  <TODO add description>
            ## @var arp_reply
            #  <TODO add description>
            ## @var VPP_MACS
            #  <TODO add description>

    ## Class method to send ND request for each VPP IPv6 address in
    #  order to determine VPP MAC address to IPv6 bindings.
    #
    #  Resolved MAC address is saved to the VPP_MACS dictionary with interface
    #  index as a key. ND Request is sent from MAC in MY_MACS dictionary with
    #  interface index as a key.
    #  @param cls The class pointer.
    #  @param args List variable to store indices of VPP interfaces.
    @classmethod
    def resolve_icmpv6_nd(cls, args):
        for i in args:
            ip = cls.VPP_IP6S[i]
            cls.log("Sending ICMPv6ND_NS request for %s on port %u" % (ip, i))
            nd_req = (Ether(dst="ff:ff:ff:ff:ff:ff", src=cls.MY_MACS[i]) /
                      IPv6(src=cls.MY_IP6S[i], dst=ip) /
                      ICMPv6ND_NS(tgt=ip) /
                      ICMPv6NDOptSrcLLAddr(lladdr=cls.MY_MACS[i]))
            cls.pg_add_stream(i, nd_req)
            cls.pg_enable_capture([i])

            cls.cli(2, "trace add pg-input 1")
            cls.pg_start()
            nd_reply = cls.pg_get_capture(i)[0]
            icmpv6_na = nd_reply['ICMPv6 Neighbor Discovery - Neighbor Advertisement']
            dst_ll_addr = icmpv6_na['ICMPv6 Neighbor Discovery Option - Destination Link-Layer Address']
            cls.VPP_MACS[i] = dst_ll_addr.lladdr
            ## @var ip
            #  <TODO add description>
            ## @var nd_req
            #  <TODO add description>
            ## @var nd_reply
            #  <TODO add description>
            ## @var icmpv6_na
            #  <TODO add description>
            ## @var dst_ll_addr
            #  <TODO add description>
            ## @var VPP_MACS
            #  <TODO add description>

    ## Class method to configure IPv4 addresses on VPP interfaces.
    #
    #  Set dictionary variables MY_IP4S and VPP_IP4S to IPv4 addresses
    #  calculated using interface VPP interface index as a parameter.
    #  /24 IPv4 prefix is used, with VPP interface address host part set
    #  to .1 and MY address set to .2.
    #  Used IPv4 prefix scheme: 172.16.{VPP-interface-index}.0/24.
    #  @param cls The class pointer.
    #  @param args List variable to store indices of VPP interfaces.
    @classmethod
    def config_ip4(cls, args):
        for i in args:
            cls.MY_IP4S[i] = "172.16.%u.2" % i
            cls.VPP_IP4S[i] = "172.16.%u.1" % i
            cls.api("sw_interface_add_del_address pg%u %s/24" % (i, cls.VPP_IP4S[i]))
            cls.log("My IPv4 address is %s" % (cls.MY_IP4S[i]))
            ## @var MY_IP4S
            #  Dictionary variable to store host IPv4 addresses connected to packet
            #  generator interfaces.
            ## @var VPP_IP4S
            #  Dictionary variable to store VPP IPv4 addresses of the packet
            #  generator interfaces.

    ## Class method to configure IPv6 addresses on VPP interfaces.
    #
    #  Set dictionary variables MY_IP6S and VPP_IP6S to IPv6 addresses
    #  calculated using interface VPP interface index as a parameter.
    #  /64 IPv6 prefix is used, with VPP interface address host part set
    #  to ::1 and MY address set to ::2.
    #  Used IPv6 prefix scheme: fd10:{VPP-interface-index}::0/64.
    #  @param cls The class pointer.
    #  @param args List variable to store indices of VPP interfaces.
    @classmethod
    def config_ip6(cls, args):
        for i in args:
            cls.MY_IP6S[i] = "fd10:%u::2" % i
            cls.VPP_IP6S[i] = "fd10:%u::1" % i
            cls.api("sw_interface_add_del_address pg%u %s/64" % (i, cls.VPP_IP6S[i]))
            cls.log("My IPv6 address is %s" % (cls.MY_IP6S[i]))
            ## @var MY_IP6S
            #  Dictionary variable to store host IPv6 addresses connected to packet
            #  generator interfaces.
            ## @var VPP_IP6S
            #  Dictionary variable to store VPP IPv6 addresses of the packet
            #  generator interfaces.
