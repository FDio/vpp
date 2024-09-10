from asfframework import VppTestRunner
from framework import VppTestCase
import unittest
from config import config
from vpp_vxlan_tunnel import VppVxlanTunnel
from scapy.layers.l2 import Ether, Dot1Q
from scapy.layers.vxlan import VXLAN
from scapy.packet import Raw, bind_layers
from scapy.layers.inet import IP, UDP
from template_classifier import TestClassifier
from vpp_policer import VppPolicer, PolicerAction, Dir
import template_classifier
import binascii
from vpp_papi import VppEnum

class TestSnap(VppTestCase):
    """TAS SNAP"""

    @classmethod
    def setUpClass(cls):
        super(TestSnap, cls).setUpClass()
        try:
            cls.flags = 0x8
            cls.create_pg_interfaces(range(2))
            for i in cls.pg_interfaces:
                i.config_ip4().resolve_arp()
                i.admin_up()
        except Exception:
            cls.tearDownClass()
            raise

        cls.remote_mac2 = "22:22:22:22:22:22"

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestSnap, cls).tearDownClass()

    def configure_snap(self):
        self.vapi.cli(f"create bridge-domain {self.tunnel_bd} learn 0 flood 0 uu-flood 0")
        self.vapi.cli(f"create bridge-domain {self.snp_tunnel_bd} learn 0 flood 0 uu-flood 0")

        # N3IWF side subinterface
        self.vapi.cli("create sub-interface pg0 100")
        self.vapi.cli("set interface state pg0.100 up")
        self.vapi.cli(f"set interface l2 bridge pg0.100 {self.tunnel_bd}")

        # SNP side vxlan tunnel interface
        r = VppVxlanTunnel(
            self,
            src=self.pg1.local_ip4,
            dst=self.pg1.remote_ip4,
            src_port=self.snp_dport,
            dst_port=self.snp_dport,
            vni=self.snp_vni,
        )
        r.add_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=r.sw_if_index, bd_id=self.snp_tunnel_bd)

        self.vapi.cli(f"create vxlan tunnel src 172.16.2.1 dst 172.16.2.3 vni {self.vni2} src_port 1144 dst_port 1144")
        self.vapi.cli(f"set interface l2 bridge vxlan_tunnel1 {self.snp_tunnel_bd}")

        # create BVI interfaces
        self.l0mac="10:10:10:10:10:10"
        l0 = "loop0"
        #self.vapi.cli(f"create loopback interface mac {self.pg0.local_mac}")
        self.vapi.cli(f"create loopback interface mac {self.l0mac}")
        self.vapi.cli(f"set interface state {l0} up")
        self.vapi.cli(f"set interface l2 bridge {l0} {self.tunnel_bd} bvi")
        self.vapi.cli(f"set int ip addr {l0} 192.168.1.1/24")

        self.l1mac="20:20:20:20:20:20"
        l1 = "loop1"
        #self.vapi.cli(f"create loopback interface mac {self.pg1.local_mac}")
        self.vapi.cli(f"create loopback interface mac {self.l1mac}")
        self.vapi.cli(f"set interface state {l1} up")
        self.vapi.cli(f"set interface l2 bridge {l1} {self.snp_tunnel_bd} bvi")
        self.vapi.cli(f"set int ip addr {l1} 192.168.2.1/24")

        # record DSCP value in IP header
        self.vapi.cli(f"qos record ip {l0}")

        self.vapi.cli(f"ip route add 1.2.3.4/24 via {l1}")
        self.vapi.cli(f"ip route add 4.3.2.0/24 via pg0") # avoiding loop0 as we dont want record dscp in this direction
        self.vapi.cli(f"set ip neighbor {l1} 1.2.3.4 {self.pg1.remote_mac}")
        self.vapi.cli(f"set ip neighbor {l1} 1.2.3.5 {self.remote_mac2}")

        self.vapi.cli(f"set ip neighbor {l0} 4.3.2.1 {self.pg0.remote_mac}")

        self.vapi.cli(f"l2fib add {self.pg1.remote_mac} {self.snp_tunnel_bd} vxlan_tunnel0")
        self.vapi.cli(f"l2fib add {self.remote_mac2} {self.snp_tunnel_bd} vxlan_tunnel1")
        self.vapi.cli(f"l2fib add {self.pg0.remote_mac} {self.tunnel_bd} pg0.100")

        # POLICERS
        self.vapi.cli(f"policer add name pol1 rate kbps cir 150000 cb 15000000 type 1r2c conform-action transmit exceed-action drop")
        self.vapi.cli(f"policer add name pol2 rate kbps cir 1500 cb 150000 type 1r2c conform-action transmit exceed-action drop")

        # CLASSIFIERS
        self.vapi.cli(f"classify table miss-next 0 current-data-offset -14 current-data-flag 1 mask l3 ip4 dst")
        self.vapi.cli(f"classify session table-index 0 match l3 ip4 dst 1.2.3.4  policer-hit-next pol1")
        self.vapi.cli(f"classify session table-index 0 match l3 ip4 dst 1.2.3.5  policer-hit-next pol2")
        self.vapi.cli(f"set policer classify interface {l0} ip4-table 0")

        # self.vapi.cli(f"classify session hit-next 1 table-index 0 match l3 ip4 dst 1.2.3.4 opaque-index 42")

    def encapsulate_n3(self, pkt, vni):
        return (
            Ether(src=self.pg0.remote_mac, dst=self.pg0.local_mac)
            / IP(src=self.pg0.remote_ip4, dst=self.pg0.local_ip4)
            / UDP(sport=self.dport, dport=self.dport, chksum=0)
            / VXLAN(vni=vni, flags=self.flags)
            / pkt
        )

    def encapsulate_snp(self, pkt, vni):
        return (
            Ether(src=self.pg1.remote_mac, dst=self.pg1.local_mac)
            / IP(src=self.pg1.remote_ip4, dst=self.pg1.local_ip4)
            / UDP(sport=self.snp_dport, dport=self.snp_dport, chksum=0)
            / VXLAN(vni=vni, flags=self.flags)
            / pkt
        )

    # TODO set l2 insterface tag rewrite!
    def send_frame_from_snp(self):
        pkt1 = (
            Ether(src=self.pg1.remote_mac, dst=self.l1mac)
            / IP(src="1.2.3.4", dst="4.3.2.1", tos=32)
            / UDP(sport=10000, dport=20000)
            / Raw("\xa5" * 100))

        frames = [ self.encapsulate_snp(pkt1, self.snp_vni) ]

        n_frames = len(frames)
        self.pg1.add_stream(frames)
        self.pg0.enable_capture()
        self.pg_start()
        out = self.pg0.get_capture(n_frames)
        for i in range(n_frames):
            print(out[i].show())

    def send_frame_from_n3iw(self):
        pkt1 = (
            Ether(src=self.pg0.remote_mac, dst=self.l0mac)
            / Dot1Q(vlan=100)
            / IP(src="4.3.2.1", dst="1.2.3.4", tos=40)
            / UDP(sport=20000, dport=10000)
            / Raw("\xa5" * 100))
        pkt2 = (
            Ether(src=self.remote_mac2, dst=self.l0mac)
            / Dot1Q(vlan=100)
            / IP(src="4.3.2.1", dst="1.2.3.5", tos=42)
            / UDP(sport=20000, dport=10000)
            / Raw("\xa5" * 100))
        frames = [pkt1, pkt2]
        n_frames = len(frames)

        print("INPUT PACKET")
        for pkt in frames:
            print(pkt.show())

        self.pg0.add_stream(frames)
        self.pg1.enable_capture()
        self.pg_start()
        print("OUTPUT PACKET")
        out = self.pg1.get_capture(n_frames)
        for i in range(n_frames):
            print(out[i].show())

    def test_snap(self):
        self.dport = 1123
        self.vni = 1020
        self.vni2 = 1030
        self.tunnel_bd = 1
        self.snp_dport = 1124
        self.snp_vni = 1022
        self.snp_tunnel_bd = 2
        bind_layers(UDP, VXLAN, dport=self.dport)
        bind_layers(UDP, VXLAN, dport=self.snp_dport)
        self.configure_snap()
        try:
            self.send_frame_from_n3iw()
            #self.send_frame_from_snp()
        finally:
            print(self.vapi.cli("show trace"))
            print(self.vapi.cli("show int addr"))
            print(self.vapi.cli("show int"))
            print(self.vapi.cli("show vxlan tunnel"))
            print(self.vapi.cli("show hard"))
            print(self.vapi.cli("show ip neighbors"))
            # print(self.vapi.cli("show l2fib"))

            # print(self.vapi.cli("show classify tables verbose"))
            # print(self.vapi.cli("show classify policer type ip4"))
            # print(self.vapi.cli("show error"))
            # print(self.vapi.cli("show policer"))

if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
