from asfframework import VppTestRunner
from framework import VppTestCase
import unittest
from config import config
from vpp_vxlan_tunnel import VppVxlanTunnel
from scapy.layers.l2 import Ether
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

    @classmethod
    def tearDownClass(cls):
        for i in cls.pg_interfaces:
            i.unconfig_ip4()
            i.admin_down()
        super(TestSnap, cls).tearDownClass()

    def configure_snap(self):
        # N3IWF side vxlan tunnel interface
        r = VppVxlanTunnel(
            self,
            src=self.pg0.local_ip4,
            dst=self.pg0.remote_ip4,
            src_port=self.dport,
            dst_port=self.dport,
            vni=self.vni,
        )
        r.add_vpp_config()
        self.vapi.sw_interface_set_l2_bridge(
            rx_sw_if_index=r.sw_if_index, bd_id=self.tunnel_bd)

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

        # create BVI interfaces
        l0 = "loop0"
        self.vapi.cli(f"create loopback interface mac {self.pg0.local_mac}")
        self.vapi.cli(f"set interface state {l0} up")
        self.vapi.cli(f"set interface l2 bridge {l0} {self.tunnel_bd} bvi")
        self.vapi.cli(f"set int ip addr {l0} 192.168.1.1/24")

        l1 = "loop1"
        self.vapi.cli(f"create loopback interface mac {self.pg1.local_mac}")
        self.vapi.cli(f"set interface state {l1} up")
        self.vapi.cli(f"set interface l2 bridge {l1} {self.snp_tunnel_bd} bvi")
        self.vapi.cli(f"set int ip addr {l1} 192.168.2.1/24")

        # record DSCP value in IP header
        self.vapi.cli(f"qos record ip {l0}")

        self.vapi.cli(f"ip route add 1.2.3.4/24 via {l1}")
        self.vapi.cli(f"ip route add 4.3.2.0/24 via {l0}")
        self.vapi.cli(f"set ip neighbor {l1} 1.2.3.4 {self.pg1.remote_mac}")
        self.vapi.cli(f"set ip neighbor {l1} 1.2.3.5 {self.pg1.remote_mac}")
        self.vapi.cli(f"set ip neighbor {l0} 4.3.2.1 {self.pg0.remote_mac}")

        # POLICERS
        self.vapi.cli(f"policer add name pol1 rate kbps cir 150000 cb 15000000 type 1r2c conform-action transmit exceed-action drop")
        self.vapi.cli(f"policer add name pol2 rate kbps cir 1500 cb 150000 type 1r2c conform-action transmit exceed-action drop")

        # CLASSIFIERS
        self.vapi.cli(f"classify table miss-next 0 current-data-offset -14 current-data-flag 1 mask l3 ip4 dst")
        self.vapi.cli(f"classify session table-index 0 match l3 ip4 dst 1.2.3.4  policer-hit-next pol1")
        self.vapi.cli(f"classify session table-index 0 match l3 ip4 dst 1.2.3.5  policer-hit-next pol2")
        self.vapi.cli(f"set policer classify interface {l0} ip4-table 0")

        # self.vapi.cli(f"classify session hit-next 1 table-index 0 match l3 ip4 dst 1.2.3.4 opaque-index 42")

        # key = "ip_dst"
        # self.acl_tbl_idx = {}
        # self.create_classify_table(key,
        #         template_classifier.TestClassifier.build_ip_mask(dst_ip="ffffffff"))
        # self.create_classify_session(
        #     self.acl_tbl_idx.get(key),
        #     template_classifier.TestClassifier.build_ip_match(dst_ip="01020304")
        # )

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

    def send_frame_from_snp(self):
        pkt1 = (
            Ether(src="11:11:11:11:11:11", dst=self.pg1.local_mac)
            / IP(src="1.2.3.4", dst="4.3.2.1", tos=32)
            / UDP(sport=10000, dport=20000)
            / Raw("\xa5" * 100))

        frames = [ self.encapsulate_snp(pkt1, self.snp_vni) ]

        n_frames = len(frames)
        self.pg1.add_stream(frames)
        self.pg0.enable_capture()
        self.pg_start()
        out = self.pg0.get_capture(n_frames)

    def send_frame_from_n3iw(self):
        pkt1 = (
            Ether(src="11:11:11:11:11:11", dst=self.pg0.local_mac)
            / IP(src="4.3.2.1", dst="1.2.3.4", tos=40)
            / UDP(sport=20000, dport=10000)
            / Raw("\xa5" * 100))
        pkt2 = (
            Ether(src="11:11:11:11:11:11", dst=self.pg0.local_mac)
            / IP(src="4.3.2.1", dst="1.2.3.5", tos=42)
            / UDP(sport=20000, dport=10000)
            / Raw("\xa5" * 100))
        epkt1 = self.encapsulate_n3(pkt1, self.vni)
        e2 = self.encapsulate_n3(pkt2, self.vni)
        frames = [epkt1, e2]
        n_frames = len(frames)
        # print(epkt1.show())

        # Provide IP flow hash difference.
        # for i in range(n_frames):
        #     frames[i][UDP].dport += i

        self.pg0.add_stream(frames)
        self.pg1.enable_capture()
        self.pg_start()
        out = self.pg1.get_capture(n_frames)
        for i in range(n_frames):
            print(out[i].show())

    def test_snap(self):
        self.dport = 1123
        self.vni = 1020
        self.tunnel_bd = 1
        self.snp_dport = 1124
        self.snp_vni = 1022
        self.snp_tunnel_bd = 2
        bind_layers(UDP, VXLAN, dport=self.dport)
        bind_layers(UDP, VXLAN, dport=self.snp_dport)
        self.configure_snap()
        try:
            self.send_frame_from_n3iw()
        finally:
            print(self.vapi.cli("show trace"))
            print(self.vapi.cli("show int addr"))
            print(self.vapi.cli("show int"))
            print(self.vapi.cli("show vxlan tunnel"))
            # print(self.vapi.cli("show l2fib"))

            print(self.vapi.cli("show classify tables verbose"))
            print(self.vapi.cli("show classify policer type ip4"))
            print(self.vapi.cli("show error"))
            print(self.vapi.cli("show policer"))

if __name__ == "__main__":
    unittest.main(testRunner=VppTestRunner)
