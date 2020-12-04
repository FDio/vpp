from trex_stl_lib.api import *

class STLS1:

    def __init__ (self):
        self.ip_range = {'local': {'start': "10.0.0.3", 'end': "10.1.255.255"},
                         'external': {'start': "172.16.1.3", 'end': "172.16.1.3"},
                         'remote': {'start': "2.2.0.1", 'end': "2.2.0.1"}}
        self.port_range = {'local': {'start': 1025, 'end': 65535},
                           'remote': {'start': 12, 'end': 12}}

    def create_stream (self, vm):
        base_pkt = Ether()/IP()/UDP()

        if len(base_pkt) < 64:
            pad_len = 64 - len(base_pkt)
            pad = Padding()
            pad.load = '\x00' * pad_len
            base_pkt = base_pkt/pad
            
        pkt = STLPktBuilder(pkt=base_pkt, vm=vm)
        return STLStream(packet=pkt, mode=STLTXCont())

    def get_streams (self, direction = 0, **kwargs):
        if direction == 0:
            ip_src = self.ip_range['remote']
            ip_dst = self.ip_range['external']
            src_port = self.port_range['remote']
            dst_port = self.port_range['local']
        else:
            ip_src = self.ip_range['local']
            ip_dst = self.ip_range['remote']
            src_port = self.port_range['local']
            dst_port = self.port_range['remote']

        vm = STLVM()

        vm.var(name="ip_src", min_value=ip_src['start'], max_value=ip_src['end'], size=4, op="random")
        vm.var(name="ip_dst", min_value=ip_dst['start'], max_value=ip_dst['end'], size=4, op="random")
        vm.var(name="src_port", min_value=src_port['start'], max_value=src_port['end'], size=2, op="random")
        vm.var(name="dst_port", min_value=dst_port['start'], max_value=dst_port['end'], size=2, op="random")

        vm.write(fv_name="ip_src", pkt_offset="IP.src")
        vm.write(fv_name="ip_dst", pkt_offset="IP.dst")
        vm.write(fv_name="src_port", pkt_offset="UDP.sport")
        vm.write(fv_name="dst_port", pkt_offset="UDP.dport")

        vm.fix_chksum()

        return [ self.create_stream(vm) ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



