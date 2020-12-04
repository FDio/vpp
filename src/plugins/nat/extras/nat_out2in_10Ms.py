from trex_stl_lib.api import *

class STLS1:

    def create_stream (self):
        base_pkt = Ether()/IP(src="2.2.0.1")/UDP(sport=12)

        pad = Padding()
        if len(base_pkt) < 64:
            pad_len = 64 - len(base_pkt)
            pad.load = '\x00' * pad_len

        vm = STLVM()

        vm.tuple_var(name="tuple", ip_min="173.16.1.3", ip_max="173.17.135.162", port_min=1025, port_max=1124, limit_flows = 10000000)

        vm.write(fv_name="tuple.ip", pkt_offset="IP.dst")
        vm.fix_chksum()

        vm.write(fv_name="tuple.port", pkt_offset="UDP.dport")

        pkt = STLPktBuilder(pkt=base_pkt/pad, vm=vm)

        return STLStream(packet=pkt, mode=STLTXCont())

    def get_streams (self, direction = 0, **kwargs):
        return [self.create_stream()]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



