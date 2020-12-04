from trex_stl_lib.api import *


class STLS1:

    def create_stream(self):
        # base_pkt = Ether()/IP(dst="2.2.0.1")/UDP(dport=12)

        # pad = Padding()
        # if len(base_pkt) < 64:
        #     pad_len = 64 - len(base_pkt)
        #     pad.load = '\x00' * pad_len

        # vm = STLVM()

        # vm.tuple_var(name="tuple", ip_min="10.0.0.3", ip_max="10.0.0.202", port_min=1025, port_max=61124, limit_flows = 100000)

        # vm.write(fv_name="tuple.ip", pkt_offset="IP.src")
        # vm.fix_chksum()

        # vm.write(fv_name="tuple.port", pkt_offset="UDP.sport")

        # pkt = STLPktBuilder(pkt=base_pkt/pad, vm=vm)

        # return STLStream(packet=pkt, mode=STLTXCont())

        vm = STLScVmRaw([STLVmTupleGen(ip_min="10.0.0.1", ip_max="10.255.255.254",
                                       port_min=1025, port_max=65535,
                                       name="stuple", limit_flows=10000),
                         STLVmTupleGen(ip_min="2.0.0.1", ip_max="2.255.255.254",
                                       port_min=1025, port_max=65535,
                                       name="dtuple", limit_flows=100000000),

                         # write ip to packet IP.src
                         STLVmWrFlowVar(fv_name="stuple.ip",
                                        pkt_offset="IP.src"),
                         STLVmWrFlowVar(fv_name="dtuple.ip",
                                        pkt_offset="IP.dst"),
                         # fix checksum
                         STLVmFixIpv4(offset="IP"),
                         # write udp.port
                         STLVmWrFlowVar(fv_name="stuple.port",
                                        pkt_offset="UDP.sport"),
                         STLVmWrFlowVar(fv_name="dtuple.port",
                                        pkt_offset="UDP.dport"),
                         ]
                        )

        base_pkt = Ether()/IP(src="16.0.0.1", dst="2.0.0.1")/UDP(dport=12, sport=1025)
        pad = Padding()
        if len(base_pkt) < 64:
            pad_len = 64 - len(base_pkt)
            pad.load = '\x00' * pad_len

        pkt = STLPktBuilder(pkt=base_pkt/pad, vm=vm)

        return STLStream(packet=pkt, mode=STLTXCont())

    def get_streams(self, direction=0, **kwargs):
        return [self.create_stream()]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()
