from datetime import datetime, timedelta
import uuid
import framework
from scapy.contrib.pfcp import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, UDP

def seid():
    return uuid.uuid4().int & (1<<64)-1

DROP_IP = "192.0.2.99"
REDIR_IP = "192.0.2.100"
REDIR_TARGET_IP = "198.51.100.42"

class TestUPF(framework.VppTestCase):
    """Test UPF"""

    @classmethod
    def setUpClass(cls):
        cls.ts = int((datetime.now() - datetime(1900, 1, 1)).total_seconds())
        super(TestUPF, cls).setUpClass()
        try:
            cls.create_pg_interfaces(range(3))
            cls.interfaces = list(cls.pg_interfaces)

            cls.vapi.cli("ip table add 1")
            cls.vapi.cli("ip table add 2")
            # separate assignments are easier to understand for some
            # tools like elpy than this:
            # cls.if_cp, cls.if_access, cls.if_sgi = cls.interfaces
            cls.if_cp = cls.interfaces[0]
            cls.if_access = cls.interfaces[1]
            cls.if_sgi = cls.interfaces[2]
            for n, i in enumerate(cls.interfaces):
                i.admin_up()
                cls.vapi.cli("set interface ip table %s %d" % (i.name, n))
                i.config_ip4()
                i.resolve_arp()
            for cmd in cls.upf_setup_cmds():
                cls.vapi.cli(cmd)
        except Exception:
            super(TestUPF, cls).tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        super(TestUPF, cls).tearDownClass()

    @classmethod
    def upf_setup_cmds(cls):
        return [
            "upf nwi name cp vrf 0",
            "upf nwi name access vrf 1",
            "upf nwi name sgi vrf 2",
            "upf pfcp endpoint ip %s vrf 0" % cls.if_cp.local_ip4,
            "upf gtpu endpoint ip %s nwi cp teid 0x80000000/2" % cls.if_cp.local_ip4,
            "upf tdf ul table vrf 1 ip4 table-id 1001",
            "upf tdf ul enable ip4 %s" % cls.if_access.name,
            "ip route add 0.0.0.0/0 table 2 via %s %s" % (cls.if_sgi.remote_ip4, cls.if_sgi.name),
            "create upf application name TST",
            r"upf application TST rule 3000 add l7 regex ^https?://(.*\\.)*(example)\\.com/",
        ]

    def setUp(self):
        super(TestUPF, self).setUp()
        self.seq = 1

    def tearDown(self):
        super(TestUPF, self).tearDown()

    def test_upf(self):
        try:
            self.associate()
            self.heartbeat()
            self.verify_no_forwarding()
            self.establish_session()
            self.verify_forwarding()
            self.verify_drop()
            # FIXME: the IP redirect is currently also handled by the proxy
            # self.verify_redirect()
            self.delete_session()
            self.verify_no_forwarding()
        finally:
            self.vapi.cli("show error")

    def test_reporting(self):
        try:
            self.associate()
            self.heartbeat()
            self.establish_reporting_session()
            self.verify_reporting()
            self.verify_session_modification()
            self.delete_session()
        finally:
            self.vapi.cli("show error")
        
    def show_commands_at_teardown(self):
        self.logger.info(self.vapi.cli("show upf flows"))
        self.logger.info(self.vapi.cli("show hardware"))

    def chat(self, pkt, expectedResponse, seid=None):
        self.logger.info("REQ: %r" % pkt)
        self.if_cp.add_stream(
            Ether(src=self.if_cp.remote_mac, dst=self.if_cp.local_mac) /
            IP(src=self.if_cp.remote_ip4, dst=self.if_cp.local_ip4) /
            UDP(sport=8805, dport=8805) /
            PFCP(
                version=1, seq=self.seq,
                S=0 if seid is None else 1,
                seid=0 if seid is None else seid) /
            pkt)
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        resp = self.if_cp.get_capture(1)[0][PFCP]
        self.logger.info("RESP: %r" % resp)
        self.assertEqual(resp.seq, self.seq)
        self.seq += 1
        return resp[expectedResponse]

    def associate(self):
        resp = self.chat(PFCPAssociationSetupRequest(IE_list=[
            IE_RecoveryTimeStamp(recovery_time_stamp=self.ts),
            IE_NodeId(node_id_type="FQDN", node_id="ergw")
            ]), PFCPAssociationSetupResponse)
        self.assertEqual(CauseValues[resp[IE_Cause].cause], "Request accepted")
        self.assertIn(b"vpp", resp[IE_EnterpriseSpecific].data)

    def heartbeat(self):
        resp = self.chat(PFCPHeartbeatRequest(IE_list=[
            IE_RecoveryTimeStamp(recovery_time_stamp=self.ts)
            ]), PFCPHeartbeatResponse)
        self.assertIn(IE_RecoveryTimeStamp, resp)

    def establish_session(self):
        cp_ip = self.if_cp.remote_ip4
        ue_ip = self.if_access.remote_ip4
        self.cur_seid = seid()
        resp = self.chat(PFCPSessionEstablishmentRequest(IE_list=[
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(far_id=1),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="SGi-LAN/N6-LAN"),
                    IE_NetworkInstance(network_instance="sgi")
                ])
            ]),
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(far_id=2),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="Access"),
                    IE_NetworkInstance(network_instance="access")
                ])
            ]),
            # FIXME: this is not handled properly :(
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(far_id=3),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="SGi-LAN/N6-LAN"),
                    IE_NetworkInstance(network_instance="sgi"),
                    IE_RedirectInformation(redirect_address_type="IPv4 address",
                                           addr=REDIR_TARGET_IP)
                ])
            ]),
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(DROP=1),
                IE_FAR_Id(far_id=4),
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(far_id=1),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(network_instance="access"),
                    IE_SDF_Filter(FD=1, flow_desc="permit out ip from any to assigned"),
                    IE_SourceInterface(interface="Access"),
                    IE_UE_IP_Address(ipv4=ue_ip, V4=1)
                ]),
                IE_PDR_Id(pdr_id=1),
                IE_Precedence(precedence=200),
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(far_id=2),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(network_instance="sgi"),
                    IE_SDF_Filter(FD=1, flow_desc="permit out ip from any to assigned"),
                    IE_SourceInterface(interface="SGi-LAN/N6-LAN"),
                    IE_UE_IP_Address(ipv4=ue_ip, SD=1, V4=1)
                ]),
                IE_PDR_Id(pdr_id=2),
                IE_Precedence(precedence=200),
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(far_id=3),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(network_instance="access"),
                    IE_SDF_Filter(FD=1, flow_desc="permit out ip from %s to assigned" % REDIR_IP),
                    IE_SourceInterface(interface="Access"),
                    IE_UE_IP_Address(ipv4=ue_ip, V4=1)
                ]),
                IE_PDR_Id(pdr_id=3),
                IE_Precedence(precedence=100),
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(far_id=4),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(network_instance="access"),
                    IE_SDF_Filter(FD=1, flow_desc="permit out ip from %s to assigned" % DROP_IP),
                    IE_SourceInterface(interface="Access"),
                    IE_UE_IP_Address(ipv4=ue_ip, V4=1)
                ]),
                IE_PDR_Id(pdr_id=4),
                IE_Precedence(precedence=100),
            ]),
            IE_FqSEID(ipv4=cp_ip, v4=1, seid=self.cur_seid),
            IE_NodeId(node_id_type=2, node_id="ergw")
        ]), PFCPSessionEstablishmentResponse, seid=self.cur_seid)
        self.assertEqual(CauseValues[resp[IE_Cause].cause], "Request accepted")
        self.assertEqual(resp[IE_FqSEID].ipv4, self.if_cp.local_ip4)
        self.assertEqual(resp[IE_FqSEID].seid, self.cur_seid)

    def establish_reporting_session(self):
        cp_ip = self.if_cp.remote_ip4
        ue_ip = self.if_access.remote_ip4
        self.cur_seid = seid()
        resp = self.chat(PFCPSessionEstablishmentRequest(IE_list=[
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(far_id=1),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="SGi-LAN/N6-LAN"),
                    IE_NetworkInstance(network_instance="sgi")
                ])
            ]),
            IE_CreateFAR(IE_list=[
                IE_ApplyAction(FORW=1),
                IE_FAR_Id(far_id=2),
                IE_ForwardingParameters(IE_list=[
                    IE_DestinationInterface(interface="Access"),
                    IE_NetworkInstance(network_instance="access")
                ])
            ]),
            IE_CreateURR(IE_list=[
                IE_MeasurementMethod(EVENT=1, VOLUM=1, DURAT=1),
                IE_ReportingTriggers(START=1),
                IE_TimeQuota(time_quota=60),
                IE_URR_Id(urr_id=1)
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(far_id=1),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(network_instance="access"),
                    IE_SDF_Filter(FD=1, flow_desc="permit out ip from any to assigned"),
                    IE_SourceInterface(interface="Access"),
                    IE_UE_IP_Address(ipv4=ue_ip, V4=1)
                ]),
                IE_PDR_Id(pdr_id=1),
                IE_Precedence(precedence=200),
                IE_URR_Id(urr_id=1)
            ]),
            IE_CreatePDR(IE_list=[
                IE_FAR_Id(far_id=2),
                IE_PDI(IE_list=[
                    IE_NetworkInstance(network_instance="sgi"),
                    IE_SDF_Filter(FD=1, flow_desc="permit out ip from any to assigned"),
                    IE_SourceInterface(interface="SGi-LAN/N6-LAN"),
                    IE_UE_IP_Address(ipv4=ue_ip, SD=1, V4=1)
                ]),
                IE_PDR_Id(pdr_id=2),
                IE_Precedence(precedence=200),
            ]),
            IE_FqSEID(ipv4=cp_ip, v4=1, seid=self.cur_seid),
            IE_NodeId(node_id_type=2, node_id="ergw")
        ]), PFCPSessionEstablishmentResponse, seid=self.cur_seid)
        self.assertEqual(CauseValues[resp[IE_Cause].cause], "Request accepted")
        self.assertEqual(resp[IE_FqSEID].ipv4, self.if_cp.local_ip4)
        self.assertEqual(resp[IE_FqSEID].seid, self.cur_seid)

    def delete_session(self):
        cp_ip = self.if_cp.remote_ip4
        resp = self.chat(PFCPSessionDeletionRequest(IE_list=[
            IE_FqSEID(ipv4=cp_ip, v4=1, seid=self.cur_seid),
            IE_NodeId(node_id_type=2, node_id="ergw")
        ]), PFCPSessionDeletionResponse, seid=self.cur_seid)
        self.assertEqual(CauseValues[resp[IE_Cause].cause], "Request accepted")

    def verify_no_forwarding(self):
        # Access -> SGi
        self.if_access.add_stream(
            Ether(src=self.if_access.remote_mac, dst=self.if_access.local_mac) /
            IP(src=self.if_access.remote_ip4, dst=self.if_sgi.remote_ip4) /
            UDP(sport=12345, dport=23456) /
            Raw(b"42"))
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.if_sgi.assert_nothing_captured()
        # SGi -> Access
        self.if_sgi.add_stream(
            Ether(src=self.if_access.local_mac, dst=self.if_access.remote_mac) /
            IP(src=self.if_sgi.remote_ip4, dst=self.if_access.remote_ip4) /
            UDP(sport=23456, dport=12345) /
            Raw(b"4242"))
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.if_access.assert_nothing_captured()

    def verify_forwarding(self):
        # Access -> SGi
        self.if_access.add_stream(
            Ether(src=self.if_access.remote_mac, dst=self.if_access.local_mac) /
            IP(src=self.if_access.remote_ip4, dst=self.if_sgi.remote_ip4) /
            UDP(sport=12345, dport=23456) /
            Raw(b"42"))
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        pkt = self.if_sgi.get_capture(1)[0]
        self.assertEqual(pkt[IP].src, self.if_access.remote_ip4)
        self.assertEqual(pkt[IP].dst, self.if_sgi.remote_ip4)
        self.assertEqual(pkt[UDP].sport, 12345)
        self.assertEqual(pkt[UDP].dport, 23456)
        self.assertEqual(pkt[Raw].load, b"42")
        # SGi -> Access
        self.if_sgi.add_stream(
            Ether(src=self.if_access.local_mac, dst=self.if_access.remote_mac) /
            IP(src=self.if_sgi.remote_ip4, dst=self.if_access.remote_ip4) /
            UDP(sport=23456, dport=12345) /
            Raw(b"4242"))
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        pkt = self.if_access.get_capture(1)[0]
        self.assertEqual(pkt[IP].src, self.if_sgi.remote_ip4)
        self.assertEqual(pkt[IP].dst, self.if_access.remote_ip4)
        self.assertEqual(pkt[UDP].sport, 23456)
        self.assertEqual(pkt[UDP].dport, 12345)
        self.assertEqual(pkt[Raw].load, b"4242")

    def verify_drop(self):
        # Access -> SGi
        self.if_access.add_stream(
            Ether(src=self.if_access.remote_mac, dst=self.if_access.local_mac) /
            IP(src=self.if_access.remote_ip4, dst=DROP_IP) /
            UDP(sport=12345, dport=23456) /
            Raw(b"42"))
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        self.if_sgi.assert_nothing_captured()

    def verify_redirect(self):
        # FIXME: the IP redirect is currently also handled by the proxy
        self.if_access.add_stream(
            Ether(src=self.if_access.remote_mac, dst=self.if_access.local_mac) /
            IP(src=self.if_access.remote_ip4, dst=REDIR_IP) /
            UDP(sport=12345, dport=23456) /
            Raw(b"42"))
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        pkt = self.if_sgi.get_capture(1)[0]
        self.assertEqual(pkt[IP].src, self.if_access.remote_ip4)
        self.assertEqual(pkt[IP].dst, REDIR_TARGET_IP)
        self.assertEqual(pkt[UDP].sport, 12345)
        self.assertEqual(pkt[UDP].dport, 23456)
        self.assertEqual(pkt[Raw].load, b"42")

    def verify_reporting(self):
        # Access -> SGi
        self.if_access.add_stream(
            Ether(src=self.if_access.remote_mac, dst=self.if_access.local_mac) /
            IP(src=self.if_access.remote_ip4, dst=self.if_sgi.remote_ip4) /
            UDP(sport=12345, dport=23456) /
            Raw(b"42"))
        self.pg_enable_capture(self.pg_interfaces)
        self.pg_start()
        pkt = self.if_sgi.get_capture(1)[0]
        self.assertEqual(pkt[IP].src, self.if_access.remote_ip4)
        self.assertEqual(pkt[IP].dst, self.if_sgi.remote_ip4)
        self.assertEqual(pkt[UDP].sport, 12345)
        self.assertEqual(pkt[UDP].dport, 23456)
        self.assertEqual(pkt[Raw].load, b"42")
        sr = self.if_cp.get_capture(1)[0][PFCPSessionReportRequest]
        self.logger.info("ZZZZZ SR: %r" % sr)
        self.assertEqual(sr[IE_ReportType].UPIR, 0)
        self.assertEqual(sr[IE_ReportType].ERIR, 0)
        self.assertEqual(sr[IE_ReportType].USAR, 1)
        self.assertEqual(sr[IE_ReportType].DLDR, 0)
        self.assertEqual(sr[IE_URR_Id].urr_id, 1)
        self.assertEqual(sr[IE_UR_SEQN].ur_seqn, 0)
        rt = sr[IE_UsageReportTrigger]
        self.assertEqual(rt.IMMER, 0)
        self.assertEqual(rt.DROTH, 0)
        self.assertEqual(rt.STOPT, 0)
        self.assertEqual(rt.START, 1)
        self.assertEqual(rt.QUHTI, 0)
        self.assertEqual(rt.TIMTH, 0)
        self.assertEqual(rt.VOLTH, 0)
        self.assertEqual(rt.PERIO, 0)
        self.assertEqual(rt.EVETH, 0)
        self.assertEqual(rt.MACAR, 0)
        self.assertEqual(rt.ENVCL, 0)
        self.assertEqual(rt.MONIT, 0)
        self.assertEqual(rt.TERMR, 0)
        self.assertEqual(rt.LIUSA, 0)
        self.assertEqual(rt.TIMQU, 0)
        self.assertEqual(rt.VOLQU, 0)
        self.assertEqual(sr[IE_UE_IP_Address].V4, 1)
        self.assertEqual(sr[IE_UE_IP_Address].V6, 0)
        self.assertEqual(sr[IE_UE_IP_Address].ipv4, self.if_access.remote_ip4)

    def verify_session_modification(self):
        send_len = 0
        for i in range(0, 3):
            to_send = Ether(src=self.if_access.remote_mac, dst=self.if_access.local_mac) / \
                IP(src=self.if_access.remote_ip4, dst=self.if_sgi.remote_ip4) / \
                UDP(sport=12345, dport=23456) / \
                Raw(b"42 foo bar baz")
            send_len += len(to_send[IP])
            self.if_access.add_stream(to_send)
            self.pg_enable_capture(self.pg_interfaces)
            self.pg_start()
            self.if_sgi.get_capture(1)
        resp = self.chat(PFCPSessionModificationRequest(IE_list=[
            IE_QueryURR(IE_list=[IE_URR_Id(urr_id=1)])
        ]), PFCPSessionModificationResponse, seid=self.cur_seid)
        self.assertEqual(CauseValues[resp[IE_Cause].cause], "Request accepted")
        # TODO: check timestamps & duration
        self.assertIn(IE_StartTime, resp)
        self.assertIn(IE_EndTime, resp)
        self.assertIn(IE_DurationMeasurement, resp)
        self.assertIn(IE_UR_SEQN, resp)
        rt = resp[IE_UsageReportTrigger]
        self.assertEqual(rt.IMMER, 1)
        self.assertEqual(rt.DROTH, 0)
        self.assertEqual(rt.STOPT, 0)
        self.assertEqual(rt.START, 0)
        self.assertEqual(rt.QUHTI, 0)
        self.assertEqual(rt.TIMTH, 0)
        self.assertEqual(rt.VOLTH, 0)
        self.assertEqual(rt.PERIO, 0)
        self.assertEqual(rt.EVETH, 0)
        self.assertEqual(rt.MACAR, 0)
        self.assertEqual(rt.ENVCL, 0)
        self.assertEqual(rt.MONIT, 0)
        self.assertEqual(rt.TERMR, 0)
        self.assertEqual(rt.LIUSA, 0)
        self.assertEqual(rt.TIMQU, 0)
        self.assertEqual(rt.VOLQU, 0)
        vm = resp[IE_VolumeMeasurement]
        self.assertTrue(vm.DLVOL)
        self.assertTrue(vm.ULVOL)
        self.assertTrue(vm.TOVOL)
        self.assertEqual(vm.total_volume, send_len)
        self.assertEqual(vm.uplink_volume, send_len)
        self.assertEqual(vm.downlink_volume, 0)
        # TODO: verify more packets in both directions

# TODO: send session report response
# TODO: check for heartbeat requests from UPF
# TODO: check redirects (perhaps IPv4 type redirect) -- currently broken
# TODO: upstream the scapy changes
