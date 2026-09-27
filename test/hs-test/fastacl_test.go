package main

import (
	"regexp"
	"strconv"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(FastaclIcmpDropTest, FastaclTcpPortDropTest, FastaclPermitOverrideTest,
		FastaclRuleDeleteTest, FastaclTupleMergeTest)
}

func fastaclPingLoss(s *VethsSuite) float64 {
	o := s.Containers.ClientVpp.VppInstance.Vppctl("ping " + s.Interfaces.Server.Ip4AddressString() +
		" repeat 10 interval 0.01")
	Log(o)
	m := regexp.MustCompile(`(\d+\.?\d*)\s*%\s*packet loss`).FindStringSubmatch(o)
	AssertEqual(2, len(m), "no packet loss line in ping output")
	loss, err := strconv.ParseFloat(m[1], 64)
	AssertNil(err)
	return loss
}

func fastaclArm(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	Log(s.Containers.ClientVpp.VppInstance.Vppctl("ping " + s.Interfaces.Server.Ip4AddressString() + " repeat 2"))
	AssertEqual(float64(0), fastaclPingLoss(s), "ping lost packets before the filter was armed")
	Log(serverVpp.Vppctl("set interface fastacl " + s.Interfaces.Server.VppName()))
	AssertContains(serverVpp.Vppctl("show interface features "+s.Interfaces.Server.VppName()),
		"fastacl-filter")
}

func fastaclRule(s *VethsSuite, rule string) {
	o := s.Containers.ServerVpp.VppInstance.Vppctl("fastacl rule add " + rule)
	Log(o)
	AssertNotContains(o, "error")
}

func fastaclHttpGet(s *VethsSuite, port string) string {
	o := s.Containers.ClientVpp.VppInstance.Vppctl("http cli client uri http://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + port + "/show/version")
	Log(o)
	return o
}

func FastaclIcmpDropTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	fastaclArm(s)
	fastaclRule(s, "order 10 dst "+s.Interfaces.Server.Ip4AddressString()+"/32 proto 1 action drop")

	AssertEqual(float64(100), fastaclPingLoss(s), "ICMP to a dropped prefix got through")
	o := serverVpp.Vppctl("show fastacl rules")
	Log(o)
	AssertContains(o, "drop")
	o = serverVpp.Vppctl("show fastacl aggregate-counters")
	Log(o)
	m := regexp.MustCompile(`Dropped:\s+(\d+)`).FindStringSubmatch(o)
	AssertEqual(2, len(m), "no Dropped line in aggregate counters")
	AssertEqual("10", m[1], "aggregate counters do not show the 10 dropped echo requests")
}

func FastaclTcpPortDropTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	serverVpp.Vppctl("http cli server uri http://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	fastaclArm(s)

	fastaclRule(s, "order 10 dst "+s.Interfaces.Server.Ip4AddressString()+"/32 proto 6 dst-port "+
		s.Ports.Port2+" action drop")
	AssertContains(fastaclHttpGet(s, s.Ports.Port1), "<html>", "a rule on another port dropped HTTP")
	AssertEqual(float64(0), fastaclPingLoss(s), "a TCP rule dropped ICMP")

	fastaclRule(s, "order 20 dst "+s.Interfaces.Server.Ip4AddressString()+"/32 proto 6 dst-port "+
		s.Ports.Port1+" action drop")
	AssertNotContains(fastaclHttpGet(s, s.Ports.Port1), "<html>", "HTTP to a dropped port got through")
}

func FastaclPermitOverrideTest(s *VethsSuite) {
	fastaclArm(s)
	fastaclRule(s, "order 20 dst "+s.Interfaces.Server.Ip4AddressString()+"/24 action drop")
	AssertEqual(float64(100), fastaclPingLoss(s), "ICMP to a dropped prefix got through")

	fastaclRule(s, "order 10 dst "+s.Interfaces.Server.Ip4AddressString()+"/32 proto 1 action permit")
	AssertEqual(float64(0), fastaclPingLoss(s), "a higher-precedence permit did not override the drop")
}

func FastaclRuleDeleteTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	fastaclArm(s)
	fastaclRule(s, "order 10 dst "+s.Interfaces.Server.Ip4AddressString()+"/32 action drop")
	AssertEqual(float64(100), fastaclPingLoss(s), "ICMP to a dropped prefix got through")

	Log(serverVpp.Vppctl("fastacl rule del all"))
	AssertEqual(float64(0), fastaclPingLoss(s), "traffic still dropped after the rule was deleted")
}

func FastaclTupleMergeTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	fastaclArm(s)
	for i, prefix := range []string{"10.40.0.0/24", "10.41.0.0/23", "10.42.0.0/22", "10.43.0.0/21"} {
		fastaclRule(s, "order "+strconv.Itoa(10*(i+1))+" dst "+prefix+" action drop")
	}
	o := serverVpp.Vppctl("show fastacl tuples")
	Log(o)
	AssertContains(o, "tuples: 1")
	AssertContains(o, "tuple-merge: on")
	AssertEqual(float64(0), fastaclPingLoss(s), "rules for other prefixes dropped ICMP")
}
