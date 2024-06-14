package main

import (
	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(EchoBuiltinTest)
	RegisterSoloVethTests(TcpWithLossTest)
}

func EchoBuiltinTest(s *VethsSuite) {
	serverVpp := s.GetContainerByName("server-vpp").VppInstance
	serverVeth := s.GetInterfaceByName(ServerInterfaceName)

	serverVpp.Vppctl("test echo server " +
		" uri tcp://" + serverVeth.Ip4AddressString() + "/1234")

	clientVpp := s.GetContainerByName("client-vpp").VppInstance

	o := clientVpp.Vppctl("test echo client nclients 100 bytes 1 verbose" +
		" syn-timeout 100 test-timeout 100" +
		" uri tcp://" + serverVeth.Ip4AddressString() + "/1234")
	s.Log(o)
	s.AssertNotContains(o, "failed:")
}

// unstable with multiple workers
func TcpWithLossTest(s *VethsSuite) {
	s.SkipIfMultiWorker()
	serverVpp := s.GetContainerByName("server-vpp").VppInstance

	serverVeth := s.GetInterfaceByName(ServerInterfaceName)
	serverVpp.Vppctl("test echo server uri tcp://%s/20022",
		serverVeth.Ip4AddressString())

	clientVpp := s.GetContainerByName("client-vpp").VppInstance

	// Ensure that VPP doesn't abort itself with NSIM enabled
	// Warning: Removing this ping will make VPP crash!
	clientVpp.Vppctl("ping %s", serverVeth.Ip4AddressString())

	// Add loss of packets with Network Delay Simulator
	clientVpp.Vppctl("set nsim poll-main-thread delay 0.01 ms bandwidth 40 gbit" +
		" packet-size 1400 packets-per-drop 1000")

	name := s.GetInterfaceByName(ClientInterfaceName).Name()
	clientVpp.Vppctl("nsim output-feature enable-disable host-" + name)

	// Do echo test from client-vpp container
	output := clientVpp.Vppctl("test echo client uri tcp://%s/20022 verbose echo-bytes mbytes 50",
		serverVeth.Ip4AddressString())
	s.Log(output)
	s.AssertNotEqual(len(output), 0)
	s.AssertNotContains(output, "failed", output)
}
