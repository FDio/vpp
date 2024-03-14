package main

func init() {
	registerVethTests(EchoBuiltinTest)
	registerSoloVethTests(TcpWithLossTest)
}

func EchoBuiltinTest(s *VethsSuite) {
	serverVpp := s.getContainerByName("server-vpp").vppInstance
	serverVeth := s.getInterfaceByName(serverInterfaceName)

	serverVpp.vppctl("test echo server " +
		" uri tcp://" + serverVeth.ip4AddressString() + "/1234")

	clientVpp := s.getContainerByName("client-vpp").vppInstance

	o := clientVpp.vppctl("test echo client nclients 100 bytes 1 verbose" +
		" syn-timeout 100 test-timeout 100" +
		" uri tcp://" + serverVeth.ip4AddressString() + "/1234")
	s.log(o)
	s.assertNotContains(o, "failed:")
}

func TcpWithLossTest(s *VethsSuite) {
	serverVpp := s.getContainerByName("server-vpp").vppInstance

	serverVeth := s.getInterfaceByName(serverInterfaceName)
	serverVpp.vppctl("test echo server uri tcp://%s/20022",
		serverVeth.ip4AddressString())

	clientVpp := s.getContainerByName("client-vpp").vppInstance

	// TODO: investigate why this ping was here:
	// ---------
	// Ensure that VPP doesn't abort itself with NSIM enabled
	// Warning: Removing this ping will make the test fail!
	// clientVpp.vppctl("ping %s", serverVeth.ip4AddressString())
	// ---------

	// Add loss of packets with Network Delay Simulator
	clientVpp.vppctl("set nsim poll-main-thread delay 0.01 ms bandwidth 40 gbit" +
		" packet-size 1400 packets-per-drop 1000")

	clientVpp.vppctl("nsim output-feature enable-disable " + s.getInterfaceByName(clientInterfaceName).name)

	// Do echo test from client-vpp container
	output := clientVpp.vppctl("test echo client uri tcp://%s/20022 verbose echo-bytes mbytes 50",
		serverVeth.ip4AddressString())
	s.log(output)
	s.assertNotEqual(len(output), 0)
	s.assertNotContains(output, "failed: timeout", output)
}
