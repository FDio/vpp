package main

import (
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(EchoBuiltinTest, EchoBuiltinBandwidthTest)
	RegisterSoloVethTests(TcpWithLossTest)
}

func EchoBuiltinTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/1234")

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client nclients 100 bytes 1 verbose" +
		" syn-timeout 100 test-timeout 100" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/1234")
	s.Log(o)
	s.AssertNotContains(o, "failed:")
}

func EchoBuiltinBandwidthTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/1234")

	clientVpp := s.Containers.ClientVpp.VppInstance

	t := time.Now()
	o := clientVpp.Vppctl("test echo client nclients 4 bytes 8m throughput 16m" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/1234")
	s.Log(o)
	s.AssertNotContains(o, "failed:")
	s.AssertContains(o, "2.00 seconds")
	// 2 seconds for echo run and 1.1 for shutdowm
	s.AssertTimeEqualWithinThreshold(time.Now(), t.Add(time.Millisecond*3100), time.Millisecond*100)
}

func TcpWithLossTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server uri tcp://%s/20022",
		s.Interfaces.Server.Ip4AddressString())

	clientVpp := s.Containers.ClientVpp.VppInstance

	// Add loss of packets with Network Delay Simulator
	clientVpp.Vppctl("set nsim poll-main-thread delay 0.01 ms bandwidth 40 gbit" +
		" packet-size 1400 packets-per-drop 1000")

	clientVpp.Vppctl("nsim output-feature enable-disable host-" + s.Interfaces.Server.Name())

	// Do echo test from client-vpp container
	output := clientVpp.Vppctl("test echo client uri tcp://%s/20022 verbose echo-bytes bytes 50m",
		s.Interfaces.Server.Ip4AddressString())
	s.Log(output)
	s.AssertNotEqual(len(output), 0)
	s.AssertNotContains(output, "failed", output)
}
