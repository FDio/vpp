package main

import (
	"regexp"
	"strconv"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(EchoBuiltinTest, EchoBuiltinBandwidthTest, EchoBuiltinEchobytesTest, EchoBuiltinRoundtripTest, EchoBuiltinTestbytesTest)
	RegisterVethMWTests(TcpWithLossTest)
	RegisterSoloVeth6Tests(TcpWithLoss6Test)
}

func EchoBuiltinTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client nclients 100 bytes 1 verbose" +
		" syn-timeout 100 test-timeout 100" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	s.Log(o)
	s.AssertNotContains(o, "failed:")
}

func EchoBuiltinBandwidthTest(s *VethsSuite) {
	regex := regexp.MustCompile(`gbytes\) in (\d+\.\d+) seconds`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client nclients 4 bytes 8m throughput 16m" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	s.Log(o)
	s.AssertContains(o, "Test started")
	s.AssertContains(o, "Test finished")
	if regex.MatchString(o) {
		matches := regex.FindStringSubmatch(o)
		if len(matches) != 0 {
			seconds, _ := strconv.ParseFloat(matches[1], 32)
			// Make sure that we are within 0.1 of the targeted
			// 2 seconds of runtime
			s.AssertEqualWithinThreshold(seconds, 2, 0.1)
		} else {
			s.AssertEmpty("invalid echo test client output")
		}
	} else {
		s.AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinRoundtripTest(s *VethsSuite) {
	regex := regexp.MustCompile(`(\.\d+)ms roundtrip`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client bytes 8m" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	s.Log(o)
	s.AssertContains(o, "Test started")
	s.AssertContains(o, "Test finished")
	if regex.MatchString(o) {
		matches := regex.FindStringSubmatch(o)
		if len(matches) != 0 {
			seconds, _ := strconv.ParseFloat(matches[1], 32)
			// Make sure that we are within ms range
			s.AssertEqualWithinThreshold(seconds, 0.5, 0.5)
		} else {
			s.AssertEmpty("invalid echo test client output")
		}
	} else {
		s.AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinEchobytesTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client echo-bytes verbose uri" +
		" udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	s.Log(o)
	s.AssertNotContains(o, "test echo clients: failed: timeout with 1 sessions")
}

func EchoBuiltinTestbytesTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	// Add loss of packets with Network Delay Simulator
	clientVpp.Vppctl("set nsim poll-main-thread delay 0.1 ms bandwidth 10 mbps packet-size 1460 packets-per-drop 125")
	clientVpp.Vppctl("nsim output-feature enable-disable host-" + s.Interfaces.Client.Name())

	o := clientVpp.Vppctl("test echo client echo-bytes test-bytes verbose bytes 32k test-timeout 1 uri" +
		" udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	s.Log(o)
	s.AssertNotContains(o, "failed")
	s.AssertContains(o, " bytes out of 32768 sent (32768 target)")
}

func tcpWithoutLoss(s *VethsSuite) string {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server uri tcp://%s/"+s.Ports.Port1,
		s.Interfaces.Server.Ip4AddressString())

	clientVpp := s.Containers.ClientVpp.VppInstance

	// Do echo test from client-vpp container
	output := clientVpp.Vppctl("test echo client uri tcp://%s/%s verbose echo-bytes bytes 100m test-timeout 60",
		s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)
	s.Log(output)
	s.AssertNotEqual(len(output), 0)
	s.AssertNotContains(output, "failed", output)

	return output
}

func TcpWithLossTest(s *VethsSuite) {
	s.CpusPerVppContainer = 2
	s.CpusPerContainer = 1
	s.SetupTest()
	s.Log("  * running TcpWithoutLoss")
	output := tcpWithoutLoss(s)
	baseline, err := s.ParseEchoClientTransfer(output)
	s.AssertNil(err)

	clientVpp := s.Containers.ClientVpp.VppInstance
	serverVpp := s.Containers.ServerVpp.VppInstance

	clientVpp.Disconnect()
	clientVpp.Stop()
	s.SetupClientVpp()
	serverVpp.Disconnect()
	serverVpp.Stop()
	s.SetupServerVpp()

	// Add loss of packets with Network Delay Simulator
	s.Log(clientVpp.Vppctl("set nsim poll-main-thread delay 0.01 ms bandwidth 40 gbit" +
		" packet-size 1400 drop-fraction 0.033"))

	s.Log(clientVpp.Vppctl("nsim output-feature enable-disable host-" + s.Interfaces.Client.Name()))

	s.Log("  * running TcpWithLoss")
	output = tcpWithoutLoss(s)

	withLoss, err := s.ParseEchoClientTransfer(output)
	s.AssertNil(err)

	if !s.CoverageRun {
		s.Log(" Baseline: %v gbit/s\nWith loss: %v gbit/s", baseline, withLoss)
		s.AssertGreaterEqual(baseline, withLoss)
		// 0.75, 0.33 = debug build, i7-1185G7, -20%
		s.AssertGreaterEqual(baseline, 0.75)
		s.AssertGreaterEqual(withLoss, 0.33)
	}
}

func tcpWithoutLoss6(s *Veths6Suite) string {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server uri tcp://%s/"+s.Ports.Port1,
		s.Interfaces.Server.Ip6AddressString())

	clientVpp := s.Containers.ClientVpp.VppInstance

	// Do echo test from client-vpp container
	output := clientVpp.Vppctl("test echo client uri tcp://%s/%s verbose echo-bytes bytes 100m test-timeout 60",
		s.Interfaces.Server.Ip6AddressString(), s.Ports.Port1)
	s.Log(output)
	s.AssertNotEqual(len(output), 0)
	s.AssertNotContains(output, "failed", output)

	return output
}

func TcpWithLoss6Test(s *Veths6Suite) {
	s.Log("  * running TcpWithoutLoss")
	output := tcpWithoutLoss6(s)
	baseline, err := s.ParseEchoClientTransfer(output)
	s.AssertNil(err)

	clientVpp := s.Containers.ClientVpp.VppInstance
	serverVpp := s.Containers.ServerVpp.VppInstance

	clientVpp.Disconnect()
	clientVpp.Stop()
	s.SetupClientVpp()
	serverVpp.Disconnect()
	serverVpp.Stop()
	s.SetupServerVpp()

	// Add loss of packets with Network Delay Simulator
	s.Log(clientVpp.Vppctl("set nsim poll-main-thread delay 0.01 ms bandwidth 40 gbit" +
		" packet-size 1400 drop-fraction 0.033"))

	s.Log(clientVpp.Vppctl("nsim output-feature enable-disable host-" + s.Interfaces.Client.Name()))

	s.Log("  * running TcpWithLoss")
	output = tcpWithoutLoss6(s)

	withLoss, err := s.ParseEchoClientTransfer(output)
	s.AssertNil(err)

	if !s.CoverageRun {
		s.Log(" Baseline: %v gbit/s\nWith loss: %v gbit/s", baseline, withLoss)
		s.AssertGreaterEqual(baseline, withLoss)
		// 0.09, 0.03 = debug build, i7-1185G7, -20%
		s.AssertGreaterEqual(baseline, 0.09)
		s.AssertGreaterEqual(withLoss, 0.03)
	}
}
