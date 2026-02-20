package main

import (
	"regexp"
	"strconv"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(EchoBuiltinTest, EchoBuiltinBandwidthTest, EchoBuiltinEchobytesTest, EchoBuiltinRoundtripTest,
		EchoBuiltinTestbytesTest, EchoBuiltinPeriodicReportTest, EchoBuiltinPeriodicReportTotalTest, TlsSingleConnectionTest,
		EchoBuiltinPeriodicReportUDPTest, EchoBuiltinUdpTest)
	RegisterVethMWTests(TcpWithLossMWTest)
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
	Log(o)
	AssertNotContains(o, "failed:")
}

func EchoBuiltinUdpTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
}

func EchoBuiltinBandwidthTest(s *VethsSuite) {
	regex := regexp.MustCompile(`gbytes\) in (\d+\.\d+) seconds`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client nclients 4 bytes 2m throughput 32m" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindStringSubmatch(o)
		if len(matches) != 0 {
			seconds, _ := strconv.ParseFloat(matches[1], 32)
			// Make sure that we are within 0.25 of the targeted
			// 2 seconds of runtime
			AssertEqualWithinThreshold(seconds, 2, 0.25)
		} else {
			AssertEmpty("invalid echo test client output")
		}
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinPeriodicReportTotalTest(s *VethsSuite) {
	regex := regexp.MustCompile(`(\d?\.\d)\s+(\d+\.\d+)M\s+0\s+\d+\.\d+Mb/s\s+(\d?\.\d+)ms`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client bytes 7900k throughput 16m report-interval-total 1" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindAllStringSubmatch(o, -1)
		// Check we got a correct number of reports
		AssertEqual(4, len(matches))
		// Verify TX numbers
		for i := range 4 {
			mbytes, _ := strconv.ParseFloat(matches[i][2], 32)
			AssertEqualWithinThreshold(mbytes, 2*(i+1), 0.1)
			rtt, _ := strconv.ParseFloat(matches[i][3], 32)
			AssertGreaterThan(rtt, 0.0)
		}
		// Verify reporting times
		AssertEqual(matches[0][1], "1.0")
		AssertEqual(matches[1][1], "2.0")
		AssertEqual(matches[2][1], "3.0")
		AssertEqual(matches[3][1], "4.0")
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinPeriodicReportUDPTest(s *VethsSuite) {
	regex := regexp.MustCompile(`(\d?\.\d)-(\d?.\d)\s+(\d+\.\d+)M\s+\d?\.\d+M\s+\d+\.\d+Mb/s\s+(\d?\.\d+)ms\s+(\d+)/(\d+)`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client bytes 6000k throughput 12m report-interval 1 echo-bytes" +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindAllStringSubmatch(o, -1)
		// Check we got a correct number of reports
		AssertEqual(4, len(matches))
		// Verify TX numbers
		for i := range 4 {
			mbytes, _ := strconv.ParseFloat(matches[i][3], 32)
			AssertEqualWithinThreshold(mbytes, 1.5, 0.1)
			rtt, _ := strconv.ParseFloat(matches[i][4], 32)
			AssertGreaterThan(rtt, 0.0)
			dgramsSent, _ := strconv.ParseUint(matches[i][5], 10, 32)
			AssertEqualWithinThreshold(dgramsSent, 2048, 20)
			dgramsReceived, _ := strconv.ParseUint(matches[i][6], 10, 32)
			AssertEqualWithinThreshold(dgramsReceived, 2048, 50)
		}
		// Verify time interval numbers
		AssertEqual(matches[0][1], "0.0")
		AssertEqual(matches[0][2], "1.0")
		AssertEqual(matches[1][1], "1.0")
		AssertEqual(matches[1][2], "2.0")
		AssertEqual(matches[2][1], "2.0")
		AssertEqual(matches[2][2], "3.0")
		AssertEqual(matches[3][1], "3.0")
		AssertEqual(matches[3][2], "4.0")
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinPeriodicReportTest(s *VethsSuite) {
	regex := regexp.MustCompile(`(\d?\.\d)-(\d?.\d)\s+(\d+\.\d+)M\s+0\s+\d+\.\d+Mb/s\s+(\d?\.\d+)ms`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client bytes 7900k throughput 16m report-interval 1" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindAllStringSubmatch(o, -1)
		// Check we got a correct number of reports
		AssertEqual(4, len(matches))
		// Verify TX numbers
		for i := range 4 {
			mbytes, _ := strconv.ParseFloat(matches[i][3], 32)
			AssertEqualWithinThreshold(mbytes, 2, 0.1)
			rtt, _ := strconv.ParseFloat(matches[i][4], 32)
			AssertGreaterThan(rtt, 0.0)
		}
		// Verify time interval numbers
		AssertEqual(matches[0][1], "0.0")
		AssertEqual(matches[0][2], "1.0")
		AssertEqual(matches[1][1], "1.0")
		AssertEqual(matches[1][2], "2.0")
		AssertEqual(matches[2][1], "2.0")
		AssertEqual(matches[2][2], "3.0")
		AssertEqual(matches[3][1], "3.0")
		AssertEqual(matches[3][2], "4.0")
	} else {
		AssertEmpty("invalid echo test client output")
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
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindStringSubmatch(o)
		if len(matches) != 0 {
			seconds, _ := strconv.ParseFloat(matches[1], 32)
			// Make sure that we are within ms range
			AssertEqualWithinThreshold(seconds, 0.5, 0.5)
		} else {
			AssertEmpty("invalid echo test client output")
		}
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinEchobytesTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client echo-bytes verbose uri" +
		" udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	AssertContains(o, "sent total 6 datagrams, received total 6 datagrams")
	AssertNotContains(o, "test echo clients: failed: timeout with 1 sessions")
}

func EchoBuiltinTestbytesTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	// Add loss of packets with Network Delay Simulator
	clientVpp.Vppctl("set nsim poll-main-thread delay 0.1 ms bandwidth 10 mbps packet-size 1460 packets-per-drop 125")
	clientVpp.Vppctl("nsim output-feature enable-disable " + s.Interfaces.Client.VppName())

	o := clientVpp.Vppctl("test echo client echo-bytes test-bytes verbose bytes 32k test-timeout 1 uri" +
		" udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed")
	AssertContains(o, "lost")
	AssertContains(o, " bytes out of 32768 sent (32768 target)")
}

type tcpWithLossInterface interface {
	SetupClientVpp()
	SetupServerVpp()
}

func tcpEcho(port string, ip string, clientVpp *VppInstance, serverVpp *VppInstance) string {
	serverVpp.Vppctl("test echo server fifo-size 64k uri tcp://%s/%s", ip, port)

	// Do echo test from client-vpp container
	output := clientVpp.Vppctl("test echo client fifo-size 64k uri tcp://%s/%s verbose echo-bytes run-time 10",
		ip, port)
	Log(output)
	AssertNotEqual(len(output), 0)
	AssertNotContains(output, "failed", output)

	return output
}

func TcpWithLossMWTest(s *VethsSuite) {
	s.CpusPerVppContainer = 2
	s.CpusPerContainer = 1
	s.SetupTest()
	tcpWithLossAndNoLoss(s, s.Containers.ClientVpp.VppInstance, s.Containers.ServerVpp.VppInstance,
		s.Interfaces.Client, s.Interfaces.Server, s.Ports.Port1)
}

func TcpWithLoss6Test(s *Veths6Suite) {
	tcpWithLossAndNoLoss(s, s.Containers.ClientVpp.VppInstance, s.Containers.ServerVpp.VppInstance,
		s.Interfaces.Client, s.Interfaces.Server, s.Ports.Port1)
}

// runs tcp echo without loss, then with loss
func tcpWithLossAndNoLoss(s tcpWithLossInterface, clientVpp *VppInstance,
	serverVpp *VppInstance, clientIf *NetInterface, serverIf *NetInterface, port string) {
	Log(clientVpp.Vppctl("set nsim poll-main-thread delay 10 ms bandwidth 40 gbit"))
	Log(clientVpp.Vppctl("nsim output-feature enable-disable " + clientIf.VppName()))

	var serverAddress string
	if serverIf.Ip6AddressString() == "" {
		serverAddress = serverIf.Ip4AddressString()
	} else {
		serverAddress = serverIf.Ip6AddressString()
	}

	Log("  * running TcpWithoutLoss")
	output := tcpEcho(port, serverAddress, clientVpp, serverVpp)
	baseline, err := ParseEchoClientTransfer(output)
	AssertNil(err)

	clientVpp.Disconnect()
	clientVpp.Stop()
	s.SetupClientVpp()
	serverVpp.Disconnect()
	serverVpp.Stop()
	s.SetupServerVpp()

	// Add loss of packets with Network Delay Simulator
	Log(clientVpp.Vppctl("set nsim poll-main-thread delay 10 ms bandwidth 40 gbit" +
		" packet-size 1400 drop-fraction 0.033"))

	Log(clientVpp.Vppctl("nsim output-feature enable-disable " + clientIf.VppName()))

	Log("  * running TcpWithLoss")
	output = tcpEcho(port, serverAddress, clientVpp, serverVpp)

	withLoss, err := ParseEchoClientTransfer(output)
	AssertNil(err)

	Log("\nBaseline:  %d bytes/s\nWith loss: %d bytes/s", baseline, withLoss)
	AssertGreaterEqualUnlessCoverageBuild(baseline, withLoss)
	AssertGreaterEqualUnlessCoverageBuild(withLoss, uint64(float64(baseline)*0.15))
}

func TlsSingleConnectionTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri tls://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client uri tls://%s:%s verbose run-time 5", s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)

	Log(o)
	throughput, err := ParseEchoClientTransfer(o)
	AssertNil(err)
	AssertGreaterThan(throughput, uint64(0))
}
