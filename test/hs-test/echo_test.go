package main

import (
	"regexp"
	"strconv"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterEchoTests(EchoBuiltinTest, EchoBuiltinBandwidthTest, EchoBuiltinEchoBytesTest, EchoBuiltinRoundtripTest,
		EchoBuiltinUdpLossTest, EchoBuiltinPeriodicReportTest, EchoBuiltinPeriodicReportTotalTest, TlsSingleConnectionTest,
		EchoBuiltinPeriodicReportUDPTest, EchoBuiltinUdpTest, EchoBuiltinHttpTest, EchoBuiltinHttpsTest, EchoBuiltinHttp2Test,
		EchoBuiltinHttp3Test, EchoBuiltinHttpTestBytesTest, EchoBuiltinHttp2ConnectTcpTest, EchoBuiltinHttp3ConnectTcpTest,
		EchoBuiltinHttp2ConnectUdpTest, EchoBuiltinHttp3ConnectUdpTest)
	RegisterEchoMWTests(TcpWithLossMWTest, EchoBuiltinHttp1CpsMWTest, EchoBuiltinHttp2CpsMWTest, EchoBuiltinHttp3CpsMWTest)
	RegisterSoloEcho6Tests(TcpWithLoss6Test)
}

func EchoBuiltinTest(s *EchoSuite) {
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

func EchoBuiltinUdpTest(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
}

func EchoBuiltinBandwidthTest(s *EchoSuite) {
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

func EchoBuiltinPeriodicReportTotalTest(s *EchoSuite) {
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
			AssertEqualWithinThreshold(mbytes, 2*(i+1), 0.1, "amount of transmitted data outside of threshold")
			rtt, _ := strconv.ParseFloat(matches[i][3], 32)
			AssertGreaterThan(rtt, 0.0, "roundtrip time must be greater than 0.0")
		}
		// Verify reporting times
		AssertEqual(matches[0][1], "1.0", "invalid report time")
		AssertEqual(matches[1][1], "2.0", "invalid report time")
		AssertEqual(matches[2][1], "3.0", "invalid report time")
		AssertEqual(matches[3][1], "4.0", "invalid report time")
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinPeriodicReportUDPTest(s *EchoSuite) {
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
			AssertEqualWithinThreshold(mbytes, 1.5, 0.1, "amount of transmitted data outside of threshold")
			rtt, _ := strconv.ParseFloat(matches[i][4], 32)
			AssertGreaterThan(rtt, 0.0, "roundtrip time must be greater than 0.0")
			dgramsSent, _ := strconv.ParseUint(matches[i][5], 10, 32)
			AssertEqualWithinThreshold(dgramsSent, 2048, 20, "sent dgrams outside of threshold")
			dgramsReceived, _ := strconv.ParseUint(matches[i][6], 10, 32)
			AssertEqualWithinThreshold(dgramsReceived, 2048, 50, "received dgrams outside of threshold")
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

func EchoBuiltinPeriodicReportTest(s *EchoSuite) {
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
			AssertGreaterThan(rtt, 0.0, "roundtrip time must be greater than 0.0")
		}
		// Verify time interval numbers
		AssertEqual(matches[0][1], "0.0", "invalid report time")
		AssertEqual(matches[0][2], "1.0", "invalid report time")
		AssertEqual(matches[1][1], "1.0", "invalid report time")
		AssertEqual(matches[1][2], "2.0", "invalid report time")
		AssertEqual(matches[2][1], "2.0", "invalid report time")
		AssertEqual(matches[2][2], "3.0", "invalid report time")
		AssertEqual(matches[3][1], "3.0", "invalid report time")
		AssertEqual(matches[3][2], "4.0", "invalid report time")
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinRoundtripTest(s *EchoSuite) {
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

func EchoBuiltinEchoBytesTest(s *EchoSuite) {
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

func EchoBuiltinUdpLossTest(s *EchoSuite) {
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

func TcpWithLossMWTest(s *EchoSuite) {
	s.CpusPerVppContainer = 2
	s.CpusPerContainer = 1
	s.SetupTest()
	tcpWithLossAndNoLoss(s, s.Containers.ClientVpp.VppInstance, s.Containers.ServerVpp.VppInstance,
		s.Interfaces.Client, s.Interfaces.Server, s.Ports.Port1)
}

func TcpWithLoss6Test(s *Echo6Suite) {
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
	AssertGreaterEqualUnlessCoverageBuild(baseline, withLoss, "Tcp echo: baseline bitrate is lower than bitrate with loss applied")
	AssertGreaterEqualUnlessCoverageBuild(withLoss, uint64(float64(baseline)*0.15), "Tcp echo: bitrate below threshold")
}

func TlsSingleConnectionTest(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri tls://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client uri tls://%s:%s verbose run-time 5", s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)

	Log(o)
	throughput, err := ParseEchoClientTransfer(o)
	AssertNil(err)
	AssertGreaterThan(throughput, uint64(0), "throughput must be > 0")
}

func httpVerifyPeriodicStats(stats string) {
	regex := regexp.MustCompile(`(\d?\.\d)-(\d?.\d)\s+(\d+\.\d+)[KMG]\s+0\s+\d+\.\d+[KMG]b/s\s+(\d?\.\d+)ms`)
	if regex.MatchString(stats) {
		matches := regex.FindAllStringSubmatch(stats, -1)
		// Check we got a correct number of reports
		AssertEqual(5, len(matches))
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinHttpTestBytesTest(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client test-bytes run-time 5 http2 uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpVerifyPeriodicStats(o)
}

func EchoBuiltinHttpTest(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server uri http://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client run-time 5 uri http://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpVerifyPeriodicStats(o)
}

func EchoBuiltinHttpsTest(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client run-time 5 uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpVerifyPeriodicStats(o)
}

func EchoBuiltinHttp2Test(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client run-time 5 http2 uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpVerifyPeriodicStats(o)
}

func EchoBuiltinHttp3Test(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client run-time 5 http3 uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpVerifyPeriodicStats(o)
}

func httpTunnelVerifyPeriodicStats(stats string) {
	regex := regexp.MustCompile(`(\d?\.\d)-(\d?.\d)\s+(\d+\.\d+)[KMG]\s+(\d+\.\d+)[KMG]\s+\d+\.\d+[KMG]b/s\s+(\d?\.\d+)ms`)
	if regex.MatchString(stats) {
		matches := regex.FindAllStringSubmatch(stats, -1)
		// Check we got a correct number of reports
		AssertEqual(5, len(matches))
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinHttp2ConnectTcpTest(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server connect-tcp uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client run-time 5 echo-bytes http2 connect-tcp uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpTunnelVerifyPeriodicStats(o)
}

func EchoBuiltinHttp3ConnectTcpTest(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server connect-tcp uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client run-time 5 echo-bytes http3 connect-tcp uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpTunnelVerifyPeriodicStats(o)
}

func EchoBuiltinHttp2ConnectUdpTest(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server connect-udp uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client run-time 5 echo-bytes http2 connect-udp uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpTunnelVerifyPeriodicStats(o)
}

func EchoBuiltinHttp3ConnectUdpTest(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server connect-udp uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client run-time 5 echo-bytes http3 connect-udp uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpTunnelVerifyPeriodicStats(o)
}

func EchoBuiltinHttp1CpsMWTest(s *EchoSuite) {
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()
	s.CpusPerVppContainer = 3
	s.SetupTest(memoryConfig)
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("test echo server " +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))

	o := clientVpp.Vppctl("test echo client nclients 4000 bytes 64 syn-timeout 40" +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	Log(serverVpp.Vppctl("show http stats"))
	Log(clientVpp.Vppctl("show http stats"))
}

func EchoBuiltinHttp2CpsMWTest(s *EchoSuite) {
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()
	s.CpusPerVppContainer = 3
	s.SetupTest(memoryConfig)
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("test echo server " +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))

	o := clientVpp.Vppctl("test echo client http2 nclients 4000 bytes 64 syn-timeout 40" +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	Log(serverVpp.Vppctl("show http stats"))
	Log(clientVpp.Vppctl("show http stats"))
}

func EchoBuiltinHttp3CpsMWTest(s *EchoSuite) {
	var quicConfig Stanza
	quicConfig.NewStanza("quic").Append("conn-timeout 60000").Close()
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()
	s.CpusPerVppContainer = 3
	s.SetupTest(quicConfig, memoryConfig)
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("test echo server " +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))

	o := clientVpp.Vppctl("test echo client http3 nclients 1000 bytes 64 syn-timeout 40" +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	Log(serverVpp.Vppctl("show http stats"))
	Log(clientVpp.Vppctl("show http stats"))
}
