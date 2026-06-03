package main

import (
	"context"
	"regexp"
	"strconv"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterEchoTests(EchoBuiltinTest, EchoBuiltinClientSessionDisconnectTest, EchoBuiltinBandwidthTest,
		EchoBuiltinEchoBytesTest, EchoBuiltinRoundtripTest, EchoBuiltinUdpLossTest, EchoBuiltinPeriodicReportTest,
		EchoBuiltinPeriodicReportTotalTest, TlsSingleConnectionTest, EchoBuiltinPeriodicReportUDPTest, EchoBuiltinUdpTest,
		EchoBuiltinHttpTest, EchoBuiltinHttpsTest, EchoBuiltinHttp2Test, EchoBuiltinHttp3Test,
		EchoBuiltinHttpTestBytesTest, EchoBuiltinHttp2ConnectTcpTest, EchoBuiltinHttp3ConnectTcpTest,
		EchoBuiltinHttp2ConnectUdpTest, EchoBuiltinHttp3ConnectUdpTest, EchoBuiltinHttp2ConnectUdpBackpressureTest)
	RegisterEchoMWTests(TcpWithLossMWTest, EchoBuiltinHttp1CpsMWTest, EchoBuiltinHttp2CpsMWTest, EchoBuiltinHttp3CpsMWTest,
		EchoBuiltinHttp2ConnectUdpBackpressureMWTest)
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

func EchoBuiltinClientSessionDisconnectTest(s *EchoSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	serverVpp.Vppctl("test echo server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance
	clientCliSocket := clientVpp.Container.GetContainerWorkDir() + "/var/run/vpp/cli.sock"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type clientResult struct {
		output string
		err    error
	}
	done := make(chan clientResult, 1)
	go func() {
		o, err := clientVpp.Container.ExecContext(ctx, false,
			"vppctl -s %s test echo client nclients 2 echo-bytes run-time 30 uri tcp://%s/%s",
			clientCliSocket, s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)
		done <- clientResult{output: o, err: err}
	}()

	clientVpp.WaitForApp("echo_client", 5)

	dataPort, err := strconv.Atoi(s.Ports.Port1)
	AssertNil(err)
	dataPortString := strconv.Itoa(dataPort + 1)
	sessionIDRegex := regexp.MustCompile(`\[(\d+):(\d+)\]`)
	var dataSessions [][]string
	for range 50 {
		sessions := clientVpp.Vppctl("show session verbose proto tcp state ready rmt %s:%s",
			s.Interfaces.Server.Ip4AddressString(), dataPortString)
		dataSessions = sessionIDRegex.FindAllStringSubmatch(sessions, -1)
		if len(dataSessions) >= 2 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	AssertGreaterEqual(len(dataSessions), 2, "echo client data sessions did not become ready")

	time.Sleep(500 * time.Millisecond)

	clientVpp.Vppctl("clear session thread %s session %s", dataSessions[0][1], dataSessions[0][2])

	result := <-done
	Log(result.output)
	if result.err != nil {
		Log("echo client command returned: %v", result.err)
	}
	AssertNotEqual(context.DeadlineExceeded, ctx.Err(), "echo client did not return after session disconnect")
	AssertContains(result.output, "session close")
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

func parseEchoReportMbytes(value string) (float64, error) {
	multiplier := 1 / 1000000.0
	unit := value[len(value)-1]

	switch unit {
	case 'k':
		multiplier = 1 / 1000.0
		value = value[:len(value)-1]
	case 'M':
		multiplier = 1
		value = value[:len(value)-1]
	case 'G':
		multiplier = 1000
		value = value[:len(value)-1]
	}

	bytes, err := strconv.ParseFloat(value, 64)
	return bytes * multiplier, err
}

func EchoBuiltinPeriodicReportTotalTest(s *EchoSuite) {
	regex := regexp.MustCompile(`(\d+\.\d)\s+(\d+(?:\.\d+)?[kMG]?)\s+0\s+\d+(?:\.\d+)?Mb/s\s+(\d*\.?\d+)ms`)
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
		// Verify cumulative transmitted byte totals
		for i := range 4 {
			transmittedMbytes, err := parseEchoReportMbytes(matches[i][2])
			AssertNil(err)
			AssertEqualWithinThreshold(transmittedMbytes, 2*(i+1), 0.1,
				"amount of transmitted data outside of threshold")
			rtt, _ := strconv.ParseFloat(matches[i][3], 32)
			AssertGreaterEqual(rtt, 0.0, "roundtrip time must not be negative")
		}
		// Verify reporting times
		for i := range 3 {
			end, err := strconv.ParseFloat(matches[i][1], 64)
			AssertNil(err)
			AssertEqual(end, float64(i+1), "invalid report time")
		}
		end, err := strconv.ParseFloat(matches[3][1], 64)
		AssertNil(err)
		AssertEqualWithinThreshold(end, 4.0, 0.15, "invalid report time")
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinPeriodicReportUDPTest(s *EchoSuite) {
	regex := regexp.MustCompile(`(\d+\.\d)-(\d+\.\d)\s+(\d+(?:\.\d+)?[kMG]?)\s+(\d+(?:\.\d+)?[kMG]?)\s+\d+(?:\.\d+)?Mb/s\s+(\d*\.?\d+)ms\s+(\d+)/(\d+)`)
	totalRegex := regexp.MustCompile(`sent total (\d+) datagrams, received total (\d+) datagrams, lost (\d+) datagrams`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("test echo client bytes 6000k throughput 12m report-interval 1 echo-bytes" +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindAllStringSubmatch(o, -1)
		AssertGreaterEqual(len(matches), 3, "invalid number of periodic reports")
		// Verify TX numbers
		for i := range matches {
			mbytes, err := parseEchoReportMbytes(matches[i][3])
			AssertNil(err)
			AssertEqualWithinThreshold(mbytes, 1.5, 0.1, "amount of transmitted data outside of threshold")
			rtt, _ := strconv.ParseFloat(matches[i][5], 32)
			AssertGreaterEqual(rtt, 0.0, "roundtrip time must not be negative")
		}
		totalMatches := totalRegex.FindStringSubmatch(o)
		AssertNotEmpty(totalMatches, "invalid echo test client output")
		dgramsSentTotal, _ := strconv.ParseUint(totalMatches[1], 10, 32)
		dgramsReceivedTotal, _ := strconv.ParseUint(totalMatches[2], 10, 32)
		dgramsLost, _ := strconv.ParseUint(totalMatches[3], 10, 32)
		AssertEqualWithinThreshold(dgramsSentTotal, uint64(8192), 300, "sent dgrams outside of threshold")
		AssertEqualWithinThreshold(dgramsReceivedTotal, dgramsSentTotal, 100, "received dgrams outside of threshold")
		AssertEqual(uint64(0), dgramsLost, "lost dgrams outside of threshold")
		// Verify time interval numbers
		for i := range matches {
			start, err := strconv.ParseFloat(matches[i][1], 64)
			AssertNil(err)
			end, err := strconv.ParseFloat(matches[i][2], 64)
			AssertNil(err)
			AssertEqualWithinThreshold(end-start, 1.0, 0.15, "invalid report time")
		}
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func EchoBuiltinPeriodicReportTest(s *EchoSuite) {
	regex := regexp.MustCompile(`(\d+\.\d)-(\d+\.\d)\s+(\d+(?:\.\d+)?[kMG]?)\s+0\s+\d+(?:\.\d+)?Mb/s\s+(\d*\.?\d+)ms`)
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
			mbytes, err := parseEchoReportMbytes(matches[i][3])
			AssertNil(err)
			AssertEqualWithinThreshold(mbytes, 2, 0.1)
			rtt, _ := strconv.ParseFloat(matches[i][4], 32)
			AssertGreaterEqual(rtt, 0.0, "roundtrip time must not be negative")
		}
		// Verify time interval numbers
		for i := range 4 {
			start, err := strconv.ParseFloat(matches[i][1], 64)
			AssertNil(err)
			end, err := strconv.ParseFloat(matches[i][2], 64)
			AssertNil(err)
			AssertEqualWithinThreshold(start, float64(i), 0.15, "invalid report time")
			AssertEqualWithinThreshold(end, float64(i+1), 0.15, "invalid report time")
		}
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

func httpTunnelVerifyActivePeriodicStats(stats string) {
	regex := regexp.MustCompile(`(\d?\.\d)-(\d?.\d)\s+(\d+\.\d+)[KMG]\s+(\d+\.\d+)[KMG]\s+\d+\.\d+[KMG]b/s\s+(\d?\.\d+)ms`)
	if regex.MatchString(stats) {
		matches := regex.FindAllStringSubmatch(stats, -1)
		AssertEqual(5, len(matches))
		for _, match := range matches {
			tx, _ := strconv.ParseFloat(match[3], 32)
			rx, _ := strconv.ParseFloat(match[4], 32)
			AssertGreaterThan(tx, 0.0)
			AssertGreaterThan(rx, 0.0)
		}
	} else {
		AssertEmpty("invalid echo test client output")
	}
}

func echoBuiltinHttp2ConnectUdp(s *EchoSuite, clientExtraArgs, serverExtraArgs string) string {
	serverVpp := s.Containers.ServerVpp.VppInstance
	serverCmd := "test echo server connect-udp uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	if serverExtraArgs != "" {
		serverCmd += " " + serverExtraArgs
	}
	serverVpp.Vppctl(serverCmd)

	clientVpp := s.Containers.ClientVpp.VppInstance
	clientCmd := "test echo client run-time 5 echo-bytes http2 connect-udp uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	if clientExtraArgs != "" {
		clientCmd += " " + clientExtraArgs
	}

	o := clientVpp.Vppctl(clientCmd)
	Log(o)
	AssertNotContains(o, "failed:")
	return o
}

func EchoBuiltinHttp2ConnectUdpBackpressureTest(s *EchoSuite) {
	// Small fifos keep the tunnel close to backpressure and exercise the
	// postponed RX/TX paths fixed for HTTP/2 CONNECT-UDP.
	o := echoBuiltinHttp2ConnectUdp(s, "nclients 2 fifo-size 16k", "fifo-size 16k")
	httpTunnelVerifyActivePeriodicStats(o)
}

func EchoBuiltinHttp2ConnectUdpBackpressureMWTest(s *EchoSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	EchoBuiltinHttp2ConnectUdpBackpressureTest(s)
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
