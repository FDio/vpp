package main

import (
	"context"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	. "fd.io/hs-test/infra"
)

const tcpChainedBufferMTU = 9000

func init() {
	RegisterVperfTests(VperfBuiltinTest, VperfBuiltinClientSessionDisconnectTest, VperfBuiltinBandwidthTest,
		VperfBuiltinEchoBytesTest, VperfBuiltinRoundtripTest, VperfBuiltinUdpLossTest, VperfBuiltinPeriodicReportTest,
		VperfBuiltinPeriodicReportTotalTest, TlsSingleConnectionTest, VperfBuiltinPeriodicReportUDPTest, VperfBuiltinUdpTest,
		VperfBuiltinTcpNoTxCsumOffloadTest, VperfBuiltinTcpChainedBufferTest,
		VperfBuiltinUdpNoTxCsumOffloadTest, VperfBuiltinHttpTest, VperfBuiltinHttpsTest, VperfBuiltinHttp2Test,
		VperfBuiltinHttp3Test, VperfBuiltinHttpTestBytesTest, VperfBuiltinHttp2ConnectTcpTest, VperfBuiltinHttp3ConnectTcpTest,
		VperfBuiltinHttp2ConnectUdpTest, VperfBuiltinHttp3ConnectUdpTest, VperfBuiltinHttp2ConnectUdpBackpressureTest)
	RegisterVperfMWTests(TcpWithLossMWTest, TcpChainedBufferWithLossMWTest, VperfBuiltinHttp1CpsMWTest,
		VperfBuiltinHttp2CpsMWTest, VperfBuiltinHttp3CpsMWTest, VperfBuiltinHttp2ConnectUdpBackpressureMWTest)
	RegisterVperf6Tests(TcpWithLoss6Test)
}

func VperfBuiltinTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client nclients 100 bytes 1 verbose" +
		" syn-timeout 100 test-timeout 100" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
}

func VperfBuiltinClientSessionDisconnectTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	serverVpp.Vppctl("vperf server " +
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
			"vppctl -s %s vperf client nclients 2 echo-bytes run-time 30 uri tcp://%s/%s",
			clientCliSocket, s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)
		done <- clientResult{output: o, err: err}
	}()

	clientVpp.WaitForApp("vperf_client", 5)

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
	AssertGreaterEqual(len(dataSessions), 2, "vperf client data sessions did not become ready")

	time.Sleep(500 * time.Millisecond)

	clientVpp.Vppctl("clear session thread %s session %s", dataSessions[0][1], dataSessions[0][2])

	result := <-done
	Log(result.output)
	if result.err != nil {
		Log("vperf client command returned: %v", result.err)
	}
	AssertNotEqual(context.DeadlineExceeded, ctx.Err(), "vperf client did not return after session disconnect")
	AssertContains(result.output, "session close")
}

func VperfBuiltinUdpTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
}

func VperfBuiltinTcpNoTxCsumOffloadTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	AssertContains(serverVpp.Vppctl("set tcp csum-offload disable"), "disabled")
	AssertContains(clientVpp.Vppctl("set tcp csum-offload disable"), "disabled")
	AssertContains(serverVpp.Vppctl("show tcp config"), "checksum offload: disabled")
	AssertContains(clientVpp.Vppctl("show tcp config"), "checksum offload: disabled")

	serverVpp.Vppctl("vperf server fifo-size 64k uri tcp://%s/%s",
		s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)

	o := clientVpp.Vppctl("vperf client fifo-size 64k bytes 64k echo-bytes test-bytes "+
		"verbose test-timeout 5 uri tcp://%s/%s", s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed")
	AssertContains(o, "65536 bytes")
	throughput, err := ParseVperfClientTransfer(o)
	AssertNil(err)
	AssertGreaterThan(throughput, uint64(0), "throughput must be > 0")
}

func VperfBuiltinTcpChainedBufferTest(s *VperfSuite) {
	configureTcpChainedBufferMTU(s)

	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString()

	serverVpp.Vppctl("vperf server fifo-size 256k uri tcp://%s/%s", serverAddress, s.Ports.Port1)

	o := clientVpp.Vppctl("vperf client fifo-size 256k bytes 128k max-tx-chunk 64k "+
		"echo-bytes test-bytes verbose test-timeout 10 uri tcp://%s/%s",
		serverAddress, s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed")
	AssertContains(o, "131072 bytes")
	throughput, err := ParseVperfClientTransfer(o)
	AssertNil(err)
	AssertGreaterThan(throughput, uint64(0), "throughput must be > 0")
}

func VperfBuiltinUdpNoTxCsumOffloadTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	AssertContains(serverVpp.Vppctl("set udp csum-offload disable"), "disabled")
	AssertContains(clientVpp.Vppctl("set udp csum-offload disable"), "disabled")

	serverVpp.Vppctl("vperf server uri udp://%s/%s", s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)
	AssertContains(serverVpp.Vppctl("show session verbose 2"), "no-csum-offload")

	o := clientVpp.Vppctl("vperf client bytes 32k echo-bytes test-bytes verbose "+
		"test-timeout 5 uri udp://%s/%s", s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed")
	AssertContains(o, "sent total")
	AssertContains(o, "received total")
	throughput, err := ParseVperfClientTransfer(o)
	AssertNil(err)
	AssertGreaterThan(throughput, uint64(0), "throughput must be > 0")
}

func VperfBuiltinBandwidthTest(s *VperfSuite) {
	regex := regexp.MustCompile(`gbytes\) in (\d+\.\d+) seconds`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client nclients 4 bytes 2m throughput 32m" +
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
			AssertEmpty("invalid vperf client output")
		}
	} else {
		AssertEmpty("invalid vperf client output")
	}
}

func VperfBuiltinPeriodicReportTotalTest(s *VperfSuite) {
	regex := regexp.MustCompile(`(\d+\.\d)\s+(\d+(?:\.\d+)?)M\s+0\s+\d+(?:\.\d+)?Mb/s\s+(\d*\.?\d+)ms`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client bytes 7900k throughput 16m report-interval-total 1" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindAllStringSubmatch(o, -1)
		// Check we got a correct number of reports
		AssertEqual(4, len(matches))
		// Verify cumulative transmitted byte totals
		for i := range 4 {
			transmittedMbytes, err := strconv.ParseFloat(matches[i][2], 64)
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
		AssertEmpty("invalid vperf client output")
	}
}

func VperfBuiltinPeriodicReportUDPTest(s *VperfSuite) {
	regex := regexp.MustCompile(`(\d+\.\d)-(\d+\.\d)\s+(\d+(?:\.\d+)?)M\s+(\d+(?:\.\d+)?)M\s+\d+(?:\.\d+)?Mb/s\s+(\d*\.?\d+)ms\s+(\d+)/(\d+)`)
	totalRegex := regexp.MustCompile(`sent total (\d+) datagrams, received total (\d+) datagrams, lost (\d+) datagrams`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client bytes 6000k throughput 12m report-interval 1 echo-bytes" +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindAllStringSubmatch(o, -1)
		AssertGreaterEqual(len(matches), 3, "invalid number of periodic reports")
		// Verify TX numbers
		for i := range matches {
			mbytes, err := strconv.ParseFloat(matches[i][3], 64)
			AssertNil(err)
			AssertEqualWithinThreshold(mbytes, 1.5, 0.1, "amount of transmitted data outside of threshold")
			rtt, _ := strconv.ParseFloat(matches[i][5], 32)
			AssertGreaterEqual(rtt, 0.0, "roundtrip time must not be negative")
		}
		totalMatches := totalRegex.FindStringSubmatch(o)
		AssertNotEmpty(totalMatches, "invalid vperf client output")
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
			AssertEqual(start, float64(i), "invalid report time")
			if i == len(matches)-1 {
				AssertEqualWithinThreshold(end, float64(i+1), 0.15, "invalid report time")
			} else {
				AssertEqual(end, float64(i+1), "invalid report time")
			}
		}
	} else {
		AssertEmpty("invalid vperf client output")
	}
}

func VperfBuiltinPeriodicReportTest(s *VperfSuite) {
	regex := regexp.MustCompile(`(\d+\.\d)-(\d+\.\d)\s+(\d+(?:\.\d+)?)M\s+0\s+\d+(?:\.\d+)?Mb/s\s+(\d*\.?\d+)ms`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client bytes 7900k throughput 16m report-interval 1" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindAllStringSubmatch(o, -1)
		// Check we got a correct number of reports
		AssertEqual(4, len(matches))
		// Verify TX numbers
		for i := range 4 {
			mbytes, err := strconv.ParseFloat(matches[i][3], 64)
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
			AssertEqual(start, float64(i), "invalid report time")
			if i == 3 {
				AssertEqualWithinThreshold(end, float64(i+1), 0.15, "invalid report time")
			} else {
				AssertEqual(end, float64(i+1), "invalid report time")
			}
		}
	} else {
		AssertEmpty("invalid vperf client output")
	}
}

func VperfBuiltinRoundtripTest(s *VperfSuite) {
	regex := regexp.MustCompile(`(\.\d+)ms roundtrip`)
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server " +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client bytes 8m" +
		" uri tcp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	if regex.MatchString(o) {
		matches := regex.FindStringSubmatch(o)
		if len(matches) != 0 {
			seconds, _ := strconv.ParseFloat(matches[1], 32)
			// Make sure that we are within ms range
			AssertEqualWithinThreshold(seconds, 0.5, 0.5)
		} else {
			AssertEmpty("invalid vperf client output")
		}
	} else {
		AssertEmpty("invalid vperf client output")
	}
}

func VperfBuiltinEchoBytesTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client echo-bytes verbose uri" +
		" udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	AssertContains(o, "sent total 6 datagrams, received total 6 datagrams")
	AssertNotContains(o, "vperf client: failed: timeout with 1 sessions")
}

func VperfBuiltinUdpLossTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server " +
		" uri udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	// Add loss of packets with Network Delay Simulator
	clientVpp.Vppctl("set nsim poll-main-thread delay 0.1 ms bandwidth 10 mbps packet-size 1460 packets-per-drop 125")
	clientVpp.Vppctl("nsim output-feature enable-disable " + s.Interfaces.Client.VppName())

	o := clientVpp.Vppctl("vperf client echo-bytes test-bytes verbose bytes 32k test-timeout 1 uri" +
		" udp://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed")
	AssertContains(o, "lost")
	AssertContains(o, " bytes out of 32768 sent (32768 target)")
}

func setTcpChainedBufferLinuxLinkMTU(ifName string, mtu int) {
	mtuString := strconv.Itoa(mtu)
	cmd := exec.Command("ip", "link", "set", "dev", ifName, "mtu", mtuString)
	Log(cmd.String())
	o, err := cmd.CombinedOutput()
	AssertNil(err, string(o))
}

func setTcpChainedBufferVethMTU(s *VethsSuite, mtu int) {
	for _, nc := range s.NetConfigs {
		if nc.Type() == Bridge {
			setTcpChainedBufferLinuxLinkMTU(nc.Name(), mtu)
		}
	}

	for _, intf := range []*NetInterface{s.Interfaces.Server, s.Interfaces.Client} {
		setTcpChainedBufferLinuxLinkMTU(intf.Name(), mtu)
		setTcpChainedBufferLinuxLinkMTU(intf.Host.Name(), mtu)
	}
}

func setTcpChainedBufferVppInterfaceMTU(vpp *VppInstance, intf *NetInterface, mtu int) {
	o := vpp.Vppctl("set interface mtu %d %s", mtu, intf.VppName())
	Log(o)
	AssertNotContains(o, "unknown input")
	AssertNotContains(o, "error")
}

func configureTcpChainedBufferMTU(s *VperfSuite) {
	expected := "TCP default mtu: " + strconv.Itoa(tcpChainedBufferMTU)
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	setTcpChainedBufferVethMTU(&s.VethsSuite, tcpChainedBufferMTU)
	setTcpChainedBufferVppInterfaceMTU(serverVpp, s.Interfaces.Server, tcpChainedBufferMTU)
	setTcpChainedBufferVppInterfaceMTU(clientVpp, s.Interfaces.Client, tcpChainedBufferMTU)
	AssertContains(serverVpp.Vppctl("set tcp mtu %d", tcpChainedBufferMTU), expected)
	AssertContains(clientVpp.Vppctl("set tcp mtu %d", tcpChainedBufferMTU), expected)

	serverTcpConfig := serverVpp.Vppctl("sh tcp config")
	clientTcpConfig := clientVpp.Vppctl("sh tcp config")
	Log(serverTcpConfig)
	Log(clientTcpConfig)
	AssertContains(serverTcpConfig, "default mtu: "+strconv.Itoa(tcpChainedBufferMTU))
	AssertContains(clientTcpConfig, "default mtu: "+strconv.Itoa(tcpChainedBufferMTU))
}

type tcpWithLossInterface interface {
	SetupClientVpp()
	SetupServerVpp()
}

type tcpWithLossConfig struct {
	packetSize int
	setup      func()
}

func tcpVperf(port string, ip string, clientVpp *VppInstance, serverVpp *VppInstance) string {
	serverVpp.Vppctl("vperf server fifo-size 64k uri tcp://%s/%s", ip, port)

	// Run a TCP vperf test (echo-bytes/full-duplex) from the client-vpp container
	output := clientVpp.Vppctl("vperf client fifo-size 64k uri tcp://%s/%s verbose echo-bytes run-time 10",
		ip, port)
	Log(output)
	AssertNotEqual(len(output), 0)
	AssertNotContains(output, "failed", output)

	return output
}

func TcpWithLossMWTest(s *VperfSuite) {
	s.CpusPerVppContainer = 2
	s.CpusPerContainer = 1
	s.SetupTest()
	tcpWithLossAndNoLoss(s, s.Containers.ClientVpp.VppInstance, s.Containers.ServerVpp.VppInstance,
		s.Interfaces.Client, s.Interfaces.Server, s.Ports.Port1)
}

func TcpChainedBufferWithLossMWTest(s *VperfSuite) {
	s.CpusPerVppContainer = 2
	s.CpusPerContainer = 1
	s.SetupTest()
	tcpWithLossAndNoLoss(s, s.Containers.ClientVpp.VppInstance, s.Containers.ServerVpp.VppInstance,
		s.Interfaces.Client, s.Interfaces.Server, s.Ports.Port1, tcpWithLossConfig{
			packetSize: tcpChainedBufferMTU,
			setup:      func() { configureTcpChainedBufferMTU(s) },
		})
}

func TcpWithLoss6Test(s *Vperf6Suite) {
	tcpWithLossAndNoLoss(s, s.Containers.ClientVpp.VppInstance, s.Containers.ServerVpp.VppInstance,
		s.Interfaces.Client, s.Interfaces.Server, s.Ports.Port1)
}

// runs tcp vperf without loss, then with loss
func tcpWithLossAndNoLoss(s tcpWithLossInterface, clientVpp *VppInstance,
	serverVpp *VppInstance, clientIf *NetInterface, serverIf *NetInterface, port string,
	configs ...tcpWithLossConfig) {
	config := tcpWithLossConfig{packetSize: 1400}
	if len(configs) > 0 {
		config = configs[0]
		if config.packetSize == 0 {
			config.packetSize = 1400
		}
	}

	Log(clientVpp.Vppctl("set nsim poll-main-thread delay 10 ms bandwidth 40 gbit"))
	Log(clientVpp.Vppctl("nsim output-feature enable-disable " + clientIf.VppName()))

	var serverAddress string
	if serverIf.Ip6AddressString() == "" {
		serverAddress = serverIf.Ip4AddressString()
	} else {
		serverAddress = serverIf.Ip6AddressString()
	}

	Log("  * running TcpWithoutLoss")
	if config.setup != nil {
		config.setup()
	}
	output := tcpVperf(port, serverAddress, clientVpp, serverVpp)
	baseline, err := ParseVperfClientTransfer(output)
	AssertNil(err)

	clientVpp.Disconnect()
	clientVpp.Stop()
	s.SetupClientVpp()
	serverVpp.Disconnect()
	serverVpp.Stop()
	s.SetupServerVpp()

	// Add loss of packets with Network Delay Simulator
	Log(clientVpp.Vppctl("set nsim poll-main-thread delay 10 ms bandwidth 40 gbit"+
		" packet-size %d drop-fraction 0.033", config.packetSize))

	Log(clientVpp.Vppctl("nsim output-feature enable-disable " + clientIf.VppName()))

	Log("  * running TcpWithLoss")
	if config.setup != nil {
		config.setup()
	}
	output = tcpVperf(port, serverAddress, clientVpp, serverVpp)

	withLoss, err := ParseVperfClientTransfer(output)
	AssertNil(err)

	Log("\nBaseline:  %d bytes/s\nWith loss: %d bytes/s", baseline, withLoss)
	AssertGreaterEqualUnlessCoverageBuild(baseline, withLoss, "Tcp vperf: baseline bitrate is lower than bitrate with loss applied")
	AssertGreaterEqualUnlessCoverageBuild(withLoss, uint64(float64(baseline)*0.15), "Tcp vperf: bitrate below threshold")
}

func TlsSingleConnectionTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server " +
		" uri tls://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client uri tls://%s:%s verbose run-time 5", s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)

	Log(o)
	throughput, err := ParseVperfClientTransfer(o)
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
		AssertEmpty("invalid vperf client output")
	}
}

func VperfBuiltinHttpTestBytesTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client test-bytes run-time 5 http2 uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpVerifyPeriodicStats(o)
}

func VperfBuiltinHttpTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server uri http://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client run-time 5 uri http://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpVerifyPeriodicStats(o)
}

func VperfBuiltinHttpsTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client run-time 5 uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpVerifyPeriodicStats(o)
}

func VperfBuiltinHttp2Test(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client run-time 5 http2 uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpVerifyPeriodicStats(o)
}

func VperfBuiltinHttp3Test(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client run-time 5 http3 uri https://" +
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
		AssertEmpty("invalid vperf client output")
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
		AssertEmpty("invalid vperf client output")
	}
}

func vperfBuiltinHttp2ConnectUdp(s *VperfSuite, clientExtraArgs, serverExtraArgs string) string {
	serverVpp := s.Containers.ServerVpp.VppInstance
	serverCmd := "vperf server connect-udp uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	if serverExtraArgs != "" {
		serverCmd += " " + serverExtraArgs
	}
	serverVpp.Vppctl(serverCmd)

	clientVpp := s.Containers.ClientVpp.VppInstance
	clientCmd := "vperf client run-time 5 echo-bytes http2 connect-udp uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1
	if clientExtraArgs != "" {
		clientCmd += " " + clientExtraArgs
	}

	o := clientVpp.Vppctl(clientCmd)
	Log(o)
	AssertNotContains(o, "failed:")
	return o
}

func VperfBuiltinHttp2ConnectUdpBackpressureTest(s *VperfSuite) {
	// Small fifos keep the tunnel close to backpressure and exercise the
	// postponed RX/TX paths fixed for HTTP/2 CONNECT-UDP.
	o := vperfBuiltinHttp2ConnectUdp(s, "nclients 2 fifo-size 16k", "fifo-size 16k")
	httpTunnelVerifyActivePeriodicStats(o)
}

func VperfBuiltinHttp2ConnectUdpBackpressureMWTest(s *VperfSuite) {
	s.Skip("Might fail to set veth interface fanout options")
	s.CpusPerVppContainer = 3
	s.SetupTest()
	VperfBuiltinHttp2ConnectUdpBackpressureTest(s)
}

func VperfBuiltinHttp2ConnectTcpTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server connect-tcp uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client run-time 5 echo-bytes http2 connect-tcp uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpTunnelVerifyPeriodicStats(o)
}

func VperfBuiltinHttp3ConnectTcpTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server connect-tcp uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client run-time 5 echo-bytes http3 connect-tcp uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpTunnelVerifyPeriodicStats(o)
}

func VperfBuiltinHttp2ConnectUdpTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server connect-udp uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client run-time 5 echo-bytes http2 connect-udp uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpTunnelVerifyPeriodicStats(o)
}

func VperfBuiltinHttp3ConnectUdpTest(s *VperfSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("vperf server connect-udp uri https://" + s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)

	clientVpp := s.Containers.ClientVpp.VppInstance

	o := clientVpp.Vppctl("vperf client run-time 5 echo-bytes http3 connect-udp uri https://" +
		s.Interfaces.Server.Ip4AddressString() + ":" + s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed:")
	httpTunnelVerifyPeriodicStats(o)
}

func VperfBuiltinHttp1CpsMWTest(s *VperfSuite) {
	s.Skip("Might fail to set veth interface fanout options")
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()
	s.CpusPerVppContainer = 3
	s.SetupTest(memoryConfig)
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("vperf server " +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))

	o := clientVpp.Vppctl("vperf client nclients 4000 bytes 64 syn-timeout 40" +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	Log(serverVpp.Vppctl("show http stats"))
	Log(clientVpp.Vppctl("show http stats"))
}

func VperfBuiltinHttp2CpsMWTest(s *VperfSuite) {
	s.Skip("Might fail to set veth interface fanout options")
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()
	s.CpusPerVppContainer = 3
	s.SetupTest(memoryConfig)
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("vperf server " +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))

	o := clientVpp.Vppctl("vperf client http2 nclients 4000 bytes 64 syn-timeout 40" +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	Log(serverVpp.Vppctl("show http stats"))
	Log(clientVpp.Vppctl("show http stats"))
}

func VperfBuiltinHttp3CpsMWTest(s *VperfSuite) {
	s.Skip("Might fail to set veth interface fanout options")
	var quicConfig Stanza
	quicConfig.NewStanza("quic").Append("conn-timeout 60000").Append("fifo-size 32k").Close()
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()
	s.CpusPerVppContainer = 3
	s.SetupTest(quicConfig, memoryConfig)
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	Log(serverVpp.Vppctl("vperf server " +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1))

	o := clientVpp.Vppctl("vperf client http3 nclients 1000 bytes 64 syn-timeout 40" +
		" uri https://" + s.Interfaces.Server.Ip4AddressString() + "/" + s.Ports.Port1)
	Log(o)
	Log(serverVpp.Vppctl("show http stats"))
	Log(clientVpp.Vppctl("show http stats"))
}
