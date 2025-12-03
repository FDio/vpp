package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVethTests(XEchoVclClientUdpTest, XEchoVclClientTcpTest, XEchoVclServerUdpTest, VclQuicUnidirectionalStreamTest,
		XEchoVclServerTcpTest, VclEchoTcpTest, VclEchoUdpTest, VclHttpPostTest, VclClUdpDscpTest,
		VclQuicBidirectionalStreamTest, VclQuicUnidirectionalStreamClientResetTest,
		VclQuicUnidirectionalStreamServerResetTest, VclQuicBidirectionalStreamClientResetTest,
		VclQuicBidirectionalStreamServerResetTest, VclQuicClientCloseConnectionTest, VclQuicServerCloseConnectionTest,
		VclDtlsOverMTUTest)
	RegisterSoloVethTests(VclRetryAttachTest)
	RegisterVethMWTests(VclQuicUnidirectionalStreamsMWTest)
}

func vclGetLabelValue(output, label string) (int, error) {
	lines := strings.SplitSeq(output, "\n")
	for line := range lines {
		if strings.Contains(line, label) {
			return strconv.Atoi(strings.Fields(strings.SplitAfter(line, ":")[1])[0])
		}
	}
	return 0, fmt.Errorf("label '%s' not found", label)
}

func getVclConfig(c *Container, ns_id_optional ...string) string {
	var s Stanza
	ns_id := "default"
	if len(ns_id_optional) > 0 {
		ns_id = ns_id_optional[0]
	}
	s.NewStanza("vcl").
		Append(fmt.Sprintf("app-socket-api %[1]s/var/run/app_ns_sockets/%[2]s", c.GetContainerWorkDir(), ns_id)).
		Append("app-scope-global").
		Append("app-scope-local").
		Append("use-mq-eventfd")
	if len(ns_id_optional) > 0 {
		s.Append(fmt.Sprintf("namespace-id %[1]s", ns_id)).
			Append(fmt.Sprintf("namespace-secret %[1]s", ns_id))
	}
	return s.Close().ToString()
}

func XEchoVclClientUdpTest(s *VethsSuite) {
	testXEchoVclClient(s, "udp")
}

func XEchoVclClientTcpTest(s *VethsSuite) {
	testXEchoVclClient(s, "tcp")
}

func testXEchoVclClient(s *VethsSuite, proto string) {
	s.SetupAppContainers()

	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server uri %s://%s/%s fifo-size 64k", proto, s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)

	echoClnContainer := s.GetTransientContainerByName("client-app")
	echoClnContainer.CreateFile("/vcl.conf", getVclConfig(echoClnContainer))

	testClientCommand := fmt.Sprintf("vcl_test_client -N 100 -p %s %s %s 2>&1 | tee %s",
		proto, s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1, VclTestClnLogFileName(echoClnContainer))
	Log(testClientCommand)
	echoClnContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	o, err := echoClnContainer.Exec(true, WrapCmdWithLineBuffering(testClientCommand))
	AssertNil(err)
	AssertNotContains(o, "aborting test")
	Log(o)
	AssertContains(o, "CLIENT RESULTS")
}

func XEchoVclServerUdpTest(s *VethsSuite) {
	testXEchoVclServer(s, "udp")
}

func XEchoVclServerTcpTest(s *VethsSuite) {
	testXEchoVclServer(s, "tcp")
}

func testXEchoVclServer(s *VethsSuite, proto string) {
	s.SetupAppContainers()

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer cancel()
	srvVppCont := s.Containers.ServerVpp
	srvAppCont := s.Containers.ServerApp
	serverVethAddress := s.Interfaces.Server.Ip4AddressString()

	srvAppCont.CreateFile("/vcl.conf", getVclConfig(srvVppCont))
	srvAppCont.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	vclSrvCmd := fmt.Sprintf("vcl_test_server -p %s -B %s %s", proto, serverVethAddress, s.Ports.Port1)
	wg.Go(func() {
		defer GinkgoRecover()
		o, oErr, err := srvAppCont.ExecLineBuffered(ctx, true, vclSrvCmd)
		Log(o)
		Log(oErr)
		AssertNil(err, o+oErr)
	})

	srvVppCont.VppInstance.WaitForApp("vcl_test_server", 3)
	clientVpp := s.Containers.ClientVpp.VppInstance
	o := clientVpp.Vppctl("test echo client uri %s://%s/%s fifo-size 64k verbose bytes 2m", proto, serverVethAddress, s.Ports.Port1)
	cancel()
	wg.Wait()
	Log(o)
	AssertContains(o, "Test finished at")
}

func testVclEcho(s *VethsSuite, proto string, extraArgs ...string) (string, string) {
	s.SetupAppContainers()

	extras := ""
	if len(extraArgs) > 0 {
		extras = strings.Join(extraArgs, " ")
		extras += " "
	}
	srvVppCont := s.Containers.ServerVpp
	srvAppCont := s.Containers.ServerApp
	serverVethAddress := s.Interfaces.Server.Ip4AddressString()

	srvAppCont.CreateFile("/vcl.conf", getVclConfig(srvVppCont))
	srvAppCont.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	vclSrvCmd := fmt.Sprintf("vcl_test_server -p %s -B %s %s > %s 2>&1",
		proto, serverVethAddress, s.Ports.Port1, VclTestSrvLogFileName(srvAppCont))

	srvAppCont.ExecServer(true, WrapCmdWithLineBuffering(vclSrvCmd))
	srvVppCont.VppInstance.WaitForApp("vcl_test_server", 3)

	if proto == "quic" {
		o := s.Containers.ServerVpp.VppInstance.Vppctl("show quic crypto context")
		Log(o)
		AssertNotEmpty(o)
		AssertContains(o, "n_sub: 1")
	}
	echoClnContainer := s.GetTransientContainerByName("client-app")
	echoClnContainer.CreateFile("/vcl.conf", getVclConfig(echoClnContainer))

	testClientCommand := fmt.Sprintf("vcl_test_client -X -S %s-p %s %s %s 2>&1 | tee %s",
		extras, proto, serverVethAddress, s.Ports.Port1, VclTestClnLogFileName(echoClnContainer))
	echoClnContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")

	o, err := echoClnContainer.Exec(true, WrapCmdWithLineBuffering(testClientCommand))
	Log("****** Client output:\n%s\n******", o)

	oSrv, errSrv := srvAppCont.Exec(false, "cat %s", VclTestSrvLogFileName(srvAppCont))
	Log("****** Server output:\n%s\n******", oSrv)

	AssertNil(err, o)
	AssertNotContains(o, "aborting test")
	AssertNil(errSrv, oSrv)
	return o, oSrv
}

func VclEchoTcpTest(s *VethsSuite) {
	testVclEcho(s, "tcp")
}

func VclEchoUdpTest(s *VethsSuite) {
	testVclEcho(s, "udp")
}

func VclQuicUnidirectionalStreamTest(s *VethsSuite) {
	_, oSrv := testVclEcho(s, "quic", "-N 1000")
	AssertNotContains(oSrv, "ERROR: expected unidirectional stream")
	minBytes, err := vclGetLabelValue(oSrv, "client tx bytes")
	AssertNil(err)
	serverRxBytes, err := vclGetLabelValue(oSrv, "rx bytes")
	AssertNil(err)
	AssertGreaterEqual(serverRxBytes, minBytes, "server receive less data")
}

func VclQuicUnidirectionalStreamsMWTest(s *VethsSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	_, oSrv := testVclEcho(s, "quic", "-s 80 -q 10 -N 1000")
	AssertNotContains(oSrv, "ERROR: expected unidirectional stream")
	o := s.Containers.ClientVpp.VppInstance.Vppctl("show quic crypto context")
	AssertEmpty(o)
	o = s.Containers.ServerVpp.VppInstance.Vppctl("show quic crypto context")
	AssertEmpty(o)
}

func VclQuicBidirectionalStreamTest(s *VethsSuite) {
	_, oSrv := testVclEcho(s, "quic", "-B -N 1000")
	minBytes, err := vclGetLabelValue(oSrv, "client tx bytes")
	AssertNil(err)
	serverRxBytes, err := vclGetLabelValue(oSrv, "rx bytes")
	AssertNil(err)
	serverTxBytes, err := vclGetLabelValue(oSrv, "tx bytes")
	AssertNil(err)
	AssertGreaterEqual(serverRxBytes, minBytes, "server receive less data")
	AssertGreaterEqual(serverTxBytes, minBytes, "server send less data")
}

func VclQuicUnidirectionalStreamClientResetTest(s *VethsSuite) {
	oCln, oSrv := testVclEcho(s, "quic", "-N 1000 -t client-rst-stream")
	AssertNotContains(oSrv, "ctrl session went away")
	AssertNotContains(oSrv, "invalid application error code")
	serverRstCount, err := vclGetLabelValue(oSrv, "reset count")
	AssertNil(err)
	AssertEqual(serverRstCount, 1, "server stream should receive reset")
	clientRstCount, err := vclGetLabelValue(oCln, "reset count")
	AssertNil(err)
	AssertEqual(clientRstCount, 0, "client stream should not receive reset")
}

func VclQuicUnidirectionalStreamServerResetTest(s *VethsSuite) {
	oCln, oSrv := testVclEcho(s, "quic", "-N 1000 -t server-rst-stream")
	AssertNotContains(oSrv, "ctrl session went away")
	AssertNotContains(oCln, "invalid application error code")
	serverRstCount, err := vclGetLabelValue(oSrv, "reset count")
	AssertNil(err)
	AssertEqual(serverRstCount, 0, "server stream should not receive reset")
	clientRstCount, err := vclGetLabelValue(oCln, "reset count")
	AssertNil(err)
	AssertEqual(clientRstCount, 1, "client stream should receive reset")
}

func VclQuicBidirectionalStreamClientResetTest(s *VethsSuite) {
	oCln, oSrv := testVclEcho(s, "quic", "-B -N 1000 -t client-rst-stream")
	AssertNotContains(oSrv, "ctrl session went away")
	AssertNotContains(oSrv, "invalid application error code")
	serverRstCount, err := vclGetLabelValue(oSrv, "reset count")
	AssertNil(err)
	AssertEqual(serverRstCount, 1, "server stream should receive reset")
	clientRstCount, err := vclGetLabelValue(oCln, "reset count")
	AssertNil(err)
	AssertEqual(clientRstCount, 0, "client stream should not receive reset")
}

func VclQuicBidirectionalStreamServerResetTest(s *VethsSuite) {
	oCln, oSrv := testVclEcho(s, "quic", "-B -N 1000 -t server-rst-stream")
	AssertNotContains(oSrv, "ctrl session went away")
	AssertNotContains(oCln, "invalid application error code")
	serverRstCount, err := vclGetLabelValue(oSrv, "reset count")
	AssertNil(err)
	AssertEqual(serverRstCount, 0, "server stream should not receive reset")
	clientRstCount, err := vclGetLabelValue(oCln, "reset count")
	AssertNil(err)
	AssertEqual(clientRstCount, 1, "client stream should receive reset")
}

func VclQuicClientCloseConnectionTest(s *VethsSuite) {
	oCln, oSrv := testVclEcho(s, "quic", "-B -N 1000 -t client-close-conn")
	AssertNotContains(oSrv, "ctrl session went away")
	AssertNotContains(oSrv, "invalid application error code")
	serverCloseCount, err := vclGetLabelValue(oSrv, "close count")
	AssertNil(err)
	AssertEqual(serverCloseCount, 1, "server connection should be closed by client")
	clientCloseCount, err := vclGetLabelValue(oCln, "close count")
	AssertNil(err)
	AssertEqual(clientCloseCount, 0, "client connection shloud not be closed by server")
}

func VclQuicServerCloseConnectionTest(s *VethsSuite) {
	oCln, oSrv := testVclEcho(s, "quic", "-B -N 1000 -t server-close-conn")
	AssertNotContains(oSrv, "ctrl session went away")
	AssertNotContains(oCln, "invalid application error code")
	serverCloseCount, err := vclGetLabelValue(oSrv, "close count")
	AssertNil(err)
	AssertEqual(serverCloseCount, 0, "server connection should not be closed by client")
	clientCloseCount, err := vclGetLabelValue(oCln, "close count")
	AssertNil(err)
	AssertEqual(clientCloseCount, 1, "client connection shloud be closed by server")
}

func VclHttpPostTest(s *VethsSuite) {
	testVclEcho(s, "http")
}

func VclDtlsOverMTUTest(s *VethsSuite) {
	srvVppCont := s.Containers.ServerVpp
	srvAppCont := s.Containers.ServerApp
	serverVethAddress := s.Interfaces.Server.Ip4AddressString()

	srvAppCont.CreateFile("/vcl.conf", getVclConfig(srvVppCont))
	srvAppCont.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	vclSrvCmd := fmt.Sprintf("vcl_test_server -p dtls -B %s %s", serverVethAddress, s.Ports.Port1)
	srvAppCont.ExecServer(true, vclSrvCmd)

	echoClnContainer := s.GetTransientContainerByName("client-app")
	echoClnContainer.CreateFile("/vcl.conf", getVclConfig(echoClnContainer))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	testClientCommand := "vcl_test_client -p dtls -N 1 -b 8192 " + serverVethAddress + " " + s.Ports.Port1
	echoClnContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	_, err := echoClnContainer.ExecContext(ctx, true, testClientCommand)
	AssertNil(err)
}

// solo because binding server to an IP makes the test fail in the CI
func VclRetryAttachTest(s *VethsSuite) {
	testRetryAttach(s, "tcp")
}

func testRetryAttach(s *VethsSuite, proto string) {
	s.SetupAppContainers()

	srvVppContainer := s.GetTransientContainerByName("server-vpp")
	echoSrvContainer := s.Containers.ServerApp
	serverVethAddress := s.Interfaces.Server.Ip4AddressString()

	echoSrvContainer.CreateFile("/vcl.conf", getVclConfig(echoSrvContainer))
	echoSrvContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")

	vclSrvCmd := fmt.Sprintf("vcl_test_server -p %s %s > %s 2>&1",
		proto, s.Ports.Port1, VclTestSrvLogFileName(echoSrvContainer))
	echoSrvContainer.ExecServer(true, WrapCmdWithLineBuffering(vclSrvCmd))
	srvVppContainer.VppInstance.WaitForApp("vcl_test_server", 3)

	Log("This whole test case can take around 3 minutes to run. Please be patient.")
	Log("... Running first echo client test, before disconnect.")

	echoClnContainer := s.GetTransientContainerByName("client-app")
	echoClnContainer.CreateFile("/vcl.conf", getVclConfig(echoClnContainer))

	testClientCommand := fmt.Sprintf("vcl_test_client -U -p %s %s %s 2>&1 | tee %s",
		proto, serverVethAddress, s.Ports.Port1, VclTestClnLogFileName(echoClnContainer))
	echoClnContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	o, err := echoClnContainer.Exec(true, WrapCmdWithLineBuffering(testClientCommand))
	AssertNil(err)
	AssertNotContains(o, "aborting test")
	Log(o)
	Log("... First test ended. Stopping VPP server now.")

	// Stop server-vpp-instance, start it again and then run vcl-test-client once more
	srvVppContainer.VppInstance.Disconnect()
	srvVppContainer.VppInstance.Stop()

	s.SetupServerVpp()

	Log("... VPP server is starting again, so waiting for a bit.")
	time.Sleep(30 * time.Second) // Wait a moment for the re-attachment to happen

	Log("... Running second echo client test, after disconnect and re-attachment.")
	testClientCommand = fmt.Sprintf("vcl_test_client -U -X -p %s %s %s 2>&1 | tee %s",
		proto, serverVethAddress, s.Ports.Port1, VclTestClnLogFileName(echoClnContainer))
	o, err = echoClnContainer.Exec(true, WrapCmdWithLineBuffering(testClientCommand))
	Log("****** Client output:\n%s\n******", o)

	oSrv, errSrv := echoSrvContainer.Exec(false, "cat %s", VclTestSrvLogFileName(echoSrvContainer))
	Log("****** Server output:\n%s\n******", oSrv)

	AssertNil(err, o)
	AssertNotContains(o, "aborting test")
	AssertNil(errSrv, oSrv)
	Log("Done.")
}

func VclClUdpDscpTest(s *VethsSuite) {
	s.SetupAppContainers()

	srvVppCont := s.Containers.ServerVpp
	srvAppCont := s.Containers.ServerApp
	srvAppCont.CreateFile("/vcl.conf", getVclConfig(srvVppCont))
	srvAppCont.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	serverVethAddress := s.Interfaces.Server.Ip4AddressString()

	// DSCP 40 - Class selector 5 - Signalling
	vclSrvCmd := fmt.Sprintf("vcl_test_cl_udp -s %s -d 40", serverVethAddress)
	srvAppCont.ExecServer(true, vclSrvCmd)
	srvVppCont.VppInstance.WaitForApp("vcl_test_cl_udp", 3)

	cliVppCont := s.Containers.ClientVpp
	cliAppCont := s.Containers.ClientApp
	cliAppCont.CreateFile("/vcl.conf", getVclConfig(cliVppCont))
	cliAppCont.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	cliVppCont.VppInstance.Vppctl("arping %s %s", serverVethAddress, s.Interfaces.Client.VppName())

	cliVppCont.VppInstance.Vppctl("trace add af-packet-input 10")
	srvVppCont.VppInstance.Vppctl("trace add af-packet-input 10")

	// DSCP 16 - Class selector 2 - Network operations
	cliSrvCmd := fmt.Sprintf("vcl_test_cl_udp -c %s -d 16", serverVethAddress)
	o, err := cliAppCont.Exec(true, cliSrvCmd)
	AssertNil(err, o)

	o = srvVppCont.VppInstance.Vppctl("show trace")
	AssertContains(o, "dscp CS2")
	o = cliVppCont.VppInstance.Vppctl("show trace")
	AssertContains(o, "dscp CS5")
}
