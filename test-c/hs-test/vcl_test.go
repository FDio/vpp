package main

import (
	"fmt"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(XEchoVclClientUdpTest, XEchoVclClientTcpTest, XEchoVclServerUdpTest, VclEchoQuicTest,
		XEchoVclServerTcpTest, VclEchoTcpTest, VclEchoUdpTest, VclHttpPostTest, VclClUdpDscpTest)
	RegisterSoloVethTests(VclRetryAttachTest)
	RegisterVethMWTests(VclEchoQuicMWTest)
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
	serverVpp := s.Containers.ServerVpp.VppInstance

	serverVpp.Vppctl("test echo server uri %s://%s/%s fifo-size 64k", proto, s.Interfaces.Server.Ip4AddressString(), s.Ports.Port1)

	echoClnContainer := s.GetTransientContainerByName("client-app")
	echoClnContainer.CreateFile("/vcl.conf", getVclConfig(echoClnContainer))

	testClientCommand := "vcl_test_client -N 100 -p " + proto + " " + s.Interfaces.Server.Ip4AddressString() + " " + s.Ports.Port1
	s.Log(testClientCommand)
	echoClnContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	o, err := echoClnContainer.Exec(true, testClientCommand)
	s.AssertNil(err)
	s.Log(o)
	s.AssertContains(o, "CLIENT RESULTS")
}

func XEchoVclServerUdpTest(s *VethsSuite) {
	testXEchoVclServer(s, "udp")
}

func XEchoVclServerTcpTest(s *VethsSuite) {
	testXEchoVclServer(s, "tcp")
}

func testXEchoVclServer(s *VethsSuite, proto string) {
	srvVppCont := s.Containers.ServerVpp
	srvAppCont := s.Containers.ServerApp
	serverVethAddress := s.Interfaces.Server.Ip4AddressString()

	srvAppCont.CreateFile("/vcl.conf", getVclConfig(srvVppCont))
	srvAppCont.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	vclSrvCmd := fmt.Sprintf("vcl_test_server -p %s -B %s %s", proto, serverVethAddress, s.Ports.Port1)
	srvAppCont.ExecServer(true, vclSrvCmd)

	clientVpp := s.Containers.ClientVpp.VppInstance
	o := clientVpp.Vppctl("test echo client uri %s://%s/%s fifo-size 64k verbose bytes 2m", proto, serverVethAddress, s.Ports.Port1)
	s.Log(o)
	s.AssertContains(o, "Test finished at")
}

func testVclEcho(s *VethsSuite, proto string, extraArgs ...string) {
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
	vclSrvCmd := fmt.Sprintf("vcl_test_server -p %s -B %s %s", proto, serverVethAddress, s.Ports.Port1)
	srvAppCont.ExecServer(true, vclSrvCmd)

	echoClnContainer := s.GetTransientContainerByName("client-app")
	echoClnContainer.CreateFile("/vcl.conf", getVclConfig(echoClnContainer))

	testClientCommand := "vcl_test_client " + extras + "-p " + proto + " " + serverVethAddress + " " + s.Ports.Port1
	echoClnContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	o, err := echoClnContainer.Exec(true, testClientCommand)
	s.AssertNil(err)
	s.Log(o)
}

func VclEchoTcpTest(s *VethsSuite) {
	testVclEcho(s, "tcp")
}

func VclEchoUdpTest(s *VethsSuite) {
	testVclEcho(s, "udp")
}

func VclEchoQuicTest(s *VethsSuite) {
	testVclEcho(s, "quic", "-N 1000")
}

func VclEchoQuicMWTest(s *VethsSuite) {
	s.CpusPerVppContainer = 3
	s.SetupTest()
	testVclEcho(s, "quic", "-s 20 -q 10 -N 1000")
}

func VclHttpPostTest(s *VethsSuite) {
	testVclEcho(s, "http")
}

// solo because binding server to an IP makes the test fail in the CI
func VclRetryAttachTest(s *VethsSuite) {
	testRetryAttach(s, "tcp")
}

func testRetryAttach(s *VethsSuite, proto string) {
	srvVppContainer := s.GetTransientContainerByName("server-vpp")
	echoSrvContainer := s.Containers.ServerApp
	serverVethAddress := s.Interfaces.Server.Ip4AddressString()

	echoSrvContainer.CreateFile("/vcl.conf", getVclConfig(echoSrvContainer))
	echoSrvContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")

	vclSrvCmd := fmt.Sprintf("vcl_test_server -p %s %s", proto, s.Ports.Port1)
	echoSrvContainer.ExecServer(true, vclSrvCmd)

	s.Log("This whole test case can take around 3 minutes to run. Please be patient.")
	s.Log("... Running first echo client test, before disconnect.")

	echoClnContainer := s.GetTransientContainerByName("client-app")
	echoClnContainer.CreateFile("/vcl.conf", getVclConfig(echoClnContainer))

	testClientCommand := "vcl_test_client -U -p " + proto + " " + serverVethAddress + " " + s.Ports.Port1
	echoClnContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	o, err := echoClnContainer.Exec(true, testClientCommand)
	s.AssertNil(err)
	s.Log(o)
	s.Log("... First test ended. Stopping VPP server now.")

	// Stop server-vpp-instance, start it again and then run vcl-test-client once more
	srvVppContainer.VppInstance.Disconnect()
	srvVppContainer.VppInstance.Stop()

	s.SetupServerVpp()

	s.Log("... VPP server is starting again, so waiting for a bit.")
	time.Sleep(30 * time.Second) // Wait a moment for the re-attachment to happen

	s.Log("... Running second echo client test, after disconnect and re-attachment.")
	o, err = echoClnContainer.Exec(true, testClientCommand)
	s.Log(o)
	s.AssertNil(err, o)
	s.Log("Done.")
}

func VclClUdpDscpTest(s *VethsSuite) {
	srvVppCont := s.Containers.ServerVpp
	srvAppCont := s.Containers.ServerApp
	srvAppCont.CreateFile("/vcl.conf", getVclConfig(srvVppCont))
	srvAppCont.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	serverVethAddress := s.Interfaces.Server.Ip4AddressString()

	// DSCP 40 - Class selector 5 - Signalling
	vclSrvCmd := fmt.Sprintf("vcl_test_cl_udp -s %s -d 40", serverVethAddress)
	srvAppCont.ExecServer(true, vclSrvCmd)

	cliVppCont := s.Containers.ClientVpp
	cliAppCont := s.Containers.ClientApp
	cliAppCont.CreateFile("/vcl.conf", getVclConfig(cliVppCont))
	cliAppCont.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	cliVppCont.VppInstance.Vppctl("arping %s host-%s", serverVethAddress, s.Interfaces.Client.Name())

	cliVppCont.VppInstance.Vppctl("trace add af-packet-input 10")
	srvVppCont.VppInstance.Vppctl("trace add af-packet-input 10")

	// DSCP 16 - Class selector 2 - Network operations
	cliSrvCmd := fmt.Sprintf("vcl_test_cl_udp -c %s -d 16", serverVethAddress)
	o, err := cliAppCont.Exec(true, cliSrvCmd)
	s.AssertNil(err, o)

	o = srvVppCont.VppInstance.Vppctl("show trace")
	s.AssertContains(o, "dscp CS2")
	o = cliVppCont.VppInstance.Vppctl("show trace")
	s.AssertContains(o, "dscp CS5")
}
