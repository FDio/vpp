package main

import (
	"fmt"
	"time"
)

const vclTemplate = `vcl {
  app-socket-api %[1]s/var/run/app_ns_sockets/%[2]s
  app-scope-global
  app-scope-local
  namespace-id %[2]s
  namespace-secret %[2]s
  use-mq-eventfd
}
`

func (s *VethsSuite) testVclEcho(proto string) {
	port := "12345"
	srvVppCont := s.GetContainerByName("server-vpp")
	srvAppCont := s.GetContainerByName("server-app")

	serverVclConfContent := fmt.Sprintf(vclTemplate, srvVppCont.GetContainerWorkDir(), "1")
	srvAppCont.CreateFile("/vcl.conf", serverVclConfContent)
	srvAppCont.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	srvAppCont.ExecServer("vcl_test_server " + port)

	serverVeth := s.netInterfaces[serverInterfaceName]
	serverVethAddress := serverVeth.Ip4AddressString()

	echoClnContainer := s.GetTransientContainerByName("client-app")
	clientVclConfContent := fmt.Sprintf(vclTemplate, echoClnContainer.GetContainerWorkDir(), "2")
	echoClnContainer.CreateFile("/vcl.conf", clientVclConfContent)

	testClientCommand := "vcl_test_client -p " + proto + " " + serverVethAddress + " " + port
	echoClnContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	o := echoClnContainer.Exec(testClientCommand)
	s.Log(o)
}

func (s *VethsSuite) TestVclEchoTcp() {
	s.testVclEcho("tcp")
}

func (s *VethsSuite) TestVclEchoUdp() {
	s.testVclEcho("udp")
}

func (s *VethsSuite) TestVclRetryAttach() {
	s.Skip("this test takes too long, for now it's being skipped")
	s.testRetryAttach("tcp")
}

func (s *VethsSuite) testRetryAttach(proto string) {
	srvVppContainer := s.GetTransientContainerByName("server-vpp")

	echoSrvContainer := s.GetContainerByName("server-app")

	serverVclConfContent := fmt.Sprintf(vclTemplate, echoSrvContainer.GetContainerWorkDir(), "1")
	echoSrvContainer.CreateFile("/vcl.conf", serverVclConfContent)

	echoSrvContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	echoSrvContainer.ExecServer("vcl_test_server -p " + proto + " 12346")

	s.Log("This whole test case can take around 3 minutes to run. Please be patient.")
	s.Log("... Running first echo client test, before disconnect.")

	serverVeth := s.netInterfaces[serverInterfaceName]
	serverVethAddress := serverVeth.Ip4AddressString()

	echoClnContainer := s.GetTransientContainerByName("client-app")
	clientVclConfContent := fmt.Sprintf(vclTemplate, echoClnContainer.GetContainerWorkDir(), "2")
	echoClnContainer.CreateFile("/vcl.conf", clientVclConfContent)

	testClientCommand := "vcl_test_client -U -p " + proto + " " + serverVethAddress + " 12346"
	echoClnContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")
	o := echoClnContainer.Exec(testClientCommand)
	s.Log(o)
	s.Log("... First test ended. Stopping VPP server now.")

	// Stop server-vpp-instance, start it again and then run vcl-test-client once more
	srvVppContainer.vppInstance.Disconnect()
	stopVppCommand := "/bin/bash -c 'ps -C vpp_main -o pid= | xargs kill -9'"
	srvVppContainer.Exec(stopVppCommand)

	s.SetupServerVpp()

	s.Log("... VPP server is starting again, so waiting for a bit.")
	time.Sleep(30 * time.Second) // Wait a moment for the re-attachment to happen

	s.Log("... Running second echo client test, after disconnect and re-attachment.")
	o = echoClnContainer.Exec(testClientCommand)
	s.Log(o)
	s.Log("Done.")
}

func (s *VethsSuite) TestTcpWithLoss() {
	serverVpp := s.GetContainerByName("server-vpp").vppInstance

	serverVeth := s.netInterfaces[serverInterfaceName]
	serverVpp.Vppctl("test echo server uri tcp://%s/20022",
		serverVeth.Ip4AddressString())

	clientVpp := s.GetContainerByName("client-vpp").vppInstance

	// Ensure that VPP doesn't abort itself with NSIM enabled
	// Warning: Removing this ping will make the test fail!
	clientVpp.Vppctl("ping %s", serverVeth.Ip4AddressString())

	// Add loss of packets with Network Delay Simulator
	clientVpp.Vppctl("set nsim poll-main-thread delay 0.01 ms bandwidth 40 gbit" +
		" packet-size 1400 packets-per-drop 1000")

	clientVpp.Vppctl("nsim output-feature enable-disable host-vppcln")

	// Do echo test from client-vpp container
	output := clientVpp.Vppctl("test echo client uri tcp://%s/20022 mbytes 50",
		serverVeth.Ip4AddressString())
	s.AssertEqual(true, len(output) != 0)
	s.AssertNotContains(output, "failed: timeout")
	s.Log(output)
}
