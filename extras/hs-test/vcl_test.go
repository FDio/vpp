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
	srvVppCont := s.getContainerByName("server-vpp")
	srvAppCont := s.getContainerByName("server-app")

	serverVclConfContent := fmt.Sprintf(vclTemplate, srvVppCont.getContainerWorkDir(), "1")
	srvAppCont.createFile("/vcl.conf", serverVclConfContent)
	srvAppCont.addEnvVar("VCL_CONFIG", "/vcl.conf")
	srvAppCont.execServer("vcl_test_server " + port)

	serverVeth := s.netInterfaces[serverInterfaceName]
	serverVethAddress := serverVeth.ip4AddressString()

	echoClnContainer := s.getTransientContainerByName("client-app")
	clientVclConfContent := fmt.Sprintf(vclTemplate, echoClnContainer.getContainerWorkDir(), "2")
	echoClnContainer.createFile("/vcl.conf", clientVclConfContent)

	testClientCommand := "vcl_test_client -p " + proto + " " + serverVethAddress + " " + port
	echoClnContainer.addEnvVar("VCL_CONFIG", "/vcl.conf")
	o := echoClnContainer.exec(testClientCommand)
	s.log(o)
}

func (s *VethsSuite) TestVclEchoTcp() {
	s.testVclEcho("tcp")
}

func (s *VethsSuite) TestVclEchoUdp() {
	s.testVclEcho("udp")
}

func (s *VethsSuite) TestVclRetryAttach() {
	s.skip("this test takes too long, for now it's being skipped")
	s.testRetryAttach("tcp")
}

func (s *VethsSuite) testRetryAttach(proto string) {
	srvVppContainer := s.getTransientContainerByName("server-vpp")

	echoSrvContainer := s.getContainerByName("server-app")

	serverVclConfContent := fmt.Sprintf(vclTemplate, echoSrvContainer.getContainerWorkDir(), "1")
	echoSrvContainer.createFile("/vcl.conf", serverVclConfContent)

	echoSrvContainer.addEnvVar("VCL_CONFIG", "/vcl.conf")
	echoSrvContainer.execServer("vcl_test_server -p " + proto + " 12346")

	s.log("This whole test case can take around 3 minutes to run. Please be patient.")
	s.log("... Running first echo client test, before disconnect.")

	serverVeth := s.netInterfaces[serverInterfaceName]
	serverVethAddress := serverVeth.ip4AddressString()

	echoClnContainer := s.getTransientContainerByName("client-app")
	clientVclConfContent := fmt.Sprintf(vclTemplate, echoClnContainer.getContainerWorkDir(), "2")
	echoClnContainer.createFile("/vcl.conf", clientVclConfContent)

	testClientCommand := "vcl_test_client -U -p " + proto + " " + serverVethAddress + " 12346"
	echoClnContainer.addEnvVar("VCL_CONFIG", "/vcl.conf")
	o := echoClnContainer.exec(testClientCommand)
	s.log(o)
	s.log("... First test ended. Stopping VPP server now.")

	// Stop server-vpp-instance, start it again and then run vcl-test-client once more
	srvVppContainer.vppInstance.disconnect()
	stopVppCommand := "/bin/bash -c 'ps -C vpp_main -o pid= | xargs kill -9'"
	srvVppContainer.exec(stopVppCommand)

	s.setupServerVpp()

	s.log("... VPP server is starting again, so waiting for a bit.")
	time.Sleep(30 * time.Second) // Wait a moment for the re-attachment to happen

	s.log("... Running second echo client test, after disconnect and re-attachment.")
	o = echoClnContainer.exec(testClientCommand)
	s.log(o)
	s.log("Done.")
}
