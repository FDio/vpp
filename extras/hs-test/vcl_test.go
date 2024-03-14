package main

import (
	"fmt"
	"time"
)

func init() {
	registerVethTests(XEchoVclClientUdpTest, XEchoVclClientTcpTest, XEchoVclServerUdpTest,
		XEchoVclServerTcpTest, VclEchoTcpTest, VclEchoUdpTest, VclRetryAttachTest)
}

func getVclConfig(c *Container, ns_id_optional ...string) string {
	var s Stanza
	ns_id := "default"
	if len(ns_id_optional) > 0 {
		ns_id = ns_id_optional[0]
	}
	s.newStanza("vcl").
		append(fmt.Sprintf("app-socket-api %[1]s/var/run/app_ns_sockets/%[2]s", c.getContainerWorkDir(), ns_id)).
		append("app-scope-global").
		append("app-scope-local").
		append("use-mq-eventfd")
	if len(ns_id_optional) > 0 {
		s.append(fmt.Sprintf("namespace-id %[1]s", ns_id)).
			append(fmt.Sprintf("namespace-secret %[1]s", ns_id))
	}
	return s.close().toString()
}

func XEchoVclClientUdpTest(s *VethsSuite) {
	s.testXEchoVclClient("udp")
}

func XEchoVclClientTcpTest(s *VethsSuite) {
	s.testXEchoVclClient("tcp")
}

func (s *VethsSuite) testXEchoVclClient(proto string) {
	port := "12345"
	serverVpp := s.getContainerByName("server-vpp").vppInstance

	serverVeth := s.getInterfaceByName(serverInterfaceName)
	serverVpp.vppctl("test echo server uri %s://%s/%s fifo-size 64k", proto, serverVeth.ip4AddressString(), port)

	echoClnContainer := s.getTransientContainerByName("client-app")
	echoClnContainer.createFile("/vcl.conf", getVclConfig(echoClnContainer))

	testClientCommand := "vcl_test_client -N 100 -p " + proto + " " + serverVeth.ip4AddressString() + " " + port
	s.log(testClientCommand)
	echoClnContainer.addEnvVar("VCL_CONFIG", "/vcl.conf")
	o := echoClnContainer.exec(testClientCommand)
	s.log(o)
	s.assertContains(o, "CLIENT RESULTS")
}

func XEchoVclServerUdpTest(s *VethsSuite) {
	s.testXEchoVclServer("udp")
}

func XEchoVclServerTcpTest(s *VethsSuite) {
	s.testXEchoVclServer("tcp")
}

func (s *VethsSuite) testXEchoVclServer(proto string) {
	port := "12345"
	srvVppCont := s.getContainerByName("server-vpp")
	srvAppCont := s.getContainerByName("server-app")

	srvAppCont.createFile("/vcl.conf", getVclConfig(srvVppCont))
	srvAppCont.addEnvVar("VCL_CONFIG", "/vcl.conf")
	vclSrvCmd := fmt.Sprintf("vcl_test_server -p %s %s", proto, port)
	srvAppCont.execServer(vclSrvCmd)

	serverVeth := s.getInterfaceByName(serverInterfaceName)
	serverVethAddress := serverVeth.ip4AddressString()

	clientVpp := s.getContainerByName("client-vpp").vppInstance
	o := clientVpp.vppctl("test echo client uri %s://%s/%s fifo-size 64k verbose mbytes 2", proto, serverVethAddress, port)
	s.log(o)
	s.assertContains(o, "Test finished at")
}

func (s *VethsSuite) testVclEcho(proto string) {
	port := "12345"
	srvVppCont := s.getContainerByName("server-vpp")
	srvAppCont := s.getContainerByName("server-app")

	srvAppCont.createFile("/vcl.conf", getVclConfig(srvVppCont))
	srvAppCont.addEnvVar("VCL_CONFIG", "/vcl.conf")
	srvAppCont.execServer("vcl_test_server " + port)

	serverVeth := s.getInterfaceByName(serverInterfaceName)
	serverVethAddress := serverVeth.ip4AddressString()

	echoClnContainer := s.getTransientContainerByName("client-app")
	echoClnContainer.createFile("/vcl.conf", getVclConfig(echoClnContainer))

	testClientCommand := "vcl_test_client -p " + proto + " " + serverVethAddress + " " + port
	echoClnContainer.addEnvVar("VCL_CONFIG", "/vcl.conf")
	o := echoClnContainer.exec(testClientCommand)
	s.log(o)
}

func VclEchoTcpTest(s *VethsSuite) {
	s.testVclEcho("tcp")
}

func VclEchoUdpTest(s *VethsSuite) {
	s.testVclEcho("udp")
}

func VclRetryAttachTest(s *VethsSuite) {
	s.testRetryAttach("tcp")
}

func (s *VethsSuite) testRetryAttach(proto string) {
	srvVppContainer := s.getTransientContainerByName("server-vpp")

	echoSrvContainer := s.getContainerByName("server-app")

	echoSrvContainer.createFile("/vcl.conf", getVclConfig(echoSrvContainer))

	echoSrvContainer.addEnvVar("VCL_CONFIG", "/vcl.conf")
	echoSrvContainer.execServer("vcl_test_server -p " + proto + " 12346")

	s.log("This whole test case can take around 3 minutes to run. Please be patient.")
	s.log("... Running first echo client test, before disconnect.")

	serverVeth := s.getInterfaceByName(serverInterfaceName)
	serverVethAddress := serverVeth.ip4AddressString()

	echoClnContainer := s.getTransientContainerByName("client-app")
	echoClnContainer.createFile("/vcl.conf", getVclConfig(echoClnContainer))

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
