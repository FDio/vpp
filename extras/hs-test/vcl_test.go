package main

import (
	"fmt"
	"time"
)

func (s *VethsSuite) TestVclEchoQuic() {
	s.skip("quic test skipping..")
	s.testVclEcho("quic")
}

func (s *VethsSuite) TestVclEchoUdp() {
	s.skip("udp echo currently broken in vpp, skipping..")
	s.testVclEcho("udp")
}

func (s *VethsSuite) TestVclEchoTcp() {
	s.testVclEcho("tcp")
}

func (s *VethsSuite) testVclEcho(proto string) {
	serverVethAddress := s.veths["vppsrv"].Address()
	uri := proto + "://" + serverVethAddress + "/12344"

	echoSrvContainer := s.getContainerByName("server-application")
	serverCommand := "vpp_echo server TX=RX" +
		" socket-name " + echoSrvContainer.GetContainerWorkDir() + "/var/run/app_ns_sockets/1" +
		" use-app-socket-api" +
		" uri " + uri
	s.log(serverCommand)
	err := echoSrvContainer.execServer(serverCommand)
	s.assertNil(err)

	echoClnContainer := s.getContainerByName("client-application")

	clientCommand := "vpp_echo client" +
		" socket-name " + echoClnContainer.GetContainerWorkDir() + "/var/run/app_ns_sockets/2" +
		" use-app-socket-api uri " + uri
	s.log(clientCommand)
	o, err := echoClnContainer.exec(clientCommand)
	s.assertNil(err)

	s.log(o)
}

func (s *VethsSuite) TestVclRetryAttach() {
	s.skip("this test takes too long, for now it's being skipped")
	s.testRetryAttach("tcp")
}

func (s *VethsSuite) testRetryAttach(proto string) {
	srvVppContainer := s.getContainerCopyByName("server-vpp")

	echoSrvContainer := s.getContainerByName("server-application")

	serverVclConfContent := fmt.Sprintf(vclTemplate, echoSrvContainer.GetContainerWorkDir(), "1")
	echoSrvContainer.createFile("/vcl.conf", serverVclConfContent)

	echoSrvContainer.addEnvVar("VCL_CONFIG", "/vcl.conf")
	err := echoSrvContainer.execServer("vcl_test_server -p " + proto + " 12346")
	s.assertNil(err)

	s.log("This whole test case can take around 3 minutes to run. Please be patient.")
	s.log("... Running first echo client test, before disconnect.")

	serverVeth := s.veths[serverInterfaceName]
	serverVethAddress := serverVeth.Address()

	echoClnContainer := s.getContainerCopyByName("client-application")
	clientVclConfContent := fmt.Sprintf(vclTemplate, echoClnContainer.GetContainerWorkDir(), "2")
	echoClnContainer.createFile("/vcl.conf", clientVclConfContent)

	testClientCommand := "vcl_test_client -U -p " + proto + " " + serverVethAddress + " 12346"
	echoClnContainer.addEnvVar("VCL_CONFIG", "/vcl.conf")
	o, err := echoClnContainer.exec(testClientCommand)
	s.log(o)
	s.assertNil(err)
	s.log("... First test ended. Stopping VPP server now.")

	// Stop server-vpp-instance, start it again and then run vcl-test-client once more
	srvVppContainer.vppInstance.disconnect()
	stopVppCommand := "/bin/bash -c 'ps -C vpp_main -o pid= | xargs kill -9'"
	_, err = srvVppContainer.exec(stopVppCommand)
	s.assertNil(err)

	s.setupServerVpp()

	s.log("... VPP server is starting again, so waiting for a bit.")
	time.Sleep(30 * time.Second) // Wait a moment for the re-attachment to happen

	s.log("... Running second echo client test, after disconnect and re-attachment.")
	o, err = echoClnContainer.exec(testClientCommand)
	s.log(o)
	s.assertNil(err)
	s.log("Done.")
}

func (s *VethsSuite) TestTcpWithLoss() {
	serverContainer := s.getContainerByName("server-vpp")

	serverVpp := NewVppInstance(serverContainer)
	s.assertNotNil(serverVpp)
	serverVpp.set2VethsServer()
	err := serverVpp.start()
	s.assertNil(err, "starting VPP failed")

	serverVeth := s.veths[serverInterfaceName]
	_, err = serverVpp.vppctl("test echo server uri tcp://%s/20022", serverVeth.Address())
	s.assertNil(err, "starting echo server failed")

	clientContainer := s.getContainerByName("client-vpp")

	clientVpp := NewVppInstance(clientContainer)
	s.assertNotNil(clientVpp)
	clientVpp.set2VethsClient()
	err = clientVpp.start()
	s.assertNil(err, "starting VPP failed")

	// Ensure that VPP doesn't abort itself with NSIM enabled
	// Warning: Removing this ping will make the test fail!
	_, err = serverVpp.vppctl("ping 10.10.10.2")
	s.assertNil(err, "ping failed")

	// Add loss of packets with Network Delay Simulator
	_, err = clientVpp.vppctl("set nsim poll-main-thread delay 0.01 ms bandwidth 40 gbit packet-size 1400 packets-per-drop 1000")
	s.assertNil(err, "configuring NSIM failed")
	_, err = clientVpp.vppctl("nsim output-feature enable-disable host-vppcln")
	s.assertNil(err, "enabling NSIM failed")

	// Do echo test from client-vpp container
	output, err := clientVpp.vppctl("test echo client uri tcp://10.10.10.1/20022 mbytes 50")
	s.assertNil(err)
	s.assertEqual(true, len(output) != 0)
	s.assertNotContains(output, "failed: timeout")
	s.log(output)
}
