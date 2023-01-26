package main

import (
	"fmt" // TODO remove this
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
	srvVppContainer := s.getContainerByName("server-vpp")

	_, err := srvVppContainer.execAction("Configure2Veths srv")
	s.assertNil(err)

	clnVppContainer := s.getContainerByName("client-vpp")

	_, err = clnVppContainer.execAction("Configure2Veths cln")
	s.assertNil(err)

	echoSrvContainer := s.getContainerByName("server-application")

	// run server app
	_, err = echoSrvContainer.execAction("RunEchoServer " + proto)
	s.assertNil(err)

	echoClnContainer := s.getContainerByName("client-application")

	o, err := echoClnContainer.execAction("RunEchoClient " + proto)
	s.assertNil(err)

	s.log(o)
}

func (s *VethsSuite) TestVclRetryAttach() {
	s.skip()
	s.testRetryAttach("tcp")
}

func (s *VethsSuite) testRetryAttach(proto string) {
	srvVppContainer := s.getContainerByName("server-vpp")

	// vppInstance := srvVppContainer.newVppInstance() // allow to modify startup.config (what's done with stanza in action)
	// vppInstance.start() // this will only start VPP with stanza added
	// vppInstance.configure(networkConfig.getInterface("servervpp")) // assuming IP is generated and fetchable
	_, err := srvVppContainer.execAction("Configure2Veths srv-with-preset-hw-addr")
	s.assertNil(err)

	clnVppContainer := s.getContainerByName("client-vpp")

	_, err = clnVppContainer.execAction("Configure2Veths cln")
	s.assertNil(err)

	echoSrvContainer := s.getContainerByName("server-application")
	_, err = echoSrvContainer.execAction("RunVclEchoServer " + proto)
	s.assertNil(err)

	s.log("This whole test case can take around 3 minutes to run. Please be patient.")
	s.log("... Running first echo client test, before disconnect.")
	echoClnContainer := s.getContainerByName("client-application")
	_, err = echoClnContainer.execAction("RunVclEchoClient " + proto)
	s.assertNil(err)
	s.log("... First test ended. Stopping VPP server now.")

	// Stop server-vpp-instance, start it again and then run vcl-test-client once more
	stopVppCommand := "/bin/bash -c 'ps -C vpp_main -o pid= | xargs kill -9'"
	_, err = srvVppContainer.exec(stopVppCommand)
	s.assertNil(err)
	time.Sleep(5 * time.Second) // Give parent process time to reap the killed child process
	stopVppCommand = "/bin/bash -c 'ps -C hs-test -o pid= | xargs kill -9'"
	_, err = srvVppContainer.exec(stopVppCommand)
	s.assertNil(err)
	_, err = srvVppContainer.execAction("Configure2Veths srv-with-preset-hw-addr")
	s.assertNil(err)

	s.log("... VPP server is starting again, so waiting for a bit.")
	time.Sleep(30 * time.Second) // Wait a moment for the re-attachment to happen

	s.log("... Running second echo client test, after disconnect and re-attachment.")
	_, err = echoClnContainer.execAction("RunVclEchoClient " + proto)
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

	_, err = serverVpp.vppctl("test echo server uri tcp://10.10.10.1/20022")
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

func (s *VethsSuite) TestConnection() {
	var startupConfig Stanza
	startupConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").Close()

	serverContainer := s.getContainerByName("server-vpp")

	serverVpp, _ := serverContainer.newVppInstance(startupConfig)
	s.assertNotNil(serverVpp)

	err := serverVpp.start()
	s.assertNil(err)

	// TODO replace netElement with actual implementation
	serverVeth := *s.netConfigs["vppsrv"]
	idx, err := serverVpp.createAfPacket(serverVeth)
	s.assertNil(err)
	s.assertNotEqual(0, idx)
	fmt.Println("Interface index:", idx)

	namespaceSecret := "1"
	err = serverVpp.addAppNamespace(1, idx, namespaceSecret)
	s.assertNil(err)

	//serverVpp.showVersion()

	// Client setup
	clientContainer := s.getContainerByName("client-vpp")

	clientVpp, _ := clientContainer.newVppInstance(startupConfig)
	s.assertNotNil(clientVpp)

	err = clientVpp.start()
	s.assertNil(err)

	// TODO replace netElement with actual implementation
	clientVeth := *s.netConfigs["vppcln"]
	idx, err = clientVpp.createAfPacket(clientVeth)
	s.assertNil(err)
	s.assertNotEqual(0, idx)
	fmt.Println("Interface index:", idx)

	clientNamespaceSecret := "2"
	err = clientVpp.addAppNamespace(2, idx, clientNamespaceSecret)
	s.assertNil(err)

	echoSrvContainer := s.getContainerByName("server-application")
	_, err = echoSrvContainer.execAction("RunEchoServer " + "tcp")
	s.assertNil(err)

	echoClnContainer := s.getContainerByName("client-application")

	o, err := echoClnContainer.execAction("RunEchoClient " + "tcp")
	s.assertNil(err)

	s.log(o)

}
