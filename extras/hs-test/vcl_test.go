package main

import (
	"fmt"
	"time"

)

func (s *VethsSuite) TestVclEchoQuic() {
	s.T().Skip("quic test skipping..")
	s.testVclEcho("quic")
}

func (s *VethsSuite) TestVclEchoUdp() {
	s.T().Skip("udp echo currently broken in vpp, skipping..")
	s.testVclEcho("udp")
}

func (s *VethsSuite) TestVclEchoTcp() {
	s.testVclEcho("tcp")
}

func (s *VethsSuite) testVclEcho(proto string) {
	srvInstance := s.GetContainers()[0]
	_, err := hstExec("Configure2Veths srv", srvInstance.name)
	s.assertNil(err)

	clnInstance := s.GetContainers()[1]
	_, err = hstExec("Configure2Veths cln", clnInstance.name)
	s.assertNil(err)

	// run server app
	echoSrv := s.GetContainers()[2]
	_, err = hstExec("RunEchoServer "+proto, echoSrv.name)
	s.assertNil(err)

	echoCln := s.GetContainers()[3]
	o, err := hstExec("RunEchoClient "+proto, echoCln.name)
	s.assertNil(err)

	fmt.Println(o)
}

func (s *VethsSuite) TestVclRetryAttach() {
	s.T().Skip()
	s.testRetryAttach("tcp")
}

func (s *VethsSuite) testRetryAttach(proto string) {
	serverVolume := "echo-srv-vol"
	s.NewVolume(serverVolume)

	clientVolume := "echo-cln-vol"
	s.NewVolume(clientVolume)

	srvInstance := "vpp-vcl-test-srv"
	serverVppContainer, err := s.NewContainer(srvInstance)
	s.assertNil(err)
	serverVppContainer.addVolume(serverVolume, "/tmp/Configure2Veths")
	s.assertNil(serverVppContainer.run())

	clnInstance := "vpp-vcl-test-cln"
	clientVppContainer, err := s.NewContainer(clnInstance)
	s.assertNil(err)
	clientVppContainer.addVolume(clientVolume, "/tmp/Configure2Veths")
	s.assertNil(clientVppContainer.run())

	echoSrv := "echo-srv"
	serverEchoContainer, err := s.NewContainer(echoSrv)
	s.assertNil(err)
	serverEchoContainer.addVolume(serverVolume, "/tmp/" + echoSrv)
	s.assertNil(serverEchoContainer.run())

	echoCln := "echo-cln"
	clientEchoContainer, err := s.NewContainer(echoCln)
	s.assertNil(err)
	clientEchoContainer.addVolume(clientVolume, "/tmp/" + echoCln)
	s.assertNil(clientEchoContainer.run())

	_, err = hstExec("Configure2Veths srv-with-preset-hw-addr", srvInstance)
	s.assertNil(err)

	_, err = hstExec("Configure2Veths cln", clnInstance)
	s.assertNil(err)

	_, err = hstExec("RunVclEchoServer "+proto, echoSrv)
	s.assertNil(err)

	fmt.Println("This whole test case can take around 3 minutes to run. Please be patient.")
	fmt.Println("... Running first echo client test, before disconnect.")
	_, err = hstExec("RunVclEchoClient "+proto, echoCln)
	s.assertNil(err)
	fmt.Println("... First test ended. Stopping VPP server now.")

	// Stop server-vpp-instance, start it again and then run vcl-test-client once more
	stopVppCommand := "/bin/bash -c 'ps -C vpp_main -o pid= | xargs kill -9'"
	_, err = dockerExec(stopVppCommand, srvInstance)
	s.assertNil(err)
	time.Sleep(5 * time.Second) // Give parent process time to reap the killed child process
	stopVppCommand = "/bin/bash -c 'ps -C hs-test -o pid= | xargs kill -9'"
	_, err = dockerExec(stopVppCommand, srvInstance)
	s.assertNil(err)
	_, err = hstExec("Configure2Veths srv-with-preset-hw-addr", srvInstance)
	s.assertNil(err)

	fmt.Println("... VPP server is starting again, so waiting for a bit.")
	time.Sleep(30 * time.Second) // Wait a moment for the re-attachment to happen

	fmt.Println("... Running second echo client test, after disconnect and re-attachment.")
	_, err = hstExec("RunVclEchoClient "+proto, echoCln)
	s.assertNil(err)
	fmt.Println("Done.")
}

func (s *VethsSuite) TestTcpWithLoss() {
	serverContainer := s.GetContainers()[0]

	serverVpp := NewVppInstance(serverContainer)
	s.assertNotNil(serverVpp)
	serverVpp.setCliSocket("/var/run/vpp/cli.sock")
	serverVpp.set2VethsServer()
	err := serverVpp.start()
	s.assertNil(err, "starting VPP failed")

	_, err = serverVpp.vppctl("test echo server uri tcp://10.10.10.1/20022")
	s.assertNil(err, "starting echo server failed")

	clientContainer := s.GetContainers()[1]

	clientVpp := NewVppInstance(clientContainer)
	s.assertNotNil(clientVpp)
	clientVpp.setCliSocket("/var/run/vpp/cli.sock")
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
	fmt.Println(output)
}
