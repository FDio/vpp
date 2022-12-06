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
	serverVolume := "echo-srv-vol"
	s.NewVolume(serverVolume)

	clientVolume := "echo-cln-vol"
	s.NewVolume(clientVolume)

	srvInstance := "vpp-vcl-test-srv"
	serverVppContainer, err := s.NewContainer(srvInstance)
	s.assertNil(err)
	serverVppContainer.addVolume(serverVolume, "/tmp/Configure2Veths")
	serverVppContainer.run()

	clnInstance := "vpp-vcl-test-cln"
	clientVppContainer, err := s.NewContainer(clnInstance)
	s.assertNil(err)
	clientVppContainer.addVolume(clientVolume, "/tmp/Configure2Veths")
	clientVppContainer.run();

	echoSrv := "echo-srv"
	serverEchoContainer, err := s.NewContainer(echoSrv)
	s.assertNil(err)
	serverEchoContainer.addVolume(serverVolume, "/tmp/" + echoSrv)
	serverEchoContainer.run()

	echoCln := "echo-cln"
	clientEchoContainer, err := s.NewContainer(echoCln)
	s.assertNil(err)
	clientEchoContainer.addVolume(clientVolume, "/tmp/" + echoCln)
	clientEchoContainer.run()

	_, err = hstExec("Configure2Veths srv", srvInstance)
	s.assertNil(err)

	_, err = hstExec("Configure2Veths cln", clnInstance)
	s.assertNil(err)

	// run server app
	_, err = hstExec("RunEchoServer "+proto, echoSrv)
	s.assertNil(err)

	o, err := hstExec("RunEchoClient "+proto, echoCln)
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
	serverVppContainer.run()

	clnInstance := "vpp-vcl-test-cln"
	clientVppContainer, err := s.NewContainer(clnInstance)
	s.assertNil(err)
	clientVppContainer.addVolume(clientVolume, "/tmp/Configure2Veths")
	clientVppContainer.run();

	echoSrv := "echo-srv"
	serverEchoContainer, err := s.NewContainer(echoSrv)
	s.assertNil(err)
	serverEchoContainer.addVolume(serverVolume, "/tmp/" + echoSrv)
	serverEchoContainer.run()

	echoCln := "echo-cln"
	clientEchoContainer, err := s.NewContainer(echoCln)
	s.assertNil(err)
	clientEchoContainer.addVolume(clientVolume, "/tmp/" + echoCln)
	clientEchoContainer.run()

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
