package main

import (
	"fmt"
	"time"

	"github.com/edwarnicke/exechelper"
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
	t := s.T()

	exechelper.Run("docker volume create --name=echo-srv-vol")
	exechelper.Run("docker volume create --name=echo-cln-vol")

	srvInstance := "vpp-echo-srv"
	clnInstance := "vpp-echo-cln"
	echoSrv := "echo-srv"
	echoCln := "echo-cln"

	err := dockerRun(srvInstance, "-v echo-srv-vol:/tmp/Configure2Veths")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	err = dockerRun(clnInstance, "-v echo-cln-vol:/tmp/Configure2Veths")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + clnInstance) }()

	err = dockerRun(echoSrv, fmt.Sprintf("-v echo-srv-vol:/tmp/%s", echoSrv))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + echoSrv) }()

	err = dockerRun(echoCln, fmt.Sprintf("-v echo-cln-vol:/tmp/%s", echoCln))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + echoCln) }()

	_, err = hstExec("Configure2Veths srv", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	_, err = hstExec("Configure2Veths cln", clnInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	// run server app
	_, err = hstExec("RunEchoServer "+proto, echoSrv)
	if err != nil {
		t.Errorf("echo server: %v", err)
		return
	}

	o, err := hstExec("RunEchoClient "+proto, echoCln)
	if err != nil {
		t.Errorf("echo client: %v", err)
	}
	fmt.Println(o)
}

func (s *VethsSuite) TestVclRetryAttach() {
	s.T().Skip()
	s.testRetryAttach("tcp")
}

func (s *VethsSuite) testRetryAttach(proto string) {
	t := s.T()

	exechelper.Run("docker volume create --name=echo-srv-vol")
	exechelper.Run("docker volume create --name=echo-cln-vol")

	srvInstance := "vpp-vcl-test-srv"
	clnInstance := "vpp-vcl-test-cln"
	echoSrv := "echo-srv"
	echoCln := "echo-cln"

	err := dockerRun(srvInstance, "-v echo-srv-vol:/tmp/Configure2Veths")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	err = dockerRun(clnInstance, "-v echo-cln-vol:/tmp/Configure2Veths")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + clnInstance) }()

	err = dockerRun(echoSrv, fmt.Sprintf("-v echo-srv-vol:/tmp/%s", echoSrv))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + echoSrv) }()

	err = dockerRun(echoCln, fmt.Sprintf("-v echo-cln-vol:/tmp/%s", echoCln))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + echoCln) }()

	_, err = hstExec("Configure2Veths srv-with-preset-hw-addr", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	_, err = hstExec("Configure2Veths cln", clnInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	_, err = hstExec("RunVclEchoServer "+proto, echoSrv)
	if err != nil {
		t.Errorf("vcl test server: %v", err)
		return
	}

	fmt.Println("This whole test case can take around 3 minutes to run. Please be patient.")
	fmt.Println("... Running first echo client test, before disconnect.")
	_, err = hstExec("RunVclEchoClient "+proto, echoCln)
	if err != nil {
		t.Errorf("vcl test client: %v", err)
		return
	}
	fmt.Println("... First test ended. Stopping VPP server now.")

	// Stop server-vpp-instance, start it again and then run vcl-test-client once more
	stopVppCommand := "/bin/bash -c 'ps -C vpp_main -o pid= | xargs kill -9'"
	_, err = dockerExec(stopVppCommand, srvInstance)
	if err != nil {
		t.Errorf("error while stopping vpp: %v", err)
		return
	}
	time.Sleep(5 * time.Second) // Give parent process time to reap the killed child process
	stopVppCommand = "/bin/bash -c 'ps -C hs-test -o pid= | xargs kill -9'"
	_, err = dockerExec(stopVppCommand, srvInstance)
	if err != nil {
		t.Errorf("error while stopping hs-test: %v", err)
		return
	}
	_, err = hstExec("Configure2Veths srv-with-preset-hw-addr", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	fmt.Println("... VPP server is starting again, so waiting for a bit.")
	time.Sleep(30 * time.Second) // Wait a moment for the re-attachment to happen

	fmt.Println("... Running second echo client test, after disconnect and re-attachment.")
	_, err = hstExec("RunVclEchoClient "+proto, echoCln)
	if err != nil {
		t.Errorf("vcl test client: %v", err)
	}
	fmt.Println("Done.")
}

func (s *VethsSuite) TestTcpWithLoss() {
	serverContainer, err := s.NewContainer("server")
	s.assertNil(err, "creating container failed")
	err = serverContainer.run()
	s.assertNil(err)

	serverVpp := NewVppInstance(serverContainer)
	s.assertNotNil(serverVpp)
	serverVpp.setCliSocket("/var/run/vpp/cli.sock")
	serverVpp.set2VethsServer()
	err = serverVpp.start()
	s.assertNil(err, "starting VPP failed")

	_, err = serverVpp.vppctl("test echo server uri tcp://10.10.10.1/20022")
	s.assertNil(err, "starting echo server failed")

	clientContainer, err := s.NewContainer("client")
	s.assertNil(err, "creating container failed")
	err = clientContainer.run()
	s.assertNil(err, "starting container failed")

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
