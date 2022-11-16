package main

import (
	"fmt"
	"time"
	"strings"

	"github.com/edwarnicke/exechelper"
)

func (s *Veths2Suite) TestVclEchoQuic() {
	s.T().Skip("quic test skipping..")
	s.testVclEcho("quic")
}

func (s *Veths2Suite) TestVclEchoUdp() {
	s.T().Skip("udp echo currently broken in vpp, skipping..")
	s.testVclEcho("udp")
}

func (s *Veths2Suite) TestVclEchoTcp() {
	s.testVclEcho("tcp")
}

func (s *Veths2Suite) testVclEcho(proto string) {
	t := s.T()

	exechelper.Run("docker volume create --name=echo-srv-vol")
	exechelper.Run("docker volume create --name=echo-cln-vol")

	srvInstance := "vpp-echo-srv"
	clnInstance := "vpp-echo-cln"
	echoSrv := "echo-srv"
	echoCln := "echo-cln"

	err := dockerRun(srvInstance, "-v echo-srv-vol:/tmp/2veths")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	err = dockerRun(clnInstance, "-v echo-cln-vol:/tmp/2veths")
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

	_, err = hstExec("2veths srv", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	_, err = hstExec("2veths cln", clnInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	// run server app
	_, err = hstExec("echo-server "+proto, echoSrv)
	if err != nil {
		t.Errorf("echo server: %v", err)
		return
	}

	o, err := hstExec("echo-client "+proto, echoCln)
	if err != nil {
		t.Errorf("echo client: %v", err)
	}
	fmt.Println(o)
}

func (s *Veths2Suite) TestVclRetryAttach() {
	s.T().Skip()
	s.testRetryAttach("tcp")
}

func (s *Veths2Suite) testRetryAttach(proto string) {
	t := s.T()

	exechelper.Run("docker volume create --name=echo-srv-vol")
	exechelper.Run("docker volume create --name=echo-cln-vol")

	srvInstance := "vpp-vcl-test-srv"
	clnInstance := "vpp-vcl-test-cln"
	echoSrv := "echo-srv"
	echoCln := "echo-cln"

	err := dockerRun(srvInstance, "-v echo-srv-vol:/tmp/2veths")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	err = dockerRun(clnInstance, "-v echo-cln-vol:/tmp/2veths")
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

	_, err = hstExec("2veths srv-with-preset-hw-addr", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	_, err = hstExec("2veths cln", clnInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	_, err = hstExec("vcl-test-server "+proto, echoSrv)
	if err != nil {
		t.Errorf("vcl test server: %v", err)
		return
	}

	fmt.Println("This whole test case can take around 3 minutes to run. Please be patient.")
	fmt.Println("... Running first echo client test, before disconnect.")
	_, err = hstExec("vcl-test-client "+proto, echoCln)
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
	_, err = hstExec("2veths srv-with-preset-hw-addr", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	fmt.Println("... VPP server is starting again, so waiting for a bit.")
	time.Sleep(30 * time.Second) // Wait a moment for the re-attachment to happen

	fmt.Println("... Running second echo client test, after disconnect and re-attachment.")
	_, err = hstExec("vcl-test-client "+proto, echoCln)
	if err != nil {
		t.Errorf("vcl test client: %v", err)
	}
	fmt.Println("Done.")
}

func (s *Veths2Suite) TestTcpWithLoss() {
	t := s.T()

	srvContainerName := "vpp-echo-srv"
	clnContainerName := "vpp-echo-cln"

	err := dockerRun(srvContainerName, "")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + srvContainerName) }()

	err = dockerRun(clnContainerName, "")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + clnContainerName) }()

	_, err = hstExec("2veths srv", srvContainerName)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	_, err = hstExec("2veths cln", clnContainerName)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	socketPath := "/tmp/2veths/var/run/vpp/cli.sock"

	// Start built-in echo server in server-vpp container
	output := vppctl(t, srvContainerName, socketPath, "test echo server uri tcp://10.10.10.1/20022");

	// Ensure that VPP doesn't abort itself with NSIM enabled
	// Warning: Removing this ping will make the test fail!
	vppctl(t, srvContainerName, socketPath, "ping 10.10.10.2")

	// Add loss of packets with Network Delay Simulator
	vppctl(
		t,
		clnContainerName,
		socketPath,
		"set nsim poll-main-thread delay 0.01 ms bandwidth 40 gbit packet-size 1400 packets-per-drop 1000")
	vppctl(
		t,
		clnContainerName,
		socketPath,
		"nsim output-feature enable-disable host-vppcln")

	// Do echo test from client-vpp container
	output = vppctl(
		t,
		clnContainerName,
		socketPath,
		"test echo client uri tcp://10.10.10.1/20022 mbytes 50")
	if len(output) == 0 {
		t.Errorf("echo test failed: output is empty")
	} else if strings.Contains(output, "failed: timeout") {
		t.Errorf("echo test failed: session timed out")
	}
	fmt.Println(output)
}

// TODO once methods are returning errors, add assertions
func (s *Veths2Suite) TestTcpWithLoss2() {
	serverContainer := s.NewContainer("server")
	serverContainer.start()

	serverVpp := NewVpp(serverContainer)
	serverVpp.setCliSocket("/var/run/vpp/cli.sock")
	serverVpp.setServer()
	serverVpp.start()
	serverVpp.vppctl("test echo server uri tcp://10.10.10.1/20022")

	clientContainer := s.NewContainer("client")
	clientContainer.start()
	clientVpp := NewVpp(clientContainer)
	clientVpp.setCliSocket("/var/run/vpp/cli.sock")
	clientVpp.setClient()
	clientVpp.start()

	serverVpp.vppctl("ping 10.10.10.2")
	clientVpp.vppctl("set nsim poll-main-thread delay 0.01 ms bandwidth 40 gbit packet-size 1400 packets-per-drop 1000")
	clientVpp.vppctl("nsim output-feature enable-disable host-vppcln")
	clientVpp.vppctl("test echo client uri tcp://10.10.10.1/20022 mbytes 50")
}
