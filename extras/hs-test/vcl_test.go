package main

import (
	"fmt"
	"time"

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
	s.testRetryAttach("tcp")
}

func (s *Veths2Suite) testRetryAttach(proto string) {
	t := s.T()

	exechelper.Run("docker volume create --name=echo-srv-vol") // Here is socket 1
	exechelper.Run("docker volume create --name=echo-cln-vol") // Here is socket 2

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

	_, err = hstExec("vcl-test-server ", echoSrv)
	if err != nil {
		t.Errorf("vcl test server: %v", err)
		return
	}

	fmt.Println("First echo client test, before disconnect.")
	o, err := hstExec("vcl-test-client ", echoCln)
	if err != nil {
		t.Errorf("vcl test client: %v", err)
		return
	}
	fmt.Println(o)

	// TODO: stop server-vpp-instance, start it again and then run vcl-test-client once more
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
	_, err = hstExec("2veths srv", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	fmt.Println("First test ended. VPP server is starting. Now waiting for a bit.")
	time.Sleep(80 * time.Second) // Wait a moment for the re-attachment to happen

	fmt.Println("Second echo client test, after disconnect and re-attachment.")
	o, err = hstExec("vcl-test-client ", echoCln)
	if err != nil {
		t.Errorf("vcl test client: %v", err)
	}
	fmt.Println(o)
}
