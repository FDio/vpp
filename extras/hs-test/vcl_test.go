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
	exechelper.Run("docker volume create --name=echo-srv-vol")
	exechelper.Run("docker volume create --name=echo-cln-vol")

	srvInstance := "vpp-echo-srv"
	clnInstance := "vpp-echo-cln"
	echoSrv := "echo-srv"
	echoCln := "echo-cln"

	s.assertNil(dockerRun(srvInstance, "-v echo-srv-vol:/tmp/Configure2Veths"), "failed to run docker (srv)")
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	s.assertNil(dockerRun(clnInstance, "-v echo-cln-vol:/tmp/Configure2Veths"), "failed to run docker (cln)")
	defer func() { exechelper.Run("docker stop " + clnInstance) }()

	s.assertNil(dockerRun(echoSrv, fmt.Sprintf("-v echo-srv-vol:/tmp/%s", echoSrv)), "failed to run docker (echo srv)")
	defer func() { exechelper.Run("docker stop " + echoSrv) }()

	s.assertNil(dockerRun(echoCln, fmt.Sprintf("-v echo-cln-vol:/tmp/%s", echoCln)), "failed to run docker (echo cln)")
	defer func() { exechelper.Run("docker stop " + echoCln) }()

	_, err := hstExec("Configure2Veths srv", srvInstance)
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
	exechelper.Run("docker volume create --name=echo-srv-vol")
	exechelper.Run("docker volume create --name=echo-cln-vol")

	srvInstance := "vpp-vcl-test-srv"
	clnInstance := "vpp-vcl-test-cln"
	echoSrv := "echo-srv"
	echoCln := "echo-cln"

	s.assertNil(dockerRun(srvInstance, "-v echo-srv-vol:/tmp/Configure2Veths"), "failed to run docker (srv)")
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	s.assertNil(dockerRun(clnInstance, "-v echo-cln-vol:/tmp/Configure2Veths"), "failed to run docker (cln)")
	defer func() { exechelper.Run("docker stop " + clnInstance) }()

	s.assertNil(dockerRun(echoSrv, fmt.Sprintf("-v echo-srv-vol:/tmp/%s", echoSrv)), "failed to run docker (echo srv)")
	defer func() { exechelper.Run("docker stop " + echoSrv) }()

	s.assertNil(dockerRun(echoCln, fmt.Sprintf("-v echo-cln-vol:/tmp/%s", echoCln)), "failed to run docker (echo cln)")
	defer func() { exechelper.Run("docker stop " + echoCln) }()

	_, err := hstExec("Configure2Veths srv-with-preset-hw-addr", srvInstance)
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
