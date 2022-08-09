package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/edwarnicke/exechelper"
	"github.com/stretchr/testify/suite"
)

type TapSuite struct {
	suite.Suite
	teardownSuite func()
}

func (s *TapSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.teardownSuite = setupSuite(&s.Suite, "tap")
}

func (s *TapSuite) TearDownSuite() {
	s.teardownSuite()
}

type Veths2Suite struct {
	suite.Suite
	teardownSuite func()
}

func (s *Veths2Suite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.teardownSuite = setupSuite(&s.Suite, "2peerVeth")
}

func (s *Veths2Suite) TearDownSuite() {
	s.teardownSuite()
}

type NsSuite struct {
	suite.Suite
	teardownSuite func()
}

func (s *NsSuite) SetupSuite() {
	s.teardownSuite = setupSuite(&s.Suite, "ns")
}

func (s *NsSuite) TearDownSuite() {
	s.teardownSuite()
}

func (s *Veths2Suite) TestEchoBuiltin() {
	t := s.T()
	srvInstance := "echo-srv-internal"
	clnInstance := "echo-cln-internal"
	err := dockerRun(srvInstance, "")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	err = dockerRun(clnInstance, "")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + clnInstance) }()

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

	_, err = hstExec("echo-srv-internal private-segment-size 1g fifo-size 4 no-echo", srvInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	o, err := hstExec("echo-cln-internal nclients 10000 bytes 1 syn-timeout 100 test-timeout 100 no-return private-segment-size 1g fifo-size 4", clnInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	fmt.Println(o)
}

func (s *Veths2Suite) TestVclEchoQuic() {
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
		t.Errorf("%v", err)
		return
	}

	o, err := hstExec("echo-client "+proto, echoCln)
	if err != nil {
		t.Errorf("%v", err)
	}
	fmt.Println(o)
}

func (s *Veths2Suite) TestLDPreloadIperfVpp() {
	t := s.T()
	var clnVclConf, srvVclConf Stanza

	srvInstance := "vpp-ldp-srv"
	clnInstance := "vpp-ldp-cln"
	srvPath := "/tmp/" + srvInstance
	clnPath := "/tmp/" + clnInstance
	srvVcl := srvPath + "/vcl_srv.conf"
	clnVcl := clnPath + "/vcl_cln.conf"

	exechelper.Run("mkdir " + srvPath)
	exechelper.Run("mkdir " + clnPath)

	ldpreload := os.Getenv("HST_LDPRELOAD")
	s.Assert().NotEqual("", ldpreload)

	ldpreload = "LD_PRELOAD=" + ldpreload

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)

	fmt.Println("starting VPPs")

	err := dockerRun(srvInstance, fmt.Sprintf("-v /tmp/%s:/tmp", srvInstance))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + srvInstance) }()

	err = dockerRun(clnInstance, fmt.Sprintf("-v /tmp/%s:/tmp", clnInstance))
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + clnInstance) }()

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

	err = clnVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(fmt.Sprintf("app-socket-api /tmp/%s/2veths/var/run/app_ns_sockets/2", clnInstance)).Close().
		SaveToFile(clnVcl)
	if err != nil {
		t.Errorf("%v", err)
		t.FailNow()
	}

	err = srvVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(fmt.Sprintf("app-socket-api /tmp/%s/2veths/var/run/app_ns_sockets/1", srvInstance)).Close().
		SaveToFile(srvVcl)
	if err != nil {
		t.Errorf("%v", err)
		t.FailNow()
	}
	fmt.Printf("attaching server to vpp")

	// FIXME
	time.Sleep(5 * time.Second)

	srvEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+srvVcl)
	go StartServerApp(srvCh, stopServerCh, srvEnv)

	err = <-srvCh
	if err != nil {
		s.FailNow("vcl server", "%v", err)
	}

	fmt.Println("attaching client to vpp")
	clnEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+clnVcl)
	go StartClientApp(clnEnv, clnCh)

	// wait for client's result
	err = <-clnCh
	if err != nil {
		s.Failf("client", "%v", err)
	}

	// stop server
	stopServerCh <- struct{}{}
}

func waitForSyncFile(fname string) (*JsonResult, error) {
	var res JsonResult

	for i := 0; i < 60; i++ {
		f, err := os.Open(fname)
		if err == nil {
			defer f.Close()

			data, err := ioutil.ReadFile(fname)
			if err != nil {
				return nil, fmt.Errorf("read error: %v", err)
			}
			err = json.Unmarshal(data, &res)
			if err != nil {
				return nil, fmt.Errorf("json unmarshal error: %v", err)
			}
			return &res, nil
		}
		time.Sleep(1 * time.Second)
	}
	return nil, fmt.Errorf("no sync file found")
}

// run vpphelper in docker
func hstExec(args string, instance string) (string, error) {
	syncFile := fmt.Sprintf("/tmp/%s/sync/rc", instance)
	os.Remove(syncFile)

	c := "docker exec -d " + instance + " /hs-test " + args
	err := exechelper.Run(c)
	if err != nil {
		return "", err
	}

	res, err := waitForSyncFile(syncFile)

	if err != nil {
		return "", fmt.Errorf("failed to read sync file while executing './hs-test %s': %v", args, err)
	}

	o := res.StdOutput + res.ErrOutput
	if res.Code != 0 {
		return o, fmt.Errorf("cmd resulted in non-zero value %d: %s", res.Code, res.Desc)
	}
	return o, err
}

func dockerExec(cmd string, instance string) ([]byte, error) {
	c := "docker exec -d " + instance + " " + cmd
	return exechelper.CombinedOutput(c)
}

func testProxyHttpTcp(t *testing.T, dockerInstance string, proxySetup func() error) error {
	const outputFile = "test.data"
	const srcFile = "10M"
	stopServer := make(chan struct{}, 1)
	serverRunning := make(chan struct{}, 1)

	volumeArgs := fmt.Sprintf("-v shared-vol:/tmp/%s", dockerInstance)
	err := dockerRun(dockerInstance, volumeArgs)
	if err != nil {
		return fmt.Errorf("failed to start container: %v", err)
	}
	defer func() { exechelper.Run("docker stop " + dockerInstance) }()

	// start & configure vpp in the container
	_, err = hstExec(dockerInstance, dockerInstance)
	if err != nil {
		return fmt.Errorf("error starting vpp in container: %v", err)
	}

	fmt.Println("VPP running and configured...")

	if err := proxySetup(); err != nil {
		return fmt.Errorf("failed to setup proxy: %v", err)
	}
	fmt.Println("Proxy configured...")

	// create test file
	err = exechelper.Run(fmt.Sprintf("ip netns exec server truncate -s %s %s", srcFile, srcFile))
	if err != nil {
		return fmt.Errorf("failed to run truncate command")
	}
	defer func() { os.Remove(srcFile) }()

	fmt.Println("Test file created...")

	go startHttpServer(serverRunning, stopServer, ":666", "server")
	// TODO better error handling and recovery
	<-serverRunning

	defer func(chan struct{}) {
		stopServer <- struct{}{}
	}(stopServer)

	fmt.Println("http server started...")

	c := fmt.Sprintf("ip netns exec client wget --retry-connrefused --retry-on-http-error=503 --tries=10 -O %s 10.0.0.2:555/%s", outputFile, srcFile)
	_, err = exechelper.CombinedOutput(c)
	if err != nil {
		return fmt.Errorf("failed to run wget: %v", err)
	}
	stopServer <- struct{}{}

	defer func() { os.Remove(outputFile) }()

	if err = assertFileSize(outputFile, srcFile); err != nil {
		return err
	}
	return nil
}

func configureVppProxy() error {
	_, err := dockerExec("vppctl test proxy server server-uri tcp://10.0.0.2/555 client-uri tcp://10.0.1.1/666",
		"vpp-proxy")
	if err != nil {
		return fmt.Errorf("error while configuring vpp proxy test: %v", err)
	}
	return nil
}

func (s *NsSuite) TestVppProxyHttpTcp() {
	t := s.T()
	dockerInstance := "vpp-proxy"
	err := testProxyHttpTcp(t, dockerInstance, configureVppProxy)
	if err != nil {
		t.Errorf("%v", err)
	}
}

func startEnvoy(ctx context.Context, dockerInstance string) <-chan error {
	errCh := make(chan error)
	wd, err := os.Getwd()
	if err != nil {
		errCh <- err
		return errCh
	}

	c := []string{"docker", "run", "--rm", "--name", "envoy",
		"-v", fmt.Sprintf("%s/envoy/proxy.yaml:/etc/envoy/envoy.yaml", wd),
		"-v", fmt.Sprintf("shared-vol:/tmp/%s", dockerInstance),
		"-v", fmt.Sprintf("%s/envoy:/tmp", wd),
		"-e", "VCL_CONFIG=/tmp/vcl.conf",
		"envoyproxy/envoy-contrib:v1.21-latest"}
	fmt.Println(c)

	go func(errCh chan error) {
		count := 0
		var cmd *exec.Cmd
		for ; ; count++ {
			cmd = NewCommand(c, "")
			err = cmd.Start()
			if err == nil {
				break
			}
			if count > 5 {
				errCh <- fmt.Errorf("Failed to start envoy docker after %d attempts", count)
				return
			}
		}

		err = cmd.Wait()
		if err != nil {
			errCh <- fmt.Errorf("failed to start docker: %v", err)
			return
		}
		<-ctx.Done()
	}(errCh)
	return errCh
}

func setupEnvoy(t *testing.T, ctx context.Context, dockerInstance string) error {
	errCh := startEnvoy(ctx, dockerInstance)
	select {
	case err := <-errCh:
		return err
	default:
	}

	go func(ctx context.Context, errCh <-chan error) {
		for {
			select {
			// handle cancel() call from outside to gracefully stop the routine
			case <-ctx.Done():
				return
			default:
				select {
				case err := <-errCh:
					fmt.Printf("error while running envoy: %v", err)
				default:
				}
			}
		}
	}(ctx, errCh)
	return nil
}

func (s *NsSuite) TestEnvoyProxyHttpTcp() {
	t := s.T()
	exechelper.Run("docker volume create --name=shared-vol")
	defer func() {
		exechelper.Run("docker stop envoy")
	}()

	ctx, cancel := context.WithCancel(context.Background())

	dockerInstance := "vpp-envoy"
	err := testProxyHttpTcp(t, dockerInstance, func() error {
		return setupEnvoy(t, ctx, dockerInstance)
	})
	if err != nil {
		t.Errorf("%v", err)
	}
	cancel()
}

func setupSuite(s *suite.Suite, topologyName string) func() {
	t := s.T()
	topology, err := LoadTopology(TopologyDir, topologyName)
	if err != nil {
		t.Fatalf("error on loading topology '%s': %v", topologyName, err)
	}
	err = topology.Configure()
	if err != nil {
		t.Fatalf("failed to configure %s: %v", topologyName, err)
	}

	t.Logf("topo %s loaded", topologyName)
	return func() {
		topology.Unconfigure()
	}
}

func dockerRun(instance, args string) error {
	exechelper.Run(fmt.Sprintf("mkdir -p /tmp/%s/sync", instance))
	syncPath := fmt.Sprintf("-v /tmp/%s/sync:/tmp/sync", instance)
	cmd := "docker run --cap-add=all -d --privileged --network host --rm "
	cmd += syncPath
	cmd += " " + args
	cmd += " --name " + instance + " hs-test/vpp"
	fmt.Println(cmd)
	return exechelper.Run(cmd)
}

func (s *NsSuite) TestHttpTps() {
	t := s.T()
	finished := make(chan error, 1)
	server_ip := "10.0.0.2"
	port := "8080"
	dockerInstance := "http-tps"

	t.Log("starting vpp..")

	err := dockerRun(dockerInstance, "")
	if err != nil {
		t.Errorf("%v", err)
		return
	}
	defer func() { exechelper.Run("docker stop " + dockerInstance) }()

	// start & configure vpp in the container
	_, err = hstExec(dockerInstance, dockerInstance)
	if err != nil {
		t.Errorf("%v", err)
		return
	}

	go startWget(finished, server_ip, port, "client")
	// wait for client
	err = <-finished
	if err != nil {
		t.Errorf("%v", err)
	}
}

func assertFileSize(f1, f2 string) error {
	fi1, err := os.Stat(f1)
	if err != nil {
		return err
	}

	fi2, err1 := os.Stat(f2)
	if err1 != nil {
		return err1
	}

	if fi1.Size() != fi2.Size() {
		return fmt.Errorf("file sizes differ (%d vs %d)", fi1.Size(), fi2.Size())
	}
	return nil
}

func StartServerApp(running chan error, done chan struct{}, env []string) {
	cmd := exec.Command("iperf3", "-4", "-s")
	if env != nil {
		cmd.Env = env
	}
	err := cmd.Start()
	if err != nil {
		msg := fmt.Errorf("failed to start iperf server: %v", err)
		running <- msg
		return
	}
	running <- nil
	<-done
	cmd.Process.Kill()
}

func StartClientApp(env []string, clnCh chan error) {
	defer func() {
		clnCh <- nil
	}()

	nTries := 0

	for {
		cmd := exec.Command("iperf3", "-c", "10.10.10.1", "-u", "-l", "1460", "-b", "10g")
		if env != nil {
			cmd.Env = env
		}
		o, err := cmd.CombinedOutput()
		if err != nil {
			if nTries > 5 {
				clnCh <- fmt.Errorf("failed to start client app '%s'.\n%s", err, o)
				return
			}
			time.Sleep(1 * time.Second)
			nTries++
			continue
		} else {
			fmt.Printf("Client output: %s", o)
		}
		break
	}
}
func (s *TapSuite) TestLinuxIperf() {
	t := s.T()
	clnCh := make(chan error)
	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)
	defer func() {
		stopServerCh <- struct{}{}
	}()

	go StartServerApp(srvCh, stopServerCh, nil)
	err := <-srvCh
	if err != nil {
		t.Errorf("%v", err)
		t.FailNow()
	}
	t.Log("server running")
	go StartClientApp(nil, clnCh)
	t.Log("client running")
	err = <-clnCh
	if err != nil {
		s.Failf("client", "%v", err)
	}
	t.Log("Test completed")
}

func TestTapSuite(t *testing.T) {
	var m TapSuite
	suite.Run(t, &m)
}

func TestNs(t *testing.T) {
	var m NsSuite
	suite.Run(t, &m)
}

func TestVeths2(t *testing.T) {
	var m Veths2Suite
	suite.Run(t, &m)

}
