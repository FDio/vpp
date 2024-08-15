package main

import (
	"fmt"
	"os"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVethTests(LDPreloadIperfVppTest, LDPreloadIperfVppInterruptModeTest, RedisBenchmarkTest)
}

func LDPreloadIperfVppInterruptModeTest(s *VethsSuite) {
	LDPreloadIperfVppTest(s)
}

func LDPreloadIperfVppTest(s *VethsSuite) {
	var clnVclConf, srvVclConf Stanza
	var ldpreload string

	serverContainer := s.GetContainerByName("server-vpp")
	serverVclFileName := serverContainer.GetHostWorkDir() + "/vcl_srv.conf"

	clientContainer := s.GetContainerByName("client-vpp")
	clientVclFileName := clientContainer.GetHostWorkDir() + "/vcl_cln.conf"

	if *IsDebugBuild {
		ldpreload = "LD_PRELOAD=../../build-root/build-vpp_debug-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so"
	} else {
		ldpreload = "LD_PRELOAD=../../build-root/build-vpp-native/vpp/lib/x86_64-linux-gnu/libvcl_ldpreload.so"
	}

	stopServerCh := make(chan struct{}, 1)
	srvCh := make(chan error, 1)
	clnCh := make(chan error)

	s.Log("starting VPPs")

	clientAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		clientContainer.GetHostWorkDir())
	err := clnVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(clientAppSocketApi).Close().
		SaveToFile(clientVclFileName)
	s.AssertNil(err, fmt.Sprint(err))

	serverAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		serverContainer.GetHostWorkDir())
	err = srvVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(serverAppSocketApi).Close().
		SaveToFile(serverVclFileName)
	s.AssertNil(err, fmt.Sprint(err))

	s.Log("attaching server to vpp")

	srvEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+serverVclFileName)
	go func() {
		defer GinkgoRecover()
		s.StartServerApp(srvCh, stopServerCh, srvEnv)
	}()

	err = <-srvCh
	s.AssertNil(err, fmt.Sprint(err))

	s.Log("attaching client to vpp")
	var clnRes = make(chan string, 1)
	clnEnv := append(os.Environ(), ldpreload, "VCL_CONFIG="+clientVclFileName)
	serverVethAddress := s.GetInterfaceByName(ServerInterfaceName).Ip4AddressString()
	go func() {
		defer GinkgoRecover()
		s.StartClientApp(serverVethAddress, clnEnv, clnCh, clnRes)
	}()
	s.Log(<-clnRes)

	// wait for client's result
	err = <-clnCh
	s.AssertNil(err, fmt.Sprint(err))

	// stop server
	stopServerCh <- struct{}{}
}

func RedisBenchmarkTest(s *VethsSuite) {
	s.SkipIfMultiWorker()
	var clnVclConf, srvVclConf Stanza
	envVarsCln := make(map[string]string)
	envVarsSrv := make(map[string]string)

	serverContainer := s.GetContainerByName("server-vpp")
	serverVclFileName := serverContainer.GetHostWorkDir() + "/vcl_srv.conf"
	defer delete(serverContainer.EnvVars, "LD_PRELOAD")
	defer delete(serverContainer.EnvVars, "VCL_CONFIG")

	clientContainer := s.GetContainerByName("client-vpp")
	clientVclFileName := clientContainer.GetHostWorkDir() + "/vcl_cln.conf"
	defer delete(clientContainer.EnvVars, "LD_PRELOAD")
	defer delete(clientContainer.EnvVars, "VCL_CONFIG")

	envVarsCln["LD_PRELOAD"] = "/usr/lib/libvcl_ldpreload.so"
	envVarsSrv["LD_PRELOAD"] = "/usr/lib/libvcl_ldpreload.so"
	serverVethAddress := s.GetInterfaceByName(ServerInterfaceName).Ip4AddressString()
	runningSrv := make(chan error)
	doneSrv := make(chan struct{})
	clnCh := make(chan error)
	clnRes := make(chan string, 1)

	s.Log("starting VPPs")
	// putting these VCL configs into a function doesn't work for some reason ("ERROR: ldp_constructor: failed!")
	clientAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		clientContainer.GetContainerWorkDir())
	err := clnVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(clientAppSocketApi).Close().
		SaveToFile(clientVclFileName)
	s.AssertNil(err, fmt.Sprint(err))

	serverAppSocketApi := fmt.Sprintf("app-socket-api %s/var/run/app_ns_sockets/default",
		serverContainer.GetContainerWorkDir())
	err = srvVclConf.
		NewStanza("vcl").
		Append("rx-fifo-size 4000000").
		Append("tx-fifo-size 4000000").
		Append("app-scope-local").
		Append("app-scope-global").
		Append("use-mq-eventfd").
		Append(serverAppSocketApi).Close().
		SaveToFile(serverVclFileName)
	s.AssertNil(err, fmt.Sprint(err))

	s.Log("attaching server to vpp")
	// LDP_DEBUG=1 generates a 450+ MB log file
	envVarsCln["LDP_DEBUG"] = "0"
	envVarsCln["VCL_CONFIG"] = clientContainer.GetContainerWorkDir() + "/vcl_cln.conf"
	envVarsSrv["VCL_CONFIG"] = serverContainer.GetContainerWorkDir() + "/vcl_srv.conf"

	go func() {
		defer GinkgoRecover()
		s.StartRedisServer(serverContainer, serverVethAddress, envVarsSrv, runningSrv, doneSrv)
	}()

	err = <-runningSrv
	s.AssertNil(err)
	s.Log("attaching client to vpp")

	go func() {
		defer GinkgoRecover()
		if *NConfiguredCpus == 1 {
			s.StartRedisBenchmark(clientContainer, serverVethAddress, envVarsCln, clnCh, clnRes, "1")
		} else {
			s.StartRedisBenchmark(clientContainer, serverVethAddress, envVarsCln, clnCh, clnRes, fmt.Sprint(*NConfiguredCpus))
		}

	}()

	s.Log(<-clnRes)
	// wait for client's result
	s.Log(serverContainer.VppInstance.Vppctl("show err"))
	err = <-clnCh
	s.AssertNil(err, fmt.Sprint(err))
	// stop server
	doneSrv <- struct{}{}
}
