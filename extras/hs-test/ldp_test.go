package main

import (
	"fmt"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVethTests(LDPreloadIperfVppTest, LDPreloadIperfVppInterruptModeTest)
}

func LDPreloadIperfVppInterruptModeTest(s *VethsSuite) {
	LDPreloadIperfVppTest(s)
}

func LDPreloadIperfVppTest(s *VethsSuite) {
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

	runningSrv := make(chan error)
	doneSrv := make(chan struct{})
	clnCh := make(chan error)
	clnRes := make(chan string, 1)

	s.Log("starting VPPs")

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

	envVarsCln["VCL_CONFIG"] = clientContainer.GetContainerWorkDir() + "/vcl_cln.conf"
	envVarsSrv["VCL_CONFIG"] = serverContainer.GetContainerWorkDir() + "/vcl_srv.conf"

	go func() {
		defer GinkgoRecover()
		s.StartServerApp(serverContainer, envVarsSrv, runningSrv, doneSrv)
	}()

	err = <-runningSrv
	s.AssertNil(err)

	s.Log("attaching client to vpp")
	serverVethAddress := s.GetInterfaceByName(ServerInterfaceName).Ip4AddressString()
	go func() {
		defer GinkgoRecover()
		s.StartClientApp(clientContainer, serverVethAddress, envVarsCln, clnCh, clnRes)
	}()
	s.Log(<-clnRes)

	// wait for client's result
	err = <-clnCh
	s.AssertNil(err, fmt.Sprint(err))

	// stop server
	doneSrv <- struct{}{}
}
