package main

import (
	"fmt"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(AppNsVclVperfTcpTest, AppNsVclVperfUdpTest)
}

func AppNsVclVperfTcpTest(s *VethsSuite) {
	testAppNsVclVperf(s, "tcp", "1")
}

func AppNsVclVperfUdpTest(s *VethsSuite) {
	testAppNsVclVperf(s, "udp", "1")
}

func testAppNsVclVperf(s *VethsSuite, proto, nsId string) {
	s.SetupAppContainers()

	srvVppCont := s.Containers.ServerVpp
	srvAppCont := s.Containers.ServerApp
	serverVethAddress := s.Interfaces.Server.Ip4AddressString()

	srvVppCont.VppInstance.Vppctl("app ns add id %s secret %s if %s",
		nsId, nsId, s.Interfaces.Server.VppName())
	srvAppCont.CreateFile("/vcl.conf", getVclConfig(srvVppCont, nsId))
	srvAppCont.AddEnvVar("VCL_CONFIG", "/vcl.conf")

	vclSrvCmd := fmt.Sprintf("vperf_server -p %s -B %s %s > %s 2>&1",
		proto, serverVethAddress, s.Ports.Port1, VclTestSrvLogFileName(srvAppCont))
	srvAppCont.ExecServer(true, WrapCmdWithLineBuffering(vclSrvCmd))
	srvVppCont.VppInstance.WaitForApp("vperf_server", 3)

	defaultNsApps := srvVppCont.VppInstance.Vppctl("show app ns id default")
	AssertNotContains(defaultNsApps, "vperf_server")

	clnVppCont := s.Containers.ClientVpp
	clnVppCont.VppInstance.Vppctl("app ns add id %s secret %s if %s",
		nsId, nsId, s.Interfaces.Client.VppName())

	vperfClnContainer := s.GetTransientContainerByName("client-app")
	vperfClnContainer.CreateFile("/vcl.conf", getVclConfig(vperfClnContainer, nsId))
	vperfClnContainer.AddEnvVar("VCL_CONFIG", "/vcl.conf")

	testClientCommand := fmt.Sprintf("vperf_client -X -S -p %s %s %s 2>&1 | tee %s",
		proto, serverVethAddress, s.Ports.Port1, VclTestClnLogFileName(vperfClnContainer))

	o, err := vperfClnContainer.Exec(true, WrapCmdWithLineBuffering(testClientCommand))
	Log("****** Client output:\n%s\n******", o)

	oSrv, errSrv := srvAppCont.Exec(false, "cat %s", VclTestSrvLogFileName(srvAppCont))
	Log("****** Server output:\n%s\n******", oSrv)

	AssertNil(err, o)
	AssertNotContains(o, "aborting test")
	AssertNil(errSrv, oSrv)
}
