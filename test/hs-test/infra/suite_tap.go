package hst

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

type TapSuite struct {
	HstSuite
	Interfaces struct {
		Server *NetInterface
		Client *NetInterface
	}
	Containers struct {
		ServerVpp *Container
		ClientVpp *Container
		ServerApp *Container
		ClientApp *Container
	}
	Ports struct {
		Port1 string
		Port2 string
	}
}

func (s *TapSuite) SetupSuite() {
	time.Sleep(1 * time.Second)
	s.HstSuite.SetupSuite()
	s.ConfigureNetworkTopology("2peerTap")
	s.LoadContainerTopology("2peerVeth")
	s.Interfaces.Client = s.GetInterfaceByName("cln")
	s.Interfaces.Server = s.GetInterfaceByName("srv")
	s.Containers.ServerVpp = s.GetContainerByName("server-vpp")
	s.Containers.ClientVpp = s.GetContainerByName("client-vpp")
	s.Containers.ServerApp = s.GetContainerByName("server-app")
	s.Containers.ClientApp = s.GetContainerByName("client-app")
	s.Ports.Port1 = s.GeneratePort()
	s.Ports.Port2 = s.GeneratePort()
}

func (s *TapSuite) SetupTest(startupConf ...Stanza) {
	s.HstSuite.SetupTest()

	var customStartupConf1 Stanza
	var customStartupConf2 Stanza
	if len(startupConf) > 0 {
		customStartupConf1 = startupConf[0]
		if len(startupConf) > 1 {
			customStartupConf2 = startupConf[1]
		}
	}

	var sessionConfig Stanza
	sessionConfig.
		NewStanza("session").
		Append("enable").
		Append("use-app-socket-api").
		Append("event-queue-length 100000")

	if strings.Contains(CurrentSpecReport().LeafNodeText, "InterruptMode") {
		sessionConfig.Append("use-private-rx-mqs").Close()
		Log("**********************INTERRUPT MODE**********************")
	} else {
		sessionConfig.Close()
	}

	var httpConfig Stanza
	httpConfig.NewStanza("http").NewStanza("http2").Append("max-header-list-size 65536").Close().Close()

	serverVpp, err := s.Containers.ServerVpp.newVppInstance(s.Containers.ServerVpp.AllocatedCpus, sessionConfig, customStartupConf1, customStartupConf2)
	AssertNotNil(serverVpp, fmt.Sprint(err))

	clientVpp, err := s.Containers.ClientVpp.newVppInstance(s.Containers.ClientVpp.AllocatedCpus, sessionConfig, httpConfig, customStartupConf1, customStartupConf2)
	AssertNotNil(clientVpp, fmt.Sprint(err))

	s.SetupServerVpp()
	s.SetupClientVpp()
	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *TapSuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverVpp := s.Containers.ServerVpp.VppInstance
	if CurrentSpecReport().Failed() {
		CollectVclTestSrvLogs(s.Containers.ServerApp)
		CollectVclTestClnLogs(s.Containers.ClientApp)
		Log(clientVpp.Vppctl("show session verbose 2"))
		Log(clientVpp.Vppctl("show error"))
		Log(serverVpp.Vppctl("show session verbose 2"))
		Log(serverVpp.Vppctl("show error"))
	}
}

func (s *TapSuite) SetupServerVpp() {
	serverVpp := s.Containers.ServerVpp.VppInstance
	AssertNil(serverVpp.Start())
	AssertNil(serverVpp.CreateTap(s.Interfaces.Server, false, 1), "failed to create tap interface")
}

func (s *TapSuite) SetupClientVpp() {
	clientVpp := s.Containers.ClientVpp.VppInstance
	AssertNil(clientVpp.Start())
	AssertNil(clientVpp.CreateTap(s.Interfaces.Client, false, 1), "failed to create tap interface")
}

func (s *TapSuite) SetupAppContainers() {
	s.Containers.ClientApp.Run()
	s.Containers.ServerApp.Run()
}
