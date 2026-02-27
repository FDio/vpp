// Suite for VPP proxy testing
//
// The topology consists of 3 containers: curl (client), VPP (proxy), nginx (target HTTP server).
// VPP has 2 tap interfaces configured, one for client network and second for server/target network.

package hst

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"fd.io/hs-test/h2spec_extras"
	. "github.com/onsi/ginkgo/v2"
	"github.com/summerwind/h2spec/config"
)

const (
	CurlContainerTestFile = "/tmp/testFile"
)

type VppProxySuite struct {
	HstSuite
	maxTimeout int
	Interfaces struct {
		Client *NetInterface
		Server *NetInterface
	}
	Containers struct {
		VppProxy             *Container
		Curl                 *Container
		NginxServerTransient *Container
		IperfS               *Container
		IperfC               *Container
	}
	Ports struct {
		Server    uint16
		ServerSsl uint16
		Proxy     uint16
	}
}

var vppProxyTests = map[string][]func(s *VppProxySuite){}
var vppProxySoloTests = map[string][]func(s *VppProxySuite){}
var vppProxyMWTests = map[string][]func(s *VppProxySuite){}

func RegisterVppProxyTests(tests ...func(s *VppProxySuite)) {
	vppProxyTests[GetTestFilename()] = tests
}
func RegisterVppProxySoloTests(tests ...func(s *VppProxySuite)) {
	vppProxySoloTests[GetTestFilename()] = tests
}
func RegisterVppProxyMWTests(tests ...func(s *VppProxySuite)) {
	vppProxyMWTests[GetTestFilename()] = tests
}

func (s *VppProxySuite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("2taps")
	s.LoadContainerTopology("vppProxy")
	s.Ports.Server = s.GeneratePortAsInt()
	s.Ports.ServerSsl = s.GeneratePortAsInt()
	s.Ports.Proxy = s.GeneratePortAsInt()

	if *IsVppDebug {
		s.maxTimeout = 600
	} else {
		s.maxTimeout = 60
	}
	s.Interfaces.Client = s.GetInterfaceByName("hstcln")
	s.Interfaces.Server = s.GetInterfaceByName("hstsrv")
	s.Containers.NginxServerTransient = s.GetTransientContainerByName("nginx-server")
	s.Containers.VppProxy = s.GetContainerByName("vpp-proxy")
	s.Containers.Curl = s.GetContainerByName("curl")
	s.Containers.IperfC = s.GetContainerByName("iperfC")
	s.Containers.IperfS = s.GetContainerByName("iperfS")
}

func (s *VppProxySuite) SetupTest(proxyConfig ...Stanza) {
	s.HstSuite.SetupTest()

	// VPP HTTP connect-proxy
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()

	var customProxyConfig Stanza
	if len(proxyConfig) > 0 {
		customProxyConfig = proxyConfig[0]
	}

	vpp, err := s.Containers.VppProxy.newVppInstance(s.Containers.VppProxy.AllocatedCpus, memoryConfig, customProxyConfig)
	AssertNotNil(vpp, fmt.Sprint(err))

	AssertNil(vpp.Start())
	AssertNil(vpp.CreateTap(s.Interfaces.Client, false, 1))
	AssertNil(vpp.CreateTap(s.Interfaces.Server, false, 2))

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *VppProxySuite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	vpp := s.Containers.VppProxy.VppInstance
	if CurrentSpecReport().Failed() {
		Log(vpp.Vppctl("show session verbose 2"))
		Log(vpp.Vppctl("show error"))
		CollectNginxLogs(s.Containers.NginxServerTransient)
		CollectIperfLogs(s.Containers.IperfS)
	}
}

func (s *VppProxySuite) SetupNginxServer() {
	AssertNil(s.Containers.NginxServerTransient.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      uint16
		PortSsl   uint16
		Http2     string
		Timeout   int
	}{
		LogPrefix: s.Containers.NginxServerTransient.Name,
		Address:   s.Interfaces.Server.Host.Ip4AddressString(),
		Port:      s.Ports.Server,
		PortSsl:   s.Ports.ServerSsl,
		Http2:     "off",
		Timeout:   s.maxTimeout,
	}
	s.Containers.NginxServerTransient.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)
	AssertNil(s.Containers.NginxServerTransient.Start())
}

func (s *VppProxySuite) ConfigureVppProxy(proto string, proxyPort uint16) {
	vppProxy := s.Containers.VppProxy.VppInstance
	cmd := fmt.Sprintf("test proxy server fifo-size 512k server-uri %s://%s:%d", proto, s.VppProxyAddr(), proxyPort)
	if proto != "http" && proto != "https" && proto != "udp" {
		proto = "tcp"
	}
	if proto != "http" && proto != "https" {
		cmd += fmt.Sprintf(" client-uri %s://%s:%d", proto, s.ServerAddr(), s.Ports.Server)
	}

	output := vppProxy.Vppctl(cmd)
	Log("proxy configured: " + output)
}

func (s *VppProxySuite) ServerAddr() string {
	return s.Interfaces.Server.Host.Ip4AddressString()
}

func (s *VppProxySuite) VppProxyAddr() string {
	return s.Interfaces.Client.Ip4AddressString()
}

func (s *VppProxySuite) ClientAddr() string {
	return s.Interfaces.Client.Host.Ip4AddressString()
}

func (s *VppProxySuite) CurlRequest(targetUri string) (string, string) {
	args := fmt.Sprintf("--insecure --noproxy '*' %s", targetUri)
	body, log := RunCurlContainer(s.Containers.Curl, args)
	return body, log
}

func (s *VppProxySuite) CurlRequestViaTunnel(targetUri string, proxyUri string) (string, string) {
	args := fmt.Sprintf("--max-time %d --insecure -p -x %s %s", s.maxTimeout, proxyUri, targetUri)
	body, log := RunCurlContainer(s.Containers.Curl, args)
	return body, log
}

func (s *VppProxySuite) CurlDownloadResource(uri string) {
	args := fmt.Sprintf("-w @/tmp/write_out_download --max-time %d --insecure --noproxy '*' --remote-name --output-dir /tmp %s", s.maxTimeout, uri)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	AssertContains(writeOut, "GET response code: 200")
	AssertNotContains(log, "bytes remaining to read")
	AssertNotContains(log, "Operation timed out")
}

func (s *VppProxySuite) CurlUploadResource(uri, file string) {
	args := fmt.Sprintf("-w @/tmp/write_out_upload --max-time %d --insecure --noproxy '*' -T %s %s", s.maxTimeout, file, uri)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	AssertContains(writeOut, "PUT response code: 201")
	AssertNotContains(log, "Operation timed out")
}

func (s *VppProxySuite) CurlDownloadResourceViaTunnel(uri string, proxyUri string, extraArgs ...string) (string, string) {
	extras := ""
	if len(extraArgs) > 0 {
		extras = strings.Join(extraArgs, " ")
		extras += " "
	}
	args := fmt.Sprintf("%s-w @/tmp/write_out_download_connect --max-time %d --insecure --proxy-insecure -p -x %s --remote-name --output-dir /tmp %s", extras, s.maxTimeout, proxyUri, uri)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	if strings.Contains(extras, "proxy-http2") {
		// in case of h2 connect response code is 000 in write out
		AssertContains(log, "CONNECT tunnel established, response 200")
	} else {
		AssertContains(writeOut, "CONNECT response code: 200")
	}
	AssertContains(writeOut, "GET response code: 200")
	AssertNotContains(log, "bytes remaining to read")
	AssertNotContains(log, "Operation timed out")
	AssertNotContains(log, "Upgrade:")
	return writeOut, log
}

func (s *VppProxySuite) CurlUploadResourceViaTunnel(uri, proxyUri, file string, extraArgs ...string) (string, string) {
	extras := ""
	if len(extraArgs) > 0 {
		extras = strings.Join(extraArgs, " ")
		extras += " "
	}
	args := fmt.Sprintf("%s-w @/tmp/write_out_upload_connect --max-time %d --insecure --proxy-insecure -p -x %s -T %s %s", extras, s.maxTimeout, proxyUri, file, uri)
	writeOut, log := RunCurlContainer(s.Containers.Curl, args)
	if strings.Contains(extras, "proxy-http2") {
		// in case of h2 connect response code is 000 in write out
		AssertContains(log, "CONNECT tunnel established, response 200")
	} else {
		AssertContains(writeOut, "CONNECT response code: 200")
	}
	AssertContains(writeOut, "PUT response code: 201")
	AssertNotContains(log, "Operation timed out")
	AssertNotContains(log, "Upgrade:")
	return writeOut, log
}

func handleConn(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			break
		}
		_, err = conn.Write(buf[:n])
		if err != nil {
			break
		}
	}
}

var _ = Describe("VppProxySuite", Ordered, ContinueOnFailure, Label("VPPproxy", "Proxy"), func() {
	var s VppProxySuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range vppProxyTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("VppProxySuiteSolo", Ordered, ContinueOnFailure, Serial, Label("VPPproxy", "Proxy"), func() {
	var s VppProxySuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range vppProxySoloTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("VppProxyMWSuite", Ordered, ContinueOnFailure, Serial, Label("VPPproxy", "Proxy", "MW"), func() {
	var s VppProxySuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SkipIfNotEnoguhCpus = true
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	for filename, tests := range vppProxyMWTests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				test(&s)
			}, SpecTimeout(TestTimeout))
		}
	}
})

var _ = Describe("H2SpecProxySuite", Ordered, ContinueOnFailure, Label("HTTP", "HTTP2", "H2Spec", "H2SpecProxy", "Proxy"), func() {
	var s VppProxySuite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TeardownSuite()
	})
	AfterEach(func() {
		s.TeardownTest()
	})

	testCases := []struct {
		desc string
	}{
		{desc: "extras/2/1"},
		{desc: "extras/2/2"},
		{desc: "extras/2/3"},
		{desc: "extras/2/4"},
		{desc: "extras/2/5"},
	}

	for _, test := range testCases {
		test := test
		testName := "proxy_test.go/h2spec_" + strings.ReplaceAll(test.desc, "/", "_")
		It(testName, func(ctx SpecContext) {
			Log("[* TEST BEGIN]: " + testName)
			s.SetupNginxServer()
			s.ConfigureVppProxy("https", s.Ports.Proxy)
			path := fmt.Sprintf("%s:%d", s.ServerAddr(), s.Ports.Server)
			conf := &config.Config{
				Host:         s.VppProxyAddr(),
				Port:         int(s.Ports.Proxy),
				Path:         path,
				Timeout:      time.Second * time.Duration(s.maxTimeout),
				MaxHeaderLen: 4096,
				TLS:          true,
				Insecure:     true,
				Sections:     []string{test.desc},
				Verbose:      true,
			}
			// capture h2spec output so it will be in log
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			tg := h2spec_extras.Spec()
			tg.Test(conf)

			oChan := make(chan string)
			go func() {
				var buf bytes.Buffer
				io.Copy(&buf, r)
				oChan <- buf.String()
			}()

			// restore to normal state
			w.Close()
			os.Stdout = oldStdout
			o := <-oChan
			Log(o)
			AssertEqual(0, tg.FailedCount)
		}, SpecTimeout(TestTimeout))
	}
})
