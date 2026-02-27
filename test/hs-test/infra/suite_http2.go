package hst

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"time"

	"fd.io/hs-test/h2spec_extras"
	. "github.com/onsi/ginkgo/v2"
	"github.com/summerwind/h2spec"
	"github.com/summerwind/h2spec/config"
	"github.com/summerwind/h2spec/generic"
	"github.com/summerwind/h2spec/hpack"
	"github.com/summerwind/h2spec/http2"
	"github.com/summerwind/h2spec/spec"
)

var h2Tests = map[string][]func(s *Http2Suite){}
var h2SoloTests = map[string][]func(s *Http2Suite){}
var h2MWTests = map[string][]func(s *Http2Suite){}

const (
	h2specdFromPort   int = 30000
	h2specdReportPort int = 30080
)

type Http2Suite struct {
	HstSuite
	Interfaces struct {
		Tap *NetInterface
	}
	Containers struct {
		Vpp         *Container
		Curl        *Container
		H2load      *Container
		NginxServer *Container
	}
	Ports struct {
		Port1        string
		Port1AsInt   int
		Port2        string
		H2specdAsInt int
	}
}

func RegisterH2Tests(tests ...func(s *Http2Suite)) {
	h2Tests[GetTestFilename()] = tests
}
func RegisterH2SoloTests(tests ...func(s *Http2Suite)) {
	h2SoloTests[GetTestFilename()] = tests
}
func RegisterH2MWTests(tests ...func(s *Http2Suite)) {
	h2MWTests[GetTestFilename()] = tests
}

func (s *Http2Suite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("single")
	s.Interfaces.Tap = s.GetInterfaceByName("htapvpp")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.Curl = s.GetContainerByName("curl")
	s.Containers.H2load = s.GetContainerByName("h2load")
	s.Containers.NginxServer = s.GetTransientContainerByName("nginx-server")
	s.Ports.Port1 = s.GeneratePort()
	s.Ports.Port2 = s.GeneratePort()
	var err error
	s.Ports.Port1AsInt, err = strconv.Atoi(s.Ports.Port1)
	AssertNil(err)
}

func (s *Http2Suite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.NewStanza("session").Append("enable").Append("use-app-socket-api").Close()
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()

	vpp, _ := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus, memoryConfig, sessionConfig)

	AssertNil(vpp.Start())
	AssertNil(vpp.CreateTap(s.Interfaces.Tap, false, 1), "failed to create tap interface")

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *Http2Suite) TeardownTest() {
	defer s.HstSuite.TeardownTest()
	vpp := s.Containers.Vpp.VppInstance
	if CurrentSpecReport().Failed() {
		Log(vpp.Vppctl("show session verbose 2"))
		Log(vpp.Vppctl("show error"))
		Log(vpp.Vppctl("show http stats"))
	}
}

func (s *Http2Suite) VppAddr() string {
	return s.Interfaces.Tap.Ip4AddressString()
}

func (s *Http2Suite) HostAddr() string {
	return s.Interfaces.Tap.Host.Ip4AddressString()
}

func (s *Http2Suite) CreateNginxServer() {
	AssertNil(s.Containers.NginxServer.Create())
	nginxSettings := struct {
		LogPrefix string
		Address   string
		Port      string
		PortSsl   string
		Http2     string
		Timeout   int
	}{
		LogPrefix: s.Containers.NginxServer.Name,
		Address:   s.Interfaces.Tap.Host.Ip4AddressString(),
		Port:      s.Ports.Port1,
		PortSsl:   s.Ports.Port2,
		Http2:     "on",
		Timeout:   600,
	}
	s.Containers.NginxServer.CreateConfigFromTemplate(
		"/nginx.conf",
		"./resources/nginx/nginx_server.conf",
		nginxSettings,
	)
}

var _ = Describe("Http2Suite", Ordered, ContinueOnFailure, Label("HTTP", "HTTP2"), func() {
	var s Http2Suite
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

	for filename, tests := range h2Tests {
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

var _ = Describe("Http2SoloSuite", Ordered, ContinueOnFailure, Serial, Label("HTTP", "HTTP2", "Solo"), func() {
	var s Http2Suite
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

	for filename, tests := range h2SoloTests {
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

var _ = Describe("Http2MWSuite", Ordered, ContinueOnFailure, Serial, Label("HTTP", "HTTP2", "MW"), func() {
	var s Http2Suite
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

	for filename, tests := range h2MWTests {
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

type h2specTest struct {
	desc string
}

var genericTests = []h2specTest{
	{desc: "generic/1/1"},
	{desc: "generic/2/1"},
	{desc: "generic/2/2"},
	{desc: "generic/2/3"},
	{desc: "generic/2/4"},
	{desc: "generic/2/5"},
	// TODO: message framing without content length using END_STREAM flag
	// {desc: "generic/3.1/1"},
	// {desc: "generic/3.1/2"},
	// {desc: "generic/3.1/3"},
	{desc: "generic/3.2/1"},
	{desc: "generic/3.2/2"},
	{desc: "generic/3.2/3"},
	// generic/3.3/* PRIORITY is deprecated
	// TODO: message framing without content length using END_STREAM flag
	// {desc: "generic/3.4/1"},
	{desc: "generic/3.5/1"},
	{desc: "generic/3.7/1"},
	{desc: "generic/3.8/1"},
	{desc: "generic/3.9/1"},
	{desc: "generic/3.9/2"},
	// TODO: CONTINUATION
	//{desc: "generic/3.10/1"},
	//{desc: "generic/3.10/2"},
	{desc: "generic/4/1"},
	// HEAD method not supported
	// {desc: "generic/4/2"},
	// TODO: message framing without content length using END_STREAM flag
	// {desc: "generic/4/3"},
	// message framing using trailer section not supported
	// {desc: "generic/4/4"},
	{desc: "generic/5/1"},
	{desc: "generic/5/2"},
	{desc: "generic/5/3"},
	{desc: "generic/5/4"},
	{desc: "generic/5/5"},
	{desc: "generic/5/6"},
	{desc: "generic/5/7"},
	{desc: "generic/5/8"},
	{desc: "generic/5/9"},
	{desc: "generic/5/10"},
	{desc: "generic/5/11"},
	{desc: "generic/5/12"},
	{desc: "generic/5/13"},
	{desc: "generic/5/14"},
	{desc: "generic/5/15"},
}

var hpackTests = []h2specTest{
	{desc: "hpack/2.3.3/1"},
	{desc: "hpack/4.2/1"},
	{desc: "hpack/5.2/1"},
	{desc: "hpack/5.2/2"},
	{desc: "hpack/5.2/3"},
	{desc: "hpack/6.1/1"},
	{desc: "hpack/6.3/1"},
}

var http2Tests = []h2specTest{
	{desc: "http2/3.5/1"},
	{desc: "http2/3.5/2"},
	{desc: "http2/4.1/1"},
	{desc: "http2/4.1/2"},
	{desc: "http2/4.1/3"},
	// TODO: message framing without content length using END_STREAM flag
	// {desc: "http2/4.2/1"},
	{desc: "http2/4.2/2"},
	{desc: "http2/4.2/3"},
	{desc: "http2/4.3/1"},
	{desc: "http2/4.3/2"},
	{desc: "http2/4.3/3"},
	{desc: "http2/5.1.1/1"},
	{desc: "http2/5.1.1/2"},
	{desc: "http2/5.1.2/1"},
	{desc: "http2/5.1/1"},
	{desc: "http2/5.1/2"},
	{desc: "http2/5.1/3"},
	{desc: "http2/5.1/4"},
	{desc: "http2/5.1/5"},
	{desc: "http2/5.1/6"},
	{desc: "http2/5.1/7"},
	{desc: "http2/5.1/8"},
	{desc: "http2/5.1/9"},
	{desc: "http2/5.1/10"},
	{desc: "http2/5.1/11"},
	{desc: "http2/5.1/12"},
	{desc: "http2/5.1/13"},
	// http2/5.3.1/* PRIORITY is deprecated
	{desc: "http2/5.4.1/1"},
	{desc: "http2/5.4.1/2"},
	{desc: "http2/5.5/1"},
	{desc: "http2/5.5/2"},
	{desc: "http2/6.1/1"},
	{desc: "http2/6.1/2"},
	{desc: "http2/6.1/3"},
	{desc: "http2/6.2/1"},
	{desc: "http2/6.2/2"},
	{desc: "http2/6.2/3"},
	{desc: "http2/6.2/4"},
	// http2/6.3/* PRIORITY is deprecated
	{desc: "http2/6.4/1"},
	{desc: "http2/6.4/2"},
	{desc: "http2/6.4/3"},
	{desc: "http2/6.5.2/1"},
	{desc: "http2/6.5.2/2"},
	{desc: "http2/6.5.2/3"},
	{desc: "http2/6.5.2/4"},
	{desc: "http2/6.5.2/5"},
	{desc: "http2/6.5.3/1"},
	{desc: "http2/6.5.3/2"},
	{desc: "http2/6.5/1"},
	{desc: "http2/6.5/2"},
	{desc: "http2/6.5/3"},
	{desc: "http2/6.7/1"},
	{desc: "http2/6.7/2"},
	{desc: "http2/6.7/3"},
	{desc: "http2/6.7/4"},
	{desc: "http2/6.8/1"},
	{desc: "http2/6.9.1/1"},
	{desc: "http2/6.9.1/2"},
	// TODO: message framing without content length using END_STREAM flag
	// {desc: "http2/6.9.1/3"},
	{desc: "http2/6.9.2/1"},
	{desc: "http2/6.9.2/2"},
	{desc: "http2/6.9.2/3"},
	{desc: "http2/6.9/1"},
	// TODO: message framing without content length using END_STREAM flag
	// {desc: "http2/6.9/2"},
	{desc: "http2/6.9/3"},
	{desc: "http2/6.10/1"},
	{desc: "http2/6.10/2"},
	{desc: "http2/6.10/3"},
	{desc: "http2/6.10/4"},
	{desc: "http2/6.10/5"},
	{desc: "http2/6.10/6"},
	{desc: "http2/7/1"},
	// TODO: message framing without content length using END_STREAM flag
	// {desc: "http2/7/2"},
	{desc: "http2/8.1.2.1/1"},
	{desc: "http2/8.1.2.1/2"},
	{desc: "http2/8.1.2.1/3"},
	{desc: "http2/8.1.2.1/4"},
	{desc: "http2/8.1.2.2/1"},
	{desc: "http2/8.1.2.2/2"},
	{desc: "http2/8.1.2.3/1"},
	{desc: "http2/8.1.2.3/2"},
	{desc: "http2/8.1.2.3/3"},
	{desc: "http2/8.1.2.3/4"},
	{desc: "http2/8.1.2.3/5"},
	{desc: "http2/8.1.2.3/6"},
	{desc: "http2/8.1.2.3/7"},
	{desc: "http2/8.1.2.6/1"},
	{desc: "http2/8.1.2.6/2"},
	{desc: "http2/8.1.2/1"},
	{desc: "http2/8.1/1"},
	{desc: "http2/8.2/1"},
}

var extrasTests = []h2specTest{
	{desc: "extras/1/1"},
	{desc: "extras/1/2"},
	{desc: "extras/4/1"},
}

const (
	GenericTestGroup int = 1
	HpackTestGroup   int = 2
	Http2TestGroup   int = 3
	ExtrasTestGroup  int = 4
)

var specs = []struct {
	tg    int
	tests []h2specTest
}{
	{GenericTestGroup, genericTests},
	{HpackTestGroup, hpackTests},
	{Http2TestGroup, http2Tests},
	{ExtrasTestGroup, extrasTests},
}

var _ = Describe("H2SpecSuite", Ordered, ContinueOnFailure, Label("HTTP", "HTTP2", "H2Spec"), func() {
	var s Http2Suite
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

	for _, sp := range specs {
		for _, test := range sp.tests {
			test := test
			testName := "http2_test.go/h2spec_" + strings.ReplaceAll(test.desc, "/", "_")
			It(testName, func(ctx SpecContext) {
				Log("[* TEST BEGIN]: " + testName)
				vpp := s.Containers.Vpp.VppInstance
				serverAddress := s.VppAddr()
				Log(vpp.Vppctl("http static server uri tls://" + serverAddress + "/" + s.Ports.Port1 + " url-handlers debug 2 fifo-size 16k"))
				Log(vpp.Vppctl("test-url-handler enable"))
				conf := &config.Config{
					Host:         serverAddress,
					Port:         s.Ports.Port1AsInt,
					Path:         "/test1",
					Timeout:      time.Second * 5,
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

				var tg *spec.TestGroup
				switch sp.tg {
				case GenericTestGroup:
					tg = generic.Spec()
				case HpackTestGroup:
					tg = hpack.Spec()
				case Http2TestGroup:
					tg = http2.Spec()
				case ExtrasTestGroup:
					tg = h2spec_extras.Spec()
				}
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
	}
})

func h2specdVerifyResult(s Http2Suite, nExecuted int) bool {
	client := NewHttpClient(time.Second*5, false)
	uri := fmt.Sprintf("http://%s:%d/report", s.HostAddr(), h2specdReportPort)
	req, err := http.NewRequest("GET", uri, nil)
	AssertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	AssertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	report, err := io.ReadAll(resp.Body)
	AssertContains(string(report), "0 failed")
	AssertNil(err)
	expected := fmt.Sprintf("<div>%d tests, %d passed", nExecuted, nExecuted)
	return strings.Contains(string(report), expected)
}

var _ = Describe("H2SpecClientSuite", Ordered, Serial, Label("HTTP", "HTTP2", "H2Spec", "H2SpecClient"), func() {
	var s Http2Suite
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
		desc            string
		portOffset      int
		clientExtraArgs string
	}{
		// some tests are testing error conditions after request is completed so in this run http client with repeat
		{desc: "client/1/1", portOffset: 0},
		{desc: "client/4.1/1", portOffset: 1},
		{desc: "client/4.1/2", portOffset: 2},
		{desc: "client/4.1/3", portOffset: 3},
		// TODO: message framing without content length using END_STREAM flag
		//{desc: "client/4.2/1", portOffset: 4},
		//{desc: "client/4.2/2", portOffset: 5},
		{desc: "client/4.2/3", portOffset: 6},
		{desc: "client/4.3/1", portOffset: 7},
		{desc: "client/5.1/1", portOffset: 8},
		{desc: "client/5.1/2", portOffset: 9},
		{desc: "client/5.1/3", portOffset: 10},
		{desc: "client/5.1/4", portOffset: 11},
		// TODO: message framing without content length using END_STREAM flag
		//{desc: "client/5.1/5", portOffset: 12},
		//{desc: "client/5.1/6", portOffset: 13},
		//{desc: "client/5.1/7", portOffset: 14},
		{desc: "client/5.1/8", portOffset: 15},
		{desc: "client/5.1/9", portOffset: 16, clientExtraArgs: "repeat 2 "},
		{desc: "client/5.1/10", portOffset: 17, clientExtraArgs: "repeat 2 "},
		{desc: "client/5.1.1/1", portOffset: 18},
		{desc: "client/5.4.1/1", portOffset: 19},
		{desc: "client/5.4.1/2", portOffset: 20},
		{desc: "client/5.5/1", portOffset: 21},
		{desc: "client/6.1/1", portOffset: 22},
		{desc: "client/6.1/2", portOffset: 23},
		{desc: "client/6.1/3", portOffset: 24},
		{desc: "client/6.2/1", portOffset: 25},
		{desc: "client/6.2/2", portOffset: 26},
		{desc: "client/6.2/3", portOffset: 27},
		// PRIORITY is deprecated
		//{desc: "client/6.3/1", portOffset: 28},
		//{desc: "client/6.3/2", portOffset: 29},
		{desc: "client/6.4/1", portOffset: 30},
		{desc: "client/6.4/2", portOffset: 31},
		{desc: "client/6.4/3", portOffset: 32, clientExtraArgs: "repeat 2 "},
		{desc: "client/6.5/1", portOffset: 33},
		{desc: "client/6.5/2", portOffset: 34},
		{desc: "client/6.5/3", portOffset: 35},
		{desc: "client/6.5.2/1", portOffset: 36},
		{desc: "client/6.5.2/2", portOffset: 37},
		{desc: "client/6.5.2/3", portOffset: 38},
		{desc: "client/6.5.2/4", portOffset: 39},
		{desc: "client/6.5.3/1", portOffset: 40},
		{desc: "client/6.7/1", portOffset: 41},
		{desc: "client/6.7/2", portOffset: 42},
		{desc: "client/6.7/3", portOffset: 43},
		{desc: "client/6.7/4", portOffset: 44},
		{desc: "client/6.8/1", portOffset: 45},
		{desc: "client/6.9/1", portOffset: 46},
		// TODO: message framing without content length using END_STREAM flag
		//{desc: "client/6.9/2", portOffset: 47},
		{desc: "client/6.9/3", portOffset: 48},
		{desc: "client/6.9.1/1", portOffset: 49},
		// TODO: message framing without content length using END_STREAM flag
		//{desc: "client/6.9.1/2", portOffset: 50},
		{desc: "client/6.10/1", portOffset: 51, clientExtraArgs: "repeat 2 "},
		{desc: "client/6.10/2", portOffset: 52},
		{desc: "client/6.10/3", portOffset: 53},
		{desc: "client/6.10/4", portOffset: 54, clientExtraArgs: "repeat 2 "},
		{desc: "client/6.10/5", portOffset: 55, clientExtraArgs: "repeat 2 "},
		{desc: "client/6.10/6", portOffset: 56},
	}

	nExecuted := 0
	for _, test := range testCases {
		test := test
		testName := "http2_test.go/h2spec_" + strings.ReplaceAll(test.desc, "/", "_")
		It(testName, func(ctx SpecContext) {
			Log("[* TEST BEGIN]: " + testName)
			nExecuted++
			serverAddress := s.HostAddr()
			wd, _ := os.Getwd()
			conf := &config.Config{
				Host:         serverAddress,
				Port:         h2specdReportPort,
				Timeout:      20 * time.Second,
				MaxHeaderLen: 4096,
				TLS:          true,
				CertFile:     wd + "/resources/cert/localhost.crt",
				CertKeyFile:  wd + "/resources/cert/localhost.key",
				Verbose:      true,
				DryRun:       false,
				Exec:         "",
				FromPort:     h2specdFromPort,
				Sections:     []string{},
			}
			//capture h2spec output so it will be in log
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			go h2spec.RunClientSpec(conf)

			cmd := fmt.Sprintf("http client timeout 5 %s uri https://%s:%d/", test.clientExtraArgs, serverAddress, h2specdFromPort+test.portOffset)
			Log(s.Containers.Vpp.VppInstance.Vppctl(cmd))

			oChan := make(chan string)
			go func() {
				var buf bytes.Buffer
				io.Copy(&buf, r)
				oChan <- buf.String()
			}()

			//restore to normal state
			w.Close()
			os.Stdout = oldStdout
			o := <-oChan
			Log(o)

			//read report
			for nTries := 0; nTries < 30; nTries++ {
				if h2specdVerifyResult(s, nExecuted) {
					break
				}
				time.Sleep(1 * time.Second)
			}

		}, SpecTimeout(TestTimeout))
	}
})
