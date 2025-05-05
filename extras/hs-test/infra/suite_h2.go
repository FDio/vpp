package hst

import (
	"bytes"
	"io"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/summerwind/h2spec/spec"

	"fd.io/hs-test/h2spec_extras"
	. "github.com/onsi/ginkgo/v2"
	"github.com/summerwind/h2spec/config"
	"github.com/summerwind/h2spec/generic"
	"github.com/summerwind/h2spec/hpack"
	"github.com/summerwind/h2spec/http2"
)

var h2Tests = map[string][]func(s *H2Suite){}

type H2Suite struct {
	HstSuite
	Interfaces struct {
		Tap *NetInterface
	}
	Containers struct {
		Vpp    *Container
		Curl   *Container
		H2load *Container
	}
}

func RegisterH2Tests(tests ...func(s *H2Suite)) {
	h2Tests[getTestFilename()] = tests
}

func (s *H2Suite) SetupSuite() {
	s.HstSuite.SetupSuite()
	s.LoadNetworkTopology("tap")
	s.LoadContainerTopology("single")
	s.Interfaces.Tap = s.GetInterfaceByName("htaphost")
	s.Containers.Vpp = s.GetContainerByName("vpp")
	s.Containers.Curl = s.GetContainerByName("curl")
	s.Containers.H2load = s.GetContainerByName("h2load")
}

func (s *H2Suite) SetupTest() {
	s.HstSuite.SetupTest()

	// Setup test conditions
	var sessionConfig Stanza
	sessionConfig.NewStanza("session").Append("enable").Append("use-app-socket-api").Close()
	var memoryConfig Stanza
	memoryConfig.NewStanza("memory").Append("main-heap-size 2G").Close()

	vpp, _ := s.Containers.Vpp.newVppInstance(s.Containers.Vpp.AllocatedCpus, memoryConfig, sessionConfig)

	s.AssertNil(vpp.Start())
	s.AssertNil(vpp.CreateTap(s.Interfaces.Tap, 1, 1), "failed to create tap interface")

	if *DryRun {
		s.LogStartedContainers()
		s.Skip("Dry run mode = true")
	}
}

func (s *H2Suite) TearDownTest() {
	s.HstSuite.TearDownTest()
}

func (s *H2Suite) VppAddr() string {
	return s.Interfaces.Tap.Peer.Ip4AddressString()
}

// Marked as pending since http plugin is not build with http/2 enabled by default
var _ = Describe("Http2Suite", Ordered, ContinueOnFailure, func() {
	var s H2Suite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TearDownSuite()
	})
	AfterEach(func() {
		s.TearDownTest()
	})

	for filename, tests := range h2Tests {
		for _, test := range tests {
			test := test
			pc := reflect.ValueOf(test).Pointer()
			funcValue := runtime.FuncForPC(pc)
			testName := filename + "/" + strings.Split(funcValue.Name(), ".")[2]
			It(testName, func(ctx SpecContext) {
				s.Log(testName + ": BEGIN")
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
	// TODO: need to be tested with TLS, otherwise we consider invalid preface as bogus HTTP/1 request
	// {desc: "http2/3.5/2"},
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
	// TODO: CONTINUATION
	// {desc: "http2/5.1/4"},
	{desc: "http2/5.1/5"},
	{desc: "http2/5.1/6"},
	// TODO: CONTINUATION
	// {desc: "http2/5.1/7"},
	{desc: "http2/5.1/8"},
	{desc: "http2/5.1/9"},
	// TODO: CONTINUATION
	// {desc: "http2/5.1/10"},
	{desc: "http2/5.1/11"},
	{desc: "http2/5.1/12"},
	// TODO: CONTINUATION
	// {desc: "http2/5.1/13"},
	// http2/5.3.1/* PRIORITY is deprecated
	{desc: "http2/5.4.1/1"},
	{desc: "http2/5.4.1/2"},
	{desc: "http2/5.5/1"},
	// TODO: CONTINUATION
	// {desc: "http2/5.5/2"},
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
	// TODO: CONTINUATION
	// {desc: "http2/6.10/1"},
	// {desc: "http2/6.10/2"},
	// {desc: "http2/6.10/3"},
	// {desc: "http2/6.10/4"},
	// {desc: "http2/6.10/5"},
	// {desc: "http2/6.10/6"},
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

// Marked as pending since http plugin is not build with http/2 enabled by default
var _ = Describe("H2SpecSuite", Ordered, ContinueOnFailure, func() {
	var s H2Suite
	BeforeAll(func() {
		s.SetupSuite()
	})
	BeforeEach(func() {
		s.SetupTest()
	})
	AfterAll(func() {
		s.TearDownSuite()
	})
	AfterEach(func() {
		s.TearDownTest()
	})

	for _, sp := range specs {
		for _, test := range sp.tests {
			test := test
			testName := "http2_test.go/h2spec_" + strings.ReplaceAll(test.desc, "/", "_")
			It(testName, func(ctx SpecContext) {
				s.Log(testName + ": BEGIN")
				vpp := s.Containers.Vpp.VppInstance
				serverAddress := s.VppAddr()
				s.Log(vpp.Vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers debug 2"))
				s.Log(vpp.Vppctl("test-url-handler enable"))
				conf := &config.Config{
					Host:         serverAddress,
					Port:         80,
					Path:         "/test1",
					Timeout:      time.Second * 5,
					MaxHeaderLen: 1024,
					TLS:          false,
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
					break
				case HpackTestGroup:
					tg = hpack.Spec()
					break
				case Http2TestGroup:
					tg = http2.Spec()
					break
				case ExtrasTestGroup:
					tg = h2spec_extras.Spec()
					break
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
				s.Log(o)
				s.AssertEqual(0, tg.FailedCount)
			})
		}
	}
})
