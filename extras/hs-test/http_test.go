package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	. "github.com/onsi/ginkgo/v2"
)

func init() {
	registerNsTests(HttpTpsTest)
	registerVethTests(HttpCliTest, HttpCliConnectErrorTest)
	registerNoTopoTests(NginxHttp3Test, NginxAsServerTest,
		NginxPerfCpsTest, NginxPerfRpsTest, NginxPerfWrkTest, HeaderServerTest,
		HttpStaticMovedTest, HttpStaticNotFoundTest, HttpCliMethodNotAllowedTest,
		HttpCliBadRequestTest, HttpStaticPathTraversalTest)
	registerNoTopoSoloTests(HttpStaticPromTest)
}

const wwwRootPath = "/tmp/www_root"

func HttpTpsTest(s *NsSuite) {
	iface := s.getInterfaceByName(clientInterface)
	client_ip := iface.ip4AddressString()
	port := "8080"
	finished := make(chan error, 1)
	clientNetns := s.getNetNamespaceByName("cln")

	container := s.getContainerByName("vpp")

	// configure vpp in the container
	container.vppInstance.vppctl("http tps uri tcp://0.0.0.0/8080")

	go func() {
		defer GinkgoRecover()
		s.startWget(finished, client_ip, port, "test_file_10M", clientNetns)
	}()
	// wait for client
	err := <-finished
	s.assertNil(err, fmt.Sprint(err))
}

func HttpCliTest(s *VethsSuite) {
	serverContainer := s.getContainerByName("server-vpp")
	clientContainer := s.getContainerByName("client-vpp")

	serverVeth := s.getInterfaceByName(serverInterfaceName)

	serverContainer.vppInstance.vppctl("http cli server")

	uri := "http://" + serverVeth.ip4AddressString() + "/80"

	o := clientContainer.vppInstance.vppctl("http cli client" +
		" uri " + uri + " query /show/vlib/graph")

	s.log(o)
	s.assertContains(o, "<html>", "<html> not found in the result!")
}

func HttpCliConnectErrorTest(s *VethsSuite) {
	clientContainer := s.getContainerByName("client-vpp")

	serverVeth := s.getInterfaceByName(serverInterfaceName)

	uri := "http://" + serverVeth.ip4AddressString() + "/80"

	o := clientContainer.vppInstance.vppctl("http cli client" +
		" uri " + uri + " query /show/vlib/graph")

	s.log(o)
	s.assertContains(o, "failed to connect")
}

func NginxHttp3Test(s *NoTopoSuite) {
	s.SkipUnlessExtendedTestsBuilt()

	query := "index.html"
	nginxCont := s.getContainerByName("nginx-http3")
	s.assertNil(nginxCont.run())

	vpp := s.getContainerByName("vpp").vppInstance
	vpp.waitForApp("nginx-", 5)
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()

	defer func() { os.Remove(query) }()
	curlCont := s.getContainerByName("curl")
	args := fmt.Sprintf("curl --noproxy '*' --local-port 55444 --http3-only -k https://%s:8443/%s", serverAddress, query)
	curlCont.extraRunningArgs = args
	o, err := curlCont.combinedOutput()
	s.assertNil(err, fmt.Sprint(err))
	s.assertContains(o, "<http>", "<http> not found in the result!")
}

func HttpStaticPromTest(s *NoTopoSuite) {
	finished := make(chan error, 1)
	query := "stats.prom"
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server uri tcp://" + serverAddress + "/80 url-handlers"))
	s.log(vpp.vppctl("prom enable"))
	time.Sleep(time.Second * 5)
	go func() {
		defer GinkgoRecover()
		s.startWget(finished, serverAddress, "80", query, "")
	}()
	err := <-finished
	s.assertNil(err)
}

func HttpStaticPathTraversalTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	vpp.container.exec("mkdir -p " + wwwRootPath)
	vpp.container.exec("mkdir -p " + "/tmp/secret_folder")
	vpp.container.createFile("/tmp/secret_folder/secret_file.txt", "secret")
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/../secret_folder/secret_file.txt", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(404, resp.StatusCode)
}

func HttpStaticMovedTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	vpp.container.exec("mkdir -p " + wwwRootPath + "/tmp.aaa")
	vpp.container.createFile(wwwRootPath+"/tmp.aaa/index.html", "<http><body><p>Hello</p></body></http>")
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/tmp.aaa", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(301, resp.StatusCode)
	s.assertNotEqual("", resp.Header.Get("Location"))
}

func HttpStaticNotFoundTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	vpp.container.exec("mkdir -p " + wwwRootPath)
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	s.log(vpp.vppctl("http static server www-root " + wwwRootPath + " uri tcp://" + serverAddress + "/80 debug"))

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/notfound.html", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(404, resp.StatusCode)
}

func HttpCliMethodNotAllowedTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	client := newHttpClient()
	req, err := http.NewRequest("POST", "http://"+serverAddress+":80/test", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(405, resp.StatusCode)
	// TODO: need to be fixed in http code
	//s.assertNotEqual("", resp.Header.Get("Allow"))
}

func HttpCliBadRequestTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual(400, resp.StatusCode)
}

func HeaderServerTest(s *NoTopoSuite) {
	vpp := s.getContainerByName("vpp").vppInstance
	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()
	vpp.vppctl("http cli server")

	client := newHttpClient()
	req, err := http.NewRequest("GET", "http://"+serverAddress+":80/show/version", nil)
	s.assertNil(err, fmt.Sprint(err))
	resp, err := client.Do(req)
	s.assertNil(err, fmt.Sprint(err))
	defer resp.Body.Close()
	s.assertEqual("http_cli_server", resp.Header.Get("Server"))
}

func NginxAsServerTest(s *NoTopoSuite) {
	query := "return_ok"
	finished := make(chan error, 1)

	nginxCont := s.getContainerByName("nginx")
	s.assertNil(nginxCont.run())

	vpp := s.getContainerByName("vpp").vppInstance
	vpp.waitForApp("nginx-", 5)

	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()

	defer func() { os.Remove(query) }()
	go func() {
		defer GinkgoRecover()
		s.startWget(finished, serverAddress, "80", query, "")
	}()
	s.assertNil(<-finished)
}

func parseString(s, pattern string) string {
	temp := strings.Split(s, "\n")
	for _, item := range temp {
		if strings.Contains(item, pattern) {
			return item
		}
	}
	return ""
}

func runNginxPerf(s *NoTopoSuite, mode, ab_or_wrk string) error {
	nRequests := 1000000
	nClients := 1000

	serverAddress := s.getInterfaceByName(tapInterfaceName).peer.ip4AddressString()

	vpp := s.getContainerByName("vpp").vppInstance

	nginxCont := s.getContainerByName(singleTopoContainerNginx)
	s.assertNil(nginxCont.run())
	vpp.waitForApp("nginx-", 5)

	if ab_or_wrk == "ab" {
		abCont := s.getContainerByName("ab")
		abCont.runDetached = true
		args := fmt.Sprintf("-n %d -c %d", nRequests, nClients)
		if mode == "rps" {
			args += " -k"
		} else if mode != "cps" {
			return fmt.Errorf("invalid mode %s; expected cps/rps", mode)
		}
		// don't exit on socket receive errors
		args += " -r"
		args += " http://" + serverAddress + ":80/64B.json"
		abCont.extraRunningArgs = args
		o, err := abCont.combinedOutput()
		rps := parseString(o, "Requests per second:")
		s.log(rps)
		s.log(err)
		s.assertNil(err, "err: '%s', output: '%s'", err, o)
	} else {
		wrkCont := s.getContainerByName("wrk")
		wrkCont.runDetached = true
		args := fmt.Sprintf("-c %d -t 2 -d 30 http://%s:80/64B.json", nClients,
			serverAddress)
		wrkCont.extraRunningArgs = args
		o, err := wrkCont.combinedOutput()
		rps := parseString(o, "requests")
		s.log(rps)
		s.log(err)
		s.assertNil(err, "err: '%s', output: '%s'", err, o)
	}
	return nil
}

// unstable with multiple workers
func NginxPerfCpsTest(s *NoTopoSuite) {
	s.SkipIfMultiWorker()
	s.assertNil(runNginxPerf(s, "cps", "ab"))
}

func NginxPerfRpsTest(s *NoTopoSuite) {
	s.assertNil(runNginxPerf(s, "rps", "ab"))
}

func NginxPerfWrkTest(s *NoTopoSuite) {
	s.assertNil(runNginxPerf(s, "", "wrk"))
}
