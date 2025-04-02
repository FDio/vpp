package main

import (
	"fmt"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterNoTopoTests(Http2Test)
}

func Http2Test(s *NoTopoSuite) {
	vpp := s.Containers.Vpp.VppInstance
	serverAddress := s.VppAddr()
	vpp.Vppctl("http cli server")

	args := fmt.Sprintf("--max-time 10 --noproxy '*' --http2-prior-knowledge -k http://%s:80/show/version", serverAddress)
	s.RunCurlContainer(s.Containers.Curl, args)
}
