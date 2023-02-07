package main

func (s *TapSuite) TestLinuxIperf() {
	clnCh := make(chan error)
	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)
	clnRes := make(chan string, 1)
	defer func() {
		stopServerCh <- struct{}{}
	}()

	go StartServerApp(srvCh, stopServerCh, nil)
	err := <-srvCh
	s.assertNil(err)
	s.log("server running")

	ipAddress := s.netInterfaces["tap0"].IP4AddressString()
	go StartClientApp(ipAddress, nil, clnCh, clnRes)
	s.log("client running")
	s.log(<-clnRes)
	err = <-clnCh
	s.assertNil(err)
	s.log("Test completed")
}
