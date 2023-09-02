package main

func (s *TapSuite) TestLinuxIperf() {
	clnCh := make(chan error)
	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)
	clnRes := make(chan string, 1)
	defer func() {
		stopServerCh <- struct{}{}
	}()

	go s.startServerApp(srvCh, stopServerCh, nil)
	err := <-srvCh
	s.assertNil(err)
	s.log("server running")

	ipAddress := s.netInterfaces[tapInterfaceName].ip4AddressString()
	go s.startClientApp(ipAddress, nil, clnCh, clnRes)
	s.log("client running")
	s.log(<-clnRes)
	err = <-clnCh
	s.assertNil(err)
	s.log("Test completed")
}
