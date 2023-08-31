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
	s.AssertNil(err)
	s.Log("server running")

	ipAddress := s.netInterfaces[tapInterfaceName].Ip4AddressString()
	go StartClientApp(ipAddress, nil, clnCh, clnRes)
	s.Log("client running")
	s.Log(<-clnRes)
	err = <-clnCh
	s.AssertNil(err)
	s.Log("Test completed")
}
