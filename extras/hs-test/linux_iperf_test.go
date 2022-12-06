package main

func (s *TapSuite) TestLinuxIperf() {
	t := s.T()
	clnCh := make(chan error)
	stopServerCh := make(chan struct{})
	srvCh := make(chan error, 1)
	defer func() {
		stopServerCh <- struct{}{}
	}()

	go StartServerApp(srvCh, stopServerCh, nil)
	err := <-srvCh
	s.assertNil(err)
	t.Log("server running")
	go StartClientApp(nil, clnCh)
	t.Log("client running")
	err = <-clnCh
	s.assertNil(err)
	t.Log("Test completed")
}
