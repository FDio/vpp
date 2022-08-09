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
	if err != nil {
		t.Errorf("%v", err)
		t.FailNow()
	}
	t.Log("server running")
	go StartClientApp(nil, clnCh)
	t.Log("client running")
	err = <-clnCh
	if err != nil {
		s.Failf("client", "%v", err)
	}
	t.Log("Test completed")
}
