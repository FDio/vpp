package main

type NoTopoSuite struct {
	HstSuite
}

func (s *NoTopoSuite) SetupSuite() {
	s.teardownSuite = func() {}
	s.loadContainerTopology("single")
}
