package main

type NsSuite struct {
	HstSuite
}

func (s *NsSuite) SetupSuite() {
	s.teardownSuite = setupSuite(&s.Suite, "ns")
	s.loadContainerTopology("ns")
}

