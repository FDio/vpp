package hst

type TapSuite struct {
	VethsSuite
}

func (s *TapSuite) SetupSuite() {
	s.setupSuite("2peerTap", "br")
}
