package main

import (
	"testing"

	"github.com/stretchr/testify/suite"
)

func TestTapSuite(t *testing.T) {
	var m TapSuite
	suite.Run(t, &m)
}

func TestNs(t *testing.T) {
	var m NsSuite
	suite.Run(t, &m)
}

func TestVeths(t *testing.T) {
	var m VethsSuite
	suite.Run(t, &m)
}

func TestNoTopo(t *testing.T) {
	var m NoTopoSuite
	suite.Run(t, &m)
}

func TestMirroring(t *testing.T) {
	var m MirroringSuite
	suite.Run(t, &m)
}
