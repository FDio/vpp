package main

import (
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var suiteTimeout time.Duration

func TestHst(t *testing.T) {
	if *isVppDebug {
		// 30 minute timeout so that the framework won't timeout while debugging
		suiteTimeout = time.Minute * 30
	} else {
		suiteTimeout = time.Minute * 5
	}
	RegisterFailHandler(Fail)
	RunSpecs(t, "HST")
}
