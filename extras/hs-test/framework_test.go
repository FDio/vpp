package main

import (
	"io"
	"log"
	"os"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestHst(t *testing.T) {
	file, err := os.Create("summary/test_logs.log")
	if err != nil {
		Fail("Unable to create log file.")
	}
	defer file.Close()
	log.SetOutput(io.Writer(file))
	RegisterFailHandler(Fail)
	RunSpecs(t, "HST")
}
