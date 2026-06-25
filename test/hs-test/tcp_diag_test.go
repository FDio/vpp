package main

import (
	"regexp"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

var tcpEstablishedSessionRE = regexp.MustCompile(`(?m)^\[(\d+):(\d+)\]\[T\]\s+\S+->\S+\s+ESTABLISHED\b`)

func init() {
	RegisterVethTests(TcpConfigDiagTest, TcpListenerDiagTest, TcpSessionIndexDiagTest,
		TcpSrcAddressDiagTest, TcpNoListenerResetTraceTest, TcpEstablishedTraceTest,
		TcpOutputTraceDiagTest)
	RegisterVethStartupTests(TcpCubicStartupConfigDiagTest)
}

func waitForTcpDiagOutput(vpp *VppInstance, command string, patterns ...string) string {
	var o string

	for range 20 {
		o = vpp.Vppctl(command)
		matched := true
		for _, pattern := range patterns {
			if !strings.Contains(o, pattern) {
				matched = false
				break
			}
		}
		if matched {
			return o
		}
		time.Sleep(200 * time.Millisecond)
	}

	return o
}

func waitForTcpEstablishedSession(vpp *VppInstance) (string, string, string) {
	var o string

	for range 20 {
		o = vpp.Vppctl("show session verbose 2 proto tcp")
		match := tcpEstablishedSessionRE.FindStringSubmatch(o)
		if match != nil {
			return o, match[1], match[2]
		}
		time.Sleep(100 * time.Millisecond)
	}

	return o, "", ""
}

func TcpConfigDiagTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance

	config := serverVpp.Vppctl("show tcp config")
	Log(config)
	AssertContains(config, "tcp config")
	AssertContains(config, "max rx fifo size:")
	AssertContains(config, "congestion control algorithm:")
	AssertContains(config, "checksum offload:")

	AssertContains(serverVpp.Vppctl("set tcp csum-offload disable"), "disabled")
	AssertContains(serverVpp.Vppctl("show tcp config"), "checksum offload: disabled")
	AssertContains(serverVpp.Vppctl("set tcp csum-offload enable"), "enabled")
	AssertContains(serverVpp.Vppctl("show tcp config"), "checksum offload: enabled")
	AssertContains(serverVpp.Vppctl("set tcp mtu 9000"), "TCP default mtu: 9000")
	AssertContains(serverVpp.Vppctl("show tcp config"), "default mtu: 9000")
	AssertContains(serverVpp.Vppctl("set tcp mtu 1280"), "TCP default mtu: 1280")
	AssertContains(serverVpp.Vppctl("show tcp config"), "default mtu: 1280")
	AssertContains(serverVpp.Vppctl("set tcp mtu 1500"), "TCP default mtu: 1500")
	AssertContains(serverVpp.Vppctl("show tcp config"), "default mtu: 1500")

	punt := serverVpp.Vppctl("show tcp punt")
	Log(punt)
	AssertContains(punt, "IPv4 TCP punt:")
	AssertContains(punt, "IPv6 TCP punt:")

	serverVpp.Vppctl("clear tcp stats")
	stats := serverVpp.Vppctl("show tcp stats")
	Log(stats)
	AssertContains(stats, "Thread 0:")
}

func TcpListenerDiagTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString()

	serverVpp.Vppctl("vperf server fifo-size 64k uri tcp://%s/%s", serverAddress, s.Ports.Port1)

	listeners := serverVpp.Vppctl("show session listeners tcp")
	Log(listeners)
	AssertContains(listeners, "Listener")
	AssertContains(listeners, "vperf")
	AssertContains(listeners, s.Ports.Port1)

	listenerDetail := serverVpp.Vppctl("show session verbose 2 proto tcp state listening")
	Log(listenerDetail)
	AssertContains(listenerDetail, "LISTEN")
	AssertContains(listenerDetail, "cong_algo:")
	AssertContains(listenerDetail, "snd_mss:")
}

func TcpSessionIndexDiagTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString()

	serverVpp.Vppctl("vperf server fifo-size 64k uri tcp://%s/%s", serverAddress, s.Ports.Port1)

	done := make(chan string, 1)
	go func() {
		done <- clientVpp.Vppctl("vperf client fifo-size 64k run-time 3 verbose uri tcp://%s/%s",
			serverAddress, s.Ports.Port1)
	}()

	sessions, thread, index := waitForTcpEstablishedSession(serverVpp)
	Log(sessions)
	AssertNotEmpty(thread, "expected established TCP session thread")
	AssertNotEmpty(index, "expected established TCP session index")

	sessionDetail := serverVpp.Vppctl("show session verbose 2 thread %s index %s", thread, index)
	Log(sessionDetail)
	AssertContains(sessionDetail, "ESTABLISHED")
	AssertContains(sessionDetail, "cong:")
	AssertContains(sessionDetail, "stats:")
	AssertContains(sessionDetail, "session: state: ready")

	o := <-done
	Log(o)
	AssertNotContains(o, "failed")
}

func TcpSrcAddressDiagTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString()

	sourceAddressWithPrefix, err := s.Ip4AddrAllocator.NewIp4InterfaceAddress(
		s.Interfaces.Client.NetworkNumber)
	AssertNil(err)
	sourceAddress := strings.Split(sourceAddressWithPrefix, "/")[0]

	o := clientVpp.Vppctl("tcp src-address %s", sourceAddress)
	Log(o)
	AssertNotContains(o, "error")

	serverVpp.Vppctl("vperf server fifo-size 64k uri tcp://%s/%s", serverAddress, s.Ports.Port1)

	done := make(chan string, 1)
	go func() {
		done <- clientVpp.Vppctl("vperf client fifo-size 64k run-time 3 verbose uri tcp://%s/%s",
			serverAddress, s.Ports.Port1)
	}()

	sessions := waitForTcpDiagOutput(serverVpp, "show session verbose 2 proto tcp",
		sourceAddress, "ESTABLISHED")
	Log(sessions)
	AssertContains(sessions, "ESTABLISHED")
	AssertContains(sessions, sourceAddress)

	o = <-done
	Log(o)
	AssertNotContains(o, "failed")
}

func TcpNoListenerResetTraceTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString()

	serverVpp.Vppctl("trace add af-packet-input 10")

	o := clientVpp.Vppctl("vperf client fifo-size 64k bytes 1 echo-bytes test-bytes "+
		"verbose test-timeout 3 uri tcp://%s/%s", serverAddress, s.Ports.Port1)
	Log(o)
	AssertContains(o, "failed")

	trace := serverVpp.Vppctl("show trace")
	Log(trace)
	AssertContains(trace, "tcp4-input")
	AssertContains(trace, "tcp4-reset")
	AssertContains(trace, "RST")

	serverErrors := serverVpp.Vppctl("show error")
	clientErrors := clientVpp.Vppctl("show error")
	Log(serverErrors)
	Log(clientErrors)
	AssertContains(serverErrors, "no listener for dst port")
	AssertContains(serverErrors, "Resets sent")
	AssertContains(clientErrors, "Resets received")
}

func TcpEstablishedTraceTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString()

	serverVpp.Vppctl("trace add af-packet-input 20")

	serverVpp.Vppctl("vperf server fifo-size 64k uri tcp://%s/%s", serverAddress, s.Ports.Port1)
	o := clientVpp.Vppctl("vperf client fifo-size 64k bytes 4k echo-bytes test-bytes "+
		"verbose test-timeout 5 uri tcp://%s/%s", serverAddress, s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed")
	AssertContains(o, "4096 bytes")

	serverTrace := serverVpp.Vppctl("show trace")
	Log(serverTrace)
	AssertContains(serverTrace, "tcp4-established")
	AssertContains(serverTrace, "state ESTABLISHED")

	serverErrors := serverVpp.Vppctl("show error")
	clientErrors := clientVpp.Vppctl("show error")
	Log(serverErrors)
	Log(clientErrors)
	AssertContains(serverErrors, "tcp4-established")
	AssertContains(serverErrors, "Packets pushed into rx fifo")
	AssertContains(clientErrors, "tcp4-output")
	AssertContains(clientErrors, "Packets sent")
}

func TcpOutputTraceDiagTest(s *VethsSuite) {
	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString()

	clientVpp.Vppctl("trace add session-queue 20")

	serverVpp.Vppctl("vperf server fifo-size 64k uri tcp://%s/%s", serverAddress, s.Ports.Port1)
	o := clientVpp.Vppctl("vperf client fifo-size 64k bytes 4k echo-bytes test-bytes "+
		"verbose test-timeout 5 uri tcp://%s/%s", serverAddress, s.Ports.Port1)
	Log(o)
	AssertNotContains(o, "failed")
	AssertContains(o, "4096 bytes")

	clientTrace := clientVpp.Vppctl("show trace")
	Log(clientTrace)
	AssertContains(clientTrace, "tcp4-output")
	AssertContains(clientTrace, "state ESTABLISHED")
	AssertContains(clientTrace, "TCP:")
}

func TcpCubicStartupConfigDiagTest(s *VethsSuite) {
	var tcpConfig Stanza
	tcpConfig.NewStanza("tcp").
		Append("cc-algo cubic").
		NewStanza("cubic").
		Append("no-fast-convergence").
		Append("ssthresh 12345").
		Close().
		Close()

	Log("Generated TCP startup config:")
	Log(tcpConfig.ToString())

	s.SetupTest(tcpConfig)

	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString()

	config := serverVpp.Vppctl("show tcp config")
	Log(config)
	AssertContains(config, "congestion control algorithm: cubic")

	serverVpp.Vppctl("vperf server fifo-size 64k uri tcp://%s/%s", serverAddress, s.Ports.Port1)
	listenerDetail := serverVpp.Vppctl("show session verbose 2 proto tcp state listening")
	Log(listenerDetail)
	AssertContains(listenerDetail, "cong_algo: cubic")

	done := make(chan string, 1)
	go func() {
		done <- clientVpp.Vppctl("vperf client fifo-size 64k run-time 2 verbose uri tcp://%s/%s",
			serverAddress, s.Ports.Port1)
	}()

	sessionDetail := waitForTcpDiagOutput(serverVpp, "show session verbose 2 proto tcp", "ssthresh 12345")
	Log(sessionDetail)
	AssertContains(sessionDetail, "algo cubic")
	AssertContains(sessionDetail, "ssthresh 12345")

	o := <-done
	Log(o)
	AssertNotContains(o, "failed")
}
