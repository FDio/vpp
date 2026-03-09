/* SPDX-License-Identifier: Apache-2.0
 * Copyright (c) 2026 Cisco Systems, Inc.
 */

package main

import (
	"context"
	"strings"
	"sync"
	"time"

	. "fd.io/hs-test/infra"
	. "github.com/onsi/ginkgo/v2"
)

func init() {
	RegisterVethTests(EvtCollectorSinkTest)
}

// EvtCollectorSinkTest validates the end-to-end app eventing pipeline:
//
//  1. evt_collector_sink (VCL app) runs in the server-app container, connected
//     to server VPP.  It listens for incoming connections from the evt-collector.
//  2. server VPP runs the built-in echo server and the app-evt-collector, which
//     connects to the sink and pushes per-session TCP stats when sessions close.
//  3. Client VPP runs test echo client to generate traffic.
//  4. After the run the sink output must contain at least one "[tcp]" stat line.
func EvtCollectorSinkTest(s *VethsSuite) {
	s.SetupAppContainers()

	serverVpp := s.Containers.ServerVpp.VppInstance
	clientVpp := s.Containers.ClientVpp.VppInstance

	sinkAddr := s.Interfaces.Server.Ip4AddressString()
	sinkPort := s.Ports.Port1
	echoAddr := s.Interfaces.Server.Ip4AddressString()
	echoPort := s.Ports.Port2

	/* Write VCL config for the sink process (runs against server VPP) */
	srvAppCont := s.Containers.ServerApp
	srvAppCont.CreateFile("/vcl.conf", getVclConfig(s.Containers.ServerVpp))
	srvAppCont.AddEnvVar("VCL_CONFIG", "/vcl.conf")

	/* Run the sink as a background process */
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	sinkCmd := "evt_collector_sink " + sinkAddr + " " + sinkPort
	Log(sinkCmd)

	sinkOut := ""
	sinkErr := ""
	wg.Go(func() {
		defer GinkgoRecover()
		var oErr string
		sinkOut, oErr, _ = srvAppCont.ExecLineBuffered(ctx, true, sinkCmd)
		sinkErr = oErr
	})

	/* Wait for the sink to register with VPP */
	serverVpp.WaitForApp("evt-collector-sink", 5)

	/* Enable app eventing on the server VPP */
	o := serverVpp.Vppctl("app evt-collector enable")
	Log(o)

	/* Wait until the sink's session listener appears in VPP, then add the
	 * collector URI.  WaitForApp only guarantees vppcom_app_create completed;
	 * vppcom_session_listen fires shortly after.  Retry the add until the
	 * collector's session_map becomes non-zero (connection established). */
	o = serverVpp.Vppctl("app evt-collector add uri tcp://%s/%s",
		sinkAddr, sinkPort)
	Log(o)
	for range 10 {
		time.Sleep(500 * time.Millisecond)
		o = serverVpp.Vppctl("show app evt-collector")
		if strings.Contains(o, "is ready: 1") {
			break
		}
		/* Listener may not have been ready yet — retry the add */
		o = serverVpp.Vppctl("app evt-collector del uri tcp://%s/%s",
			sinkAddr, sinkPort)
		o = serverVpp.Vppctl("app evt-collector add uri tcp://%s/%s",
			sinkAddr, sinkPort)
		Log("retried add uri: " + o)
	}
	o = serverVpp.Vppctl("show app evt-collector")
	Log("evt-collector state:\n" + o)
	AssertContains(o, "is ready: 1")

	/* Start the echo server on the server VPP */
	o = serverVpp.Vppctl("test echo server uri tcp://%s/%s", echoAddr, echoPort)
	Log(o)

	/* Attach echo_server to the collector */
	o = serverVpp.Vppctl("app evt-collector app echo_server")
	Log(o)

	/* Run echo client — returns after all sessions close */
	o = clientVpp.Vppctl("test echo client nclients 2 bytes 1024"+
		" syn-timeout 10 test-timeout 30"+
		" uri tcp://%s/%s", echoAddr, echoPort)
	Log(o)
	AssertNotContains(o, "failed:")

	o = serverVpp.Vppctl("show app evt-collector")
	Log("evt-collector state after echo:\n" + o)

	/* Give stats a moment to arrive, then stop the sink */
	time.Sleep(time.Second)
	cancel()
	wg.Wait()

	Log("sink stdout:\n" + sinkOut)
	Log("sink stderr:\n" + sinkErr)

	/* Every evt-collector stat line must carry is_ip4=1 and proto=0 */
	var statLines []string
	for l := range strings.SplitSeq(sinkOut, "\n") {
		if strings.HasPrefix(l, "[tcp]") || strings.HasPrefix(l, "[udp]") {
			statLines = append(statLines, l)
		}
	}
	AssertGreaterThan(uint64(len(statLines)), uint64(0))
	for _, l := range statLines {
		AssertContains(l, "is_ip4=1")
		AssertContains(l, "proto=0")
	}
}
