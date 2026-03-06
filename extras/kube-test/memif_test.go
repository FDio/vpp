package main

import (
	"context"
	"fmt"
	"time"

	. "fd.io/kube-test/infra"
)

func init() {
	RegisterMemifTests(VppMemifIperfTest)
}

func VppMemifIperfTest(s *MemifSuite) {
	annotations := &PodAnnotations{ExtraMemifPorts: "udp:6081,tcp:5000-65000", ExtraMemifSpec: `{"isl3": true}`}
	s.DeployPod(s.Pods.ClientGeneric, annotations)
	s.DeployPod(s.Pods.ServerGeneric, annotations)
	ctx, cancel := context.WithTimeout(s.MainContext, time.Minute*2)
	defer cancel()

	s.FixVersionNumber(s.Pods.ClientGeneric, s.Pods.ServerGeneric)
	_, err := s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	AssertNil(err)
	_, err = s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", VclConfIperf})
	AssertNil(err)

	s.Pods.ClientGeneric.InitMemifVpp()
	s.Pods.ServerGeneric.InitMemifVpp()

	o, err := s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", "ip route add " + s.Pods.ServerGeneric.IpAddress + "/32 dev eth8"})
	AssertNil(err, o)
	o, err = s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", "ip route add " + s.Pods.ClientGeneric.IpAddress + "/32 dev eth8"})
	AssertNil(err, o)

	iperfClientCmd := fmt.Sprintf("iperf3 -l 1460 -J -4 -b 40g -c %s",
		s.Pods.ServerGeneric.IpAddress)

	o, err = s.Pods.ServerGeneric.ExecServer(ctx, []string{"/bin/bash", "-c",
		"iperf3 -s -D --logfile /iperf_server.log"})
	Log("Sleeping for 2s")
	time.Sleep(time.Second * 2)
	AssertNil(err, o)
	o, err = s.Pods.ServerGeneric.Exec(ctx, []string{"/bin/bash", "-c", "pidof iperf3"})
	AssertNil(err, o)

	o, err = s.Pods.ClientGeneric.Exec(ctx, []string{"/bin/bash", "-c", iperfClientCmd})
	AssertNil(err, o)
	result := ParseJsonIperfOutput([]byte(o))
	LogJsonIperfOutput(result)
	AssertIperfMinTransfer(result, 1000)
}
