package main

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVperfTests(TcpBbrBufferbloatTest, TcpBbrRandomLossStartupTest)
	RegisterManualVperfTests(TcpCcComparisonCubicTest, TcpCcComparisonCubicRackTest,
		TcpCcComparisonBbrTest)
}

const (
	ccCmpRunTime = 20 * time.Second
	ccCmpWarmup  = 2 * time.Second
	ccCmpSample  = 200 * time.Millisecond
	ccCmpBaseRtt = 100.0

	// Use a deterministic long-RTT tail-drop path and shape data and ACKs separately.
	// These manual tests report comparative metrics but deliberately do not rank CCs.
	ccCmpDataNsim = "set nsim poll-main-thread delay 50 ms bandwidth 50 mbps " +
		"buffer 100 ms packet-size 1500 seed 112933"
	ccCmpAckNsim = "set nsim poll-main-thread delay 50 ms bandwidth 50 mbps " +
		"buffer 20 ms packet-size 64 seed 112934"
)

type ccCmpConfig struct {
	name            string
	algo            string
	rack            bool
	runTime         time.Duration
	warmup          time.Duration
	baseRttMs       float64
	dataNsim        string
	ackNsim         string
	minGoodputMbps  float64
	maxRttP95Ms     float64
	requireNoQDrops bool
	requireLoss     bool
	requireProbeBw  bool
}

type ccCmpSamplePoint struct {
	t       float64
	sndUna  uint64
	cwnd    uint64
	flight  uint64
	rxtSegs uint64
	fr      uint64
	tr      uint64
	rttMs   float64
	queue   uint64
	queueMs float64
	bbr     string
	bbrMode uint64
}

var (
	ccCmpHeaderRE    = regexp.MustCompile(`(?m)^\[(\d+):(\d+)\]\[T\]`)
	ccCmpOutBytesRE  = regexp.MustCompile(`out segs \d+ dsegs \d+ bytes (\d+)`)
	ccCmpSndUnaRE    = regexp.MustCompile(`\bsnd_una (\d+)\b`)
	ccCmpCwndRE      = regexp.MustCompile(`\bcwnd (\d+)\b`)
	ccCmpFlightRE    = regexp.MustCompile(`flight size (\d+)`)
	ccCmpRxtSegsRE   = regexp.MustCompile(`\brxt segs (\d+)\b`)
	ccCmpFrRE        = regexp.MustCompile(`\bfr (\d+)\b`)
	ccCmpTrRE        = regexp.MustCompile(`\btr (\d+)\b`)
	ccCmpRttRE       = regexp.MustCompile(`\bsrtt ([\d.]+) us`)
	ccCmpBbrRE       = regexp.MustCompile(`\bbbr:\s*([^\r\n]+)`)
	ccCmpBbrModeRE   = regexp.MustCompile(`\bbbr:\s*state (\d+)/`)
	ccCmpNsimQueueRE = regexp.MustCompile(
		`worker \d+: queue (\d+)/\d+ service backlog ([\d.]+) ms`)
	ccCmpNsimCountersRE = regexp.MustCompile(
		`counters: packets (\d+) drops (\d+) queue-full (\d+)`)
)

func ccCmpUint(out string, re *regexp.Regexp) uint64 {
	m := re.FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	v, _ := strconv.ParseUint(m[1], 10, 64)
	return v
}

func ccCmpFloat(out string, re *regexp.Regexp) float64 {
	m := re.FindStringSubmatch(out)
	if m == nil {
		return 0
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	return v
}

func ccCmpFindDataSession(vpp *VppInstance) (string, string) {
	out := vpp.Vppctl("show session verbose 2 proto tcp")
	locs := ccCmpHeaderRE.FindAllStringSubmatchIndex(out, -1)
	var bestThread, bestIndex string
	var bestBytes uint64

	for i, loc := range locs {
		end := len(out)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := out[loc[0]:end]
		if !strings.Contains(block, "ESTABLISHED") {
			continue
		}
		bytes := ccCmpUint(block, ccCmpOutBytesRE)
		if bytes > bestBytes {
			bestBytes = bytes
			bestThread = out[loc[2]:loc[3]]
			bestIndex = out[loc[4]:loc[5]]
		}
	}
	if bestBytes < 100<<10 {
		return "", ""
	}
	return bestThread, bestIndex
}

func ccCmpParseSample(out, nsim string, elapsed time.Duration) ccCmpSamplePoint {
	sample := ccCmpSamplePoint{
		t:       elapsed.Seconds(),
		sndUna:  ccCmpUint(out, ccCmpSndUnaRE),
		cwnd:    ccCmpUint(out, ccCmpCwndRE),
		flight:  ccCmpUint(out, ccCmpFlightRE),
		rxtSegs: ccCmpUint(out, ccCmpRxtSegsRE),
		fr:      ccCmpUint(out, ccCmpFrRE),
		tr:      ccCmpUint(out, ccCmpTrRE),
		rttMs:   ccCmpFloat(out, ccCmpRttRE),
	}
	if match := ccCmpBbrRE.FindStringSubmatch(out); match != nil {
		sample.bbr = strings.TrimSpace(match[1])
		sample.bbrMode = ccCmpUint(out, ccCmpBbrModeRE)
	}
	if match := ccCmpNsimQueueRE.FindStringSubmatch(nsim); match != nil {
		sample.queue, _ = strconv.ParseUint(match[1], 10, 64)
		sample.queueMs, _ = strconv.ParseFloat(match[2], 64)
	}
	return sample
}

func ccCmpPercentile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	position := percentile * float64(len(sorted)-1)
	lower := int(math.Floor(position))
	upper := int(math.Ceil(position))
	if lower == upper {
		return sorted[lower]
	}
	weight := position - float64(lower)
	return sorted[lower]*(1-weight) + sorted[upper]*weight
}

func ccCmpMax(values []float64) float64 {
	var maximum float64
	for _, value := range values {
		maximum = max(maximum, value)
	}
	return maximum
}

func ccCmpConfigureNsim(vpp *VppInstance, intf, config string) {
	out := vpp.Vppctl(config)
	AssertNotContains(out, "invalid", "nsim configuration must be accepted")
	AssertNotContains(out, "error", "nsim configuration must be accepted")
	AssertNotContains(out, "unknown input", "nsim configuration must be accepted")
	show := vpp.Vppctl("show nsim")
	AssertNotContains(show, "not configured", "nsim must be configured before enabling it")
	AssertContains(show, "configuration", "nsim must be configured before enabling it")
	out = vpp.Vppctl("nsim output-feature enable-disable " + intf)
	AssertNotContains(out, "failed", "nsim output feature must be enabled")
}

func runTcpCcComparison(s *VperfSuite, cfg ccCmpConfig) {
	clientVpp := s.Containers.ClientVpp.VppInstance
	serverVpp := s.Containers.ServerVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString()
	runTime := cfg.runTime
	warmup := cfg.warmup
	baseRttMs := cfg.baseRttMs
	dataNsim := cfg.dataNsim
	ackNsim := cfg.ackNsim
	rackConfig := "no-rack"
	if runTime == 0 {
		runTime = ccCmpRunTime
	}
	if warmup == 0 {
		warmup = ccCmpWarmup
	}
	if baseRttMs == 0 {
		baseRttMs = ccCmpBaseRtt
	}
	if dataNsim == "" {
		dataNsim = ccCmpDataNsim
	}
	if ackNsim == "" {
		ackNsim = ccCmpAckNsim
	}
	if cfg.rack {
		rackConfig = "rack"
	}

	Log(clientVpp.Vppctl("set tcp cc-algo %s %s", cfg.algo, rackConfig))
	Log(serverVpp.Vppctl("set tcp cc-algo %s %s", cfg.algo, rackConfig))
	ccCmpConfigureNsim(clientVpp, s.Interfaces.Client.VppName(), dataNsim)
	ccCmpConfigureNsim(serverVpp, s.Interfaces.Server.VppName(), ackNsim)

	serverVpp.Vppctl("vperf server fifo-size 4m uri tcp://%s/%s", serverAddress,
		s.Ports.Port1)
	done := make(chan string, 1)
	go func() {
		done <- clientVpp.Vppctl("vperf client fifo-size 4m max-tx-chunk 4m run-time %d verbose uri tcp://%s/%s",
			int(runTime/time.Second), serverAddress, s.Ports.Port1)
	}()

	var thread, index string
	for range 50 {
		thread, index = ccCmpFindDataSession(clientVpp)
		if thread != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	AssertNotEmpty(thread, "expected an established bulk TCP session")
	AssertNotEmpty(index, "expected an established bulk TCP session index")

	initial := clientVpp.Vppctl("show session verbose 2 thread %s index %s", thread, index)
	AssertContains(initial, "algo "+cfg.algo, "bulk sender must use the selected CC algorithm")
	if cfg.rack || cfg.algo == "bbr" {
		AssertContains(initial, "rack:", "selected mode must use RACK")
	} else {
		AssertNotContains(initial, "rack:", "plain CUBIC must not use RACK")
	}

	start := time.Now()
	ticker := time.NewTicker(ccCmpSample)
	timeout := time.NewTimer(runTime + 15*time.Second)
	defer ticker.Stop()
	defer timeout.Stop()

	var samples []ccCmpSamplePoint
	var clientOut string
collect:
	for {
		select {
		case clientOut = <-done:
			break collect
		case <-ticker.C:
			out := clientVpp.Vppctl("show session verbose 2 thread %s index %s", thread, index)
			if strings.Contains(out, "ESTABLISHED") {
				nsim := clientVpp.Vppctl("show nsim verbose")
				samples = append(samples, ccCmpParseSample(out, nsim, time.Since(start)))
			}
		case <-timeout.C:
			AssertFail("vperf comparison transfer timed out")
			break collect
		}
	}
	AssertNotContains(clientOut, "failed", "vperf comparison transfer must complete")
	AssertGreaterEqualUnlessAsanBuild(len(samples), 18,
		"comparison needs enough samples for stable percentiles")

	steady := make([]ccCmpSamplePoint, 0, len(samples))
	for _, sample := range samples {
		if sample.t >= warmup.Seconds() && sample.rttMs > 0 {
			steady = append(steady, sample)
		}
	}
	AssertGreaterEqualUnlessAsanBuild(len(steady), 14,
		"comparison needs enough steady-state samples for stable percentiles")

	first := steady[0]
	last := steady[len(steady)-1]
	duration := last.t - first.t
	ackedBytes := uint64(uint32(last.sndUna) - uint32(first.sndUna))
	goodputMbps := float64(ackedBytes) * 8 / duration / 1e6
	AssertGreaterThan(goodputMbps, 0.0, "comparison transfer must make ACK progress")

	rtts := make([]float64, 0, len(steady))
	cwnds := make([]float64, 0, len(steady))
	flights := make([]float64, 0, len(steady))
	queues := make([]float64, 0, len(steady))
	for _, sample := range steady {
		rtts = append(rtts, sample.rttMs)
		cwnds = append(cwnds, float64(sample.cwnd))
		flights = append(flights, float64(sample.flight))
		queues = append(queues, sample.queueMs)
	}

	Log("TCP_CC_COMPARISON mode=%s algo=%s rack=%t samples=%d duration=%.2fs "+
		"goodput=%.2fMbit/s base_rtt=%.1fms srtt=%.2f/%.2f/%.2f/%.2fms "+
		"queue=%.2f/%.2f/%.2fms cwnd=%.0f/%.0f/%.0fB flight=%.0f/%.0f/%.0fB "+
		"rxt_segs=%d fr=%d tr=%d",
		cfg.name, cfg.algo, cfg.rack || cfg.algo == "bbr", len(steady), duration,
		goodputMbps, baseRttMs, ccCmpPercentile(rtts, 0), ccCmpPercentile(rtts, 0.5),
		ccCmpPercentile(rtts, 0.95), ccCmpMax(rtts), ccCmpPercentile(queues, 0.5),
		ccCmpPercentile(queues, 0.95), ccCmpMax(queues), ccCmpPercentile(cwnds, 0.5),
		ccCmpPercentile(cwnds, 0.95), ccCmpMax(cwnds), ccCmpPercentile(flights, 0.5),
		ccCmpPercentile(flights, 0.95), ccCmpMax(flights), last.rxtSegs, last.fr, last.tr)
	if cfg.algo == "bbr" {
		var trace strings.Builder
		for _, sample := range samples {
			if sample.bbr != "" {
				fmt.Fprintf(&trace, "t=%.2f queue=%d/%.3fms srtt=%.1fms cwnd=%d flight=%d %s\n",
					sample.t, sample.queue, sample.queueMs, sample.rttMs, sample.cwnd,
					sample.flight, sample.bbr)
			}
		}
		Log("TCP_CC_BBR_TRACE\n%s", trace.String())
	}
	clientNsim := clientVpp.Vppctl("show nsim verbose")
	if match := ccCmpNsimCountersRE.FindStringSubmatch(clientNsim); match != nil {
		packets, _ := strconv.ParseUint(match[1], 10, 64)
		drops, _ := strconv.ParseUint(match[2], 10, 64)
		queueDrops, _ := strconv.ParseUint(match[3], 10, 64)
		lossPct := 0.0
		if packets != 0 {
			lossPct = 100 * float64(drops+queueDrops) / float64(packets)
		}
		Log("TCP_CC_LOSS packets=%d modeled=%d queue_full=%d total=%.3f%%",
			packets, drops, queueDrops, lossPct)
		if cfg.requireNoQDrops {
			AssertEqual(uint64(0), queueDrops, "BBR must not fill the deep bottleneck queue")
		}
		if cfg.requireLoss {
			AssertGreaterThan(drops, uint64(0), "loss scenario must drop packets")
			AssertGreaterThan(last.rxtSegs, uint64(0),
				"loss scenario must exercise retransmission")
		}
	} else if cfg.requireNoQDrops || cfg.requireLoss {
		AssertFail("nsim queue-drop counters must be available")
	}
	if cfg.minGoodputMbps > 0 {
		AssertGreaterEqual(goodputMbps, cfg.minGoodputMbps,
			"BBR must substantially utilize the bottleneck")
	}
	if cfg.maxRttP95Ms > 0 {
		AssertLessEqual(ccCmpPercentile(rtts, 0.95), cfg.maxRttP95Ms,
			"BBR must not sustain deep-buffer RTT")
	}
	if cfg.requireProbeBw {
		reachedProbeBw := false
		for _, sample := range steady {
			reachedProbeBw = reachedProbeBw || sample.bbrMode == 1 || sample.bbrMode == 2
		}
		AssertEqual(true, reachedProbeBw,
			"BBR must exit STARTUP after delivery rate plateaus")
	}
	Log("client nsim:\n%s", clientNsim)
	Log("server nsim:\n%s", serverVpp.Vppctl("show nsim verbose"))
	Log(clientOut)
}

func TcpBbrBufferbloatTest(s *VperfSuite) {
	runTcpCcComparison(s, ccCmpConfig{
		name:            "bbr-bufferbloat",
		algo:            "bbr",
		runTime:         6 * time.Second,
		warmup:          time.Second,
		baseRttMs:       100,
		dataNsim:        "set nsim poll-main-thread delay 50 ms bandwidth 50 mbps buffer 500 ms packet-size 1500 seed 112935",
		ackNsim:         ccCmpAckNsim,
		minGoodputMbps:  40,
		maxRttP95Ms:     300,
		requireNoQDrops: true,
		requireProbeBw:  true,
	})
}

func TcpBbrRandomLossStartupTest(s *VperfSuite) {
	runTcpCcComparison(s, ccCmpConfig{
		name:            "bbr-random-loss-startup",
		algo:            "bbr",
		runTime:         5 * time.Second,
		warmup:          time.Second,
		baseRttMs:       100,
		dataNsim:        "set nsim poll-main-thread delay 50 ms bandwidth 100 mbps buffer 1000 ms packet-size 1500 drop-fraction 0.001 seed 112933",
		ackNsim:         "set nsim poll-main-thread delay 50 ms bandwidth 100 mbps buffer 20 ms packet-size 64 seed 112934",
		minGoodputMbps:  70,
		requireNoQDrops: true,
		requireLoss:     true,
		requireProbeBw:  true,
	})
}

func TcpCcComparisonCubicTest(s *VperfSuite) {
	runTcpCcComparison(s, ccCmpConfig{name: "cubic", algo: "cubic"})
}

func TcpCcComparisonCubicRackTest(s *VperfSuite) {
	runTcpCcComparison(s, ccCmpConfig{name: "cubic-rack", algo: "cubic", rack: true})
}

func TcpCcComparisonBbrTest(s *VperfSuite) {
	runTcpCcComparison(s, ccCmpConfig{name: "bbr", algo: "bbr"})
}
