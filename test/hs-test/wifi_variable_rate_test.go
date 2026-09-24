package main

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterVethTests(
		WifiVariableRateBbrTest,
		WifiVariableRateCubicExtendedTest,
		WifiVariableRateCubicRackExtendedTest,
		WifiVariableRateBbrExtendedTest,
		WifiVariableRateFixedExtendedTest,
		WifiVariableRateCycleExtendedTest,
		WifiVariableRateBatchExtendedTest,
		WifiVariableRateTailExtendedTest,
		WifiVariableRateCycleBatchExtendedTest,
		WifiVariableRateCycleTailExtendedTest,
		WifiVariableRateFastCycleExtendedTest,
		WifiVariableRatePersistentDropExtendedTest,
	)
}

const (
	// The capture's BBR bandwidth ceiling was about 445 Mbit/s. A 440/200
	// Mbit/s cycle reproduces its goodput and RTT envelope; 72.7 ms keeps the
	// nominal bottleneck queue at 4 MB.
	wvrDataFixed = "set nsim poll-main-thread delay 10 ms bandwidth 440 mbps " +
		"buffer 72.7 ms packet-size 1500 seed 270302"
	wvrDataCycleShort = wvrDataFixed +
		" rate-cycle bandwidth 200 mbps good 2 sec bad 2 sec"
	wvrDataCycleFast = wvrDataFixed +
		" rate-cycle bandwidth 200 mbps good 1 sec bad 1 sec"
	wvrDataPersistentDrop = wvrDataFixed +
		" rate-cycle bandwidth 200 mbps good 2 sec bad 30 sec"
	wvrDataCycle = wvrDataFixed +
		" rate-cycle bandwidth 200 mbps good 10 sec bad 10 sec"
	wvrAckFixed = "set nsim poll-main-thread delay 10 ms bandwidth 320 mbps " +
		"buffer 20 ms packet-size 64 seed 519007"
	wvrAckBatch = wvrAckFixed + " batch-interval 5.5 ms batch-packets 128"
	// Use the observed advancing-ACK gap quantiles as receiver service
	// opportunities. Safe cumulative ACKs coalesce at each opportunity; control,
	// loss and ECN signals are always retained. The residual 0.5 ms opportunities
	// reproduce the capture's short-gap population and 7.8 ms mean.
	wvrAckTail = wvrAckFixed + " ack-coalesce-interval 0.5 ms" +
		" batch-gap 5.5 ms probability 0.5348" +
		" batch-gap 11 ms probability 0.1245" +
		" batch-gap 16.5 ms probability 0.0344" +
		" batch-gap 27.5 ms probability 0.0140" +
		" batch-gap 89 ms probability 0.0152" +
		" batch-gap 145 ms probability 0.0070" +
		" batch-gap 253 ms probability 0.0001"
)

type wvrConfig struct {
	dataNsim string
	ackNsim  string
	cc       string
	rack     bool
	duration int
	hardened bool
}

type wvrSample struct {
	time        float64
	sndUna      uint32
	outBytes    uint64
	packets     uint64
	transmitted uint64
	pacerRate   uint64
	pacerBurst  uint64
	pacerCap    uint64
	pacerCredit float64
	srtt        float64
	cwnd        uint64
	flight      uint64
	extraAcked  uint64
	rxtBytes    uint64
	queueDelay  float64
	rateState   string
	bbr         string
}

type wvrResult struct {
	goodputMbps float64
	minRtt      float64
	medianRtt   float64
	p95Rtt      float64
	medianQueue float64
	p95Queue    float64
	maxCwnd     uint64
	maxExtra    uint64
	rxtBytes    uint64
}

var (
	wvrHeaderRe  = regexp.MustCompile(`(?m)^\[(\d+):(\d+)\]\[T\]`)
	wvrOutRe     = regexp.MustCompile(`out segs \d+ dsegs \d+ bytes (\d+)`)
	wvrUnaRe     = regexp.MustCompile(`\bsnd_una (\d+)\b`)
	wvrRttRe     = regexp.MustCompile(`\bsrtt [\d.]+ us ([\d.]+)`)
	wvrCwndRe    = regexp.MustCompile(`\bcwnd (\d+)\b`)
	wvrFlightRe  = regexp.MustCompile(`flight size (\d+)`)
	wvrExtraRe   = regexp.MustCompile(`\bextra_acked (\d+)\b`)
	wvrRxtRe     = regexp.MustCompile(`rxt segs \d+ bytes (\d+)\b`)
	wvrPacerRe   = regexp.MustCompile(`(?m)^\s*pacer: rate (\d+)\b`)
	wvrCreditRe  = regexp.MustCompile(`\bcredit ([\d.]+)\b`)
	wvrBurstRe   = regexp.MustCompile(`\bmin-burst \d+ burst (\d+)\b`)
	wvrCapRe     = regexp.MustCompile(`\bcap (\d+)\b`)
	wvrBbrRe     = regexp.MustCompile(`(?m)^\s*bbr:\s+(.+)$`)
	wvrRateRe    = regexp.MustCompile(`rate service tail:.*\((good|bad),`)
	wvrQueueRe   = regexp.MustCompile(`service backlog ([\d.]+) ms`)
	wvrPacketsRe = regexp.MustCompile(`counters: packets (\d+)\b`)
	wvrTxRe      = regexp.MustCompile(`\btransmitted (\d+)\b`)
	wvrTransRe   = regexp.MustCompile(`(?m)^\s+rate service tail:.*\((?:good|bad), (\d+) tracked transitions\b`)
	wvrXferRe    = regexp.MustCompile(`(\d+) bytes .* in ([\d.]+) seconds`)
)

func wvrUint(text string, re *regexp.Regexp) uint64 {
	match := re.FindStringSubmatch(text)
	if match == nil {
		return 0
	}
	value, _ := strconv.ParseUint(match[1], 10, 64)
	return value
}

func wvrFloat(text string, re *regexp.Regexp) float64 {
	match := re.FindStringSubmatch(text)
	if match == nil {
		return 0
	}
	value, _ := strconv.ParseFloat(match[1], 64)
	return value
}

func wvrFindDataSession(vpp *VppInstance) (string, string) {
	output := vpp.Vppctl("show session verbose 2 proto tcp")
	locations := wvrHeaderRe.FindAllStringSubmatchIndex(output, -1)
	var bestThread, bestIndex string
	var bestBytes uint64
	for i, location := range locations {
		end := len(output)
		if i+1 < len(locations) {
			end = locations[i+1][0]
		}
		block := output[location[0]:end]
		if !strings.Contains(block, "ESTABLISHED") {
			continue
		}
		bytes := wvrUint(block, wvrOutRe)
		if bytes > bestBytes {
			bestBytes = bytes
			bestThread = output[location[2]:location[3]]
			bestIndex = output[location[4]:location[5]]
		}
	}
	if bestBytes < 100<<10 {
		return "", ""
	}
	return bestThread, bestIndex
}

func wvrPercentile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sort.Float64s(values)
	index := int(percentile * float64(len(values)-1))
	return values[index]
}

func wvrExtendedOnly(s *VethsSuite) {
	if os.Getenv("HST_EXTENDED_WIFI") != "1" {
		s.Skip("set HST_EXTENDED_WIFI=1 to run the extended Wi-Fi matrix")
	}
}

func wvrRun(s *VethsSuite, config wvrConfig) wvrResult {
	client := s.Containers.ClientVpp.VppInstance
	server := s.Containers.ServerVpp.VppInstance
	serverAddress := s.Interfaces.Server.Ip4AddressString()

	Log(client.Vppctl("set tcp mtu 1480"))
	Log(server.Vppctl("set tcp mtu 1480"))
	if config.rack {
		Log(client.Vppctl("set tcp rack"))
		Log(server.Vppctl("set tcp rack"))
	}
	Log(client.Vppctl("set tcp cc-algo " + config.cc))
	Log(server.Vppctl("set tcp cc-algo " + config.cc))

	clientSet := client.Vppctl(config.dataNsim)
	serverSet := server.Vppctl(config.ackNsim)
	AssertNotContains(clientSet, "error")
	AssertNotContains(clientSet, "invalid")
	AssertNotContains(serverSet, "error")
	AssertNotContains(serverSet, "invalid")
	Log(client.Vppctl("nsim output-feature enable-disable " + s.Interfaces.Client.VppName()))
	Log(server.Vppctl("nsim output-feature enable-disable " + s.Interfaces.Server.VppName()))

	dataShow := client.Vppctl("show nsim verbose")
	ackShow := server.Vppctl("show nsim verbose")
	AssertNotContains(dataShow, "nsim not enabled")
	AssertNotContains(ackShow, "nsim not enabled")
	AssertContains(dataShow, "peaks:")
	if strings.Contains(config.dataNsim, "rate-cycle") {
		AssertContains(dataShow, "rate model: cycle:")
		AssertContains(dataShow, "rate service starts:")
	}
	if strings.Contains(config.ackNsim, "batch-interval") {
		AssertContains(ackShow, "batch interval: 5.5 ms")
	}
	if strings.Contains(config.ackNsim, "ack-coalesce-interval") {
		AssertContains(ackShow, "ACK coalescing interval:")
	}
	if strings.Contains(config.ackNsim, "batch-packets") {
		AssertContains(ackShow, "batch packet budget: 128")
	}
	if strings.Contains(config.ackNsim, "batch-gap") {
		AssertContains(ackShow, "batch gap distribution:")
		AssertContains(ackShow, "batch gap samples:")
	}

	server.Vppctl("vperf server fifo-size 4m uri tcp://%s/%s", serverAddress, s.Ports.Port1)
	done := make(chan string, 1)
	start := time.Now()
	go func() {
		done <- client.Vppctl(
			"vperf client fifo-size 4m run-time %d verbose uri tcp://%s/%s",
			config.duration, serverAddress, s.Ports.Port1)
	}()

	var thread, index string
	for range 50 {
		thread, index = wvrFindDataSession(client)
		if thread != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	AssertNotEmpty(thread, "expected a bulk TCP sender session")
	AssertNotEmpty(index, "expected a bulk TCP sender session index")

	initial := client.Vppctl("show session verbose 2 thread %s index %s", thread, index)
	AssertContains(initial, "algo "+config.cc)
	AssertContains(initial, "snd_mss 1428")
	if config.rack || config.cc == "bbr" {
		AssertContains(initial, "RACK")
	}
	if config.cc == "bbr" {
		for _, field := range []string{
			"bw_hi", "bw_lo", "latest", "bdp", "extra_acked", "ack_epoch",
			"offload", "target", "gains",
		} {
			AssertContains(initial, field, "BBR diagnostics must expose "+field)
		}
	}

	var samples []wvrSample
	ticker := time.NewTicker(250 * time.Millisecond)
	timeout := time.NewTimer(time.Duration(config.duration+15) * time.Second)
	var clientOutput string
runLoop:
	for {
		select {
		case clientOutput = <-done:
			break runLoop
		case <-ticker.C:
			session := client.Vppctl("show session verbose 2 thread %s index %s", thread, index)
			if !strings.Contains(session, "ESTABLISHED") {
				continue
			}
			rate := client.Vppctl("show nsim verbose")
			rateState := "fixed"
			if matches := wvrRateRe.FindAllStringSubmatch(rate, -1); len(matches) > 0 {
				rateState = matches[len(matches)-1][1]
			}
			bbr := ""
			if match := wvrBbrRe.FindStringSubmatch(session); match != nil {
				bbr = match[1]
			}
			samples = append(samples, wvrSample{
				time:        time.Since(start).Seconds(),
				sndUna:      uint32(wvrUint(session, wvrUnaRe)),
				outBytes:    wvrUint(session, wvrOutRe),
				packets:     wvrUint(rate, wvrPacketsRe),
				transmitted: wvrUint(rate, wvrTxRe),
				pacerRate:   wvrUint(session, wvrPacerRe),
				pacerBurst:  wvrUint(session, wvrBurstRe),
				pacerCap:    wvrUint(session, wvrCapRe),
				pacerCredit: wvrFloat(session, wvrCreditRe),
				srtt:        wvrFloat(session, wvrRttRe),
				cwnd:        wvrUint(session, wvrCwndRe),
				flight:      wvrUint(session, wvrFlightRe),
				extraAcked:  wvrUint(session, wvrExtraRe),
				rxtBytes:    wvrUint(session, wvrRxtRe),
				queueDelay:  wvrFloat(rate, wvrQueueRe),
				rateState:   rateState,
				bbr:         bbr,
			})
		case <-timeout.C:
			AssertNil(fmt.Errorf("Wi-Fi variable-rate transfer timed out"))
			break runLoop
		}
	}
	ticker.Stop()
	timeout.Stop()
	AssertNotContains(clientOutput, "failed")
	AssertNotEmpty(wvrXferRe.FindString(clientOutput), "vperf transfer must complete")
	AssertGreaterThan(len(samples), 4, "expected periodic TCP samples")

	var acknowledged uint64
	var previous uint32
	var havePrevious bool
	var rtts []float64
	var queueDelays []float64
	var sawGood, sawBad bool
	var result wvrResult
	for sampleIndex, sample := range samples {
		if havePrevious {
			delta := uint32(sample.sndUna - previous)
			// Sampling is frequent enough that valid progress is always below
			// 2 GiB. Accumulating modulo deltas handles any number of wraps.
			if delta < 1<<31 {
				acknowledged += uint64(delta)
			}
		}
		previous = sample.sndUna
		havePrevious = true
		if sample.srtt > 0 {
			rtts = append(rtts, sample.srtt)
		}
		queueDelays = append(queueDelays, sample.queueDelay)
		result.maxCwnd = max(result.maxCwnd, sample.cwnd)
		result.maxExtra = max(result.maxExtra, sample.extraAcked)
		result.rxtBytes = max(result.rxtBytes, sample.rxtBytes)
		sawGood = sawGood || sample.rateState == "good"
		sawBad = sawBad || sample.rateState == "bad"
		if config.cc == "bbr" {
			maxGrant := min(sample.pacerBurst+uint64(sample.pacerCredit), sample.pacerCap)
			Log("wifi-variable-rate t=%.2f rate=%s queue=%.1fms cwnd=%d flight=%d rtt=%.1f "+
				"pacer=%.1fMbit/s grant<=%dB %s",
				sample.time, sample.rateState, sample.queueDelay, sample.cwnd,
				sample.flight, sample.srtt, float64(sample.pacerRate)*8/1e6, maxGrant,
				sample.bbr)
			if sampleIndex > 0 {
				prior := samples[sampleIndex-1]
				interval := sample.time - prior.time
				if interval > 0 && sample.outBytes >= prior.outBytes && sample.packets >= prior.packets &&
					sample.transmitted >= prior.transmitted {
					tcpRate := float64(sample.outBytes-prior.outBytes) * 8 / interval / 1e6
					arrivalRate := float64(sample.packets-prior.packets) * 1500 * 8 /
						interval / 1e6
					departureRate := float64(sample.transmitted-prior.transmitted) * 1500 * 8 /
						interval / 1e6
					Log("wifi-variable-rate interval %.3fs pacer-now=%.1fMbit/s tcp-out=%.1fMbit/s "+
						"nsim-in/out=%.1f/%.1fMbit/s queue-delta=%.1fms",
						interval, float64(sample.pacerRate)*8/1e6, tcpRate, arrivalRate,
						departureRate, sample.queueDelay-prior.queueDelay)
				}
			}
		}
	}
	if len(samples) > 1 {
		elapsed := samples[len(samples)-1].time - samples[0].time
		result.goodputMbps = float64(acknowledged) * 8 / elapsed / 1e6
	}
	result.minRtt = wvrPercentile(append([]float64(nil), rtts...), 0)
	result.medianRtt = wvrPercentile(append([]float64(nil), rtts...), 0.5)
	result.p95Rtt = wvrPercentile(append([]float64(nil), rtts...), 0.95)
	result.medianQueue = wvrPercentile(append([]float64(nil), queueDelays...), 0.5)
	result.p95Queue = wvrPercentile(append([]float64(nil), queueDelays...), 0.95)
	if len(samples) > 0 {
		final := client.Vppctl("show session verbose 2 thread %s index %s", thread, index)
		result.rxtBytes = max(result.rxtBytes, wvrUint(final, wvrRxtRe))
	}

	dataShow = client.Vppctl("show nsim verbose")
	ackShow = server.Vppctl("show nsim verbose")
	Log("wifi-variable-rate data nsim:\n%s", dataShow)
	Log("wifi-variable-rate ACK nsim:\n%s", ackShow)
	if strings.Contains(config.dataNsim, "rate-cycle") {
		AssertEqual(true, sawGood && sawBad, "deterministic rate cycle must visit both states")
		transitions := wvrUint(dataShow, wvrTransRe)
		AssertGreaterThan(transitions, uint64(0), "worker rate state must advance")
	}
	if strings.Contains(config.ackNsim, "batch-interval") ||
		strings.Contains(config.ackNsim, "ack-coalesce-interval") {
		AssertNotContains(ackShow, "batching: delayed 0")
		AssertNotContains(ackShow, "batches 0")
	}
	if strings.Contains(config.ackNsim, "ack-coalesce-interval") {
		AssertNotContains(ackShow, "ACK coalescing: candidates 0")
		AssertNotContains(ackShow, "coalesced 0")
	}
	if strings.Contains(config.ackNsim, "batch-gap") {
		AssertNotContains(ackShow, "extended 0")
	}

	Log("wifi-variable-rate result: goodput %.1f Mbit/s configured base RTT 20.0 ms "+
		"load RTT min/median/p95 %.1f/%.1f/%.1f ms forward queue median/p95 %.1f/%.1f ms "+
		"cwnd %d extra_acked %d retransmitted %d",
		result.goodputMbps, result.minRtt, result.medianRtt, result.p95Rtt,
		result.medianQueue, result.p95Queue, result.maxCwnd, result.maxExtra,
		result.rxtBytes)

	if config.hardened {
		AssertGreaterEqual(result.minRtt, 18.0, "minimum RTT outside calibration")
		AssertLessEqual(result.minRtt, 30.0, "minimum RTT outside calibration")
		AssertGreaterEqual(result.goodputMbps, 180.0, "goodput below regression limit")
		AssertLessEqual(result.goodputMbps, 300.0, "goodput outside calibration")
		AssertLessEqual(result.medianRtt, 80.0, "median RTT outside calibration")
		AssertLessEqual(result.p95Rtt, 160.0, "p95 RTT above regression limit")
		AssertLessEqual(result.maxCwnd, uint64(4_250_000), "cwnd above regression limit")
		AssertLessEqual(result.rxtBytes, uint64(2_200_000),
			"retransmissions above regression limit")
	}
	return result
}

func WifiVariableRateBbrTest(s *VethsSuite) {
	result := wvrRun(s, wvrConfig{
		dataNsim: wvrDataCycleShort,
		ackNsim:  wvrAckTail,
		cc:       "bbr",
		duration: 12,
	})
	AssertGreaterEqual(result.goodputMbps, 235.0,
		"BBR must recover during two-second high-rate intervals")
}

func WifiVariableRateCubicExtendedTest(s *VethsSuite) {
	wvrExtendedOnly(s)
	wvrRun(s, wvrConfig{wvrDataCycle, wvrAckTail, "cubic", false, 80, false})
}

func WifiVariableRateCubicRackExtendedTest(s *VethsSuite) {
	wvrExtendedOnly(s)
	wvrRun(s, wvrConfig{wvrDataCycle, wvrAckTail, "cubic", true, 80, false})
}

func WifiVariableRateBbrExtendedTest(s *VethsSuite) {
	wvrExtendedOnly(s)
	wvrRun(s, wvrConfig{wvrDataCycle, wvrAckTail, "bbr", true, 80, true})
}

// The cases below are ordered ablations. Bloat in the fixed case points
// to the base BBR/pacer path; excess PROBE_BW_DOWN rate in the cycle case to
// stale bandwidth; and growth from batched service opportunities.
func WifiVariableRateFixedExtendedTest(s *VethsSuite) {
	wvrExtendedOnly(s)
	wvrRun(s, wvrConfig{wvrDataFixed, wvrAckFixed, "bbr", true, 20, false})
}

func WifiVariableRateCycleExtendedTest(s *VethsSuite) {
	wvrExtendedOnly(s)
	wvrRun(s, wvrConfig{wvrDataCycle, wvrAckFixed, "bbr", true, 20, false})
}

func WifiVariableRateBatchExtendedTest(s *VethsSuite) {
	wvrExtendedOnly(s)
	wvrRun(s, wvrConfig{wvrDataFixed, wvrAckBatch, "bbr", true, 20, false})
}

func WifiVariableRateTailExtendedTest(s *VethsSuite) {
	wvrExtendedOnly(s)
	wvrRun(s, wvrConfig{wvrDataFixed, wvrAckTail, "bbr", true, 20, false})
}

func WifiVariableRateCycleBatchExtendedTest(s *VethsSuite) {
	wvrExtendedOnly(s)
	wvrRun(s, wvrConfig{wvrDataCycle, wvrAckBatch, "bbr", true, 20, false})
}

func WifiVariableRateCycleTailExtendedTest(s *VethsSuite) {
	wvrExtendedOnly(s)
	wvrRun(s, wvrConfig{wvrDataCycle, wvrAckTail, "bbr", true, 45, false})
}

func WifiVariableRateFastCycleExtendedTest(s *VethsSuite) {
	wvrExtendedOnly(s)
	result := wvrRun(s, wvrConfig{wvrDataCycleFast, wvrAckTail, "bbr", true, 20, false})
	AssertGreaterEqual(result.goodputMbps, 225.0,
		"BBR must recover during one-second high-rate intervals")
}

func WifiVariableRatePersistentDropExtendedTest(s *VethsSuite) {
	wvrExtendedOnly(s)
	result := wvrRun(s, wvrConfig{wvrDataPersistentDrop, wvrAckTail, "bbr", true, 20, false})
	AssertLessEqual(result.p95Queue, 80.0,
		"recovery probes must not sustain a queue after a capacity drop")
}
