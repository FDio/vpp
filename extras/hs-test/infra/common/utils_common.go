package hst_common

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

func GetTestFilename() string {
	_, filename, _, _ := runtime.Caller(2)
	return filepath.Base(filename)
}

var testCounter uint16
var startTime time.Time = time.Now()

func TestCounterFunc() {
	if ParallelTotal.Value.String() != "1" {
		return
	}
	testCounter++
	fmt.Printf("Test counter: %d\n"+
		"Time elapsed: %.2fs\n",
		testCounter, time.Since(startTime).Seconds())
}

type IPerfResult struct {
	Start struct {
		Timestamp struct {
			Time string `json:"time"`
		} `json:"timestamp"`
		Connected []struct {
			Socket     int    `json:"socket"`
			LocalHost  string `json:"local_host"`
			LocalPort  int    `json:"local_port"`
			RemoteHost string `json:"remote_host"`
			RemotePort int    `json:"remote_port"`
		} `json:"connected"`
		Version string `json:"version"`
		Details struct {
			Protocol string `json:"protocol"`
		} `json:"test_start"`
	} `json:"start"`
	End struct {
		TcpSent *struct {
			MbitsPerSecond float64 `json:"bits_per_second"`
			MBytes         float64 `json:"bytes"`
		} `json:"sum_sent,omitempty"`
		TcpReceived *struct {
			MbitsPerSecond float64 `json:"bits_per_second"`
			MBytes         float64 `json:"bytes"`
		} `json:"sum_received,omitempty"`
		Udp *struct {
			MbitsPerSecond float64 `json:"bits_per_second"`
			JitterMs       float64 `json:"jitter_ms,omitempty"`
			LostPackets    int     `json:"lost_packets,omitempty"`
			Packets        int     `json:"packets,omitempty"`
			LostPercent    float64 `json:"lost_percent,omitempty"`
			MBytes         float64 `json:"bytes"`
		} `json:"sum,omitempty"`
	} `json:"end"`
}

func (s *HstCommon) ParseJsonIperfOutput(jsonResult []byte) IPerfResult {
	var result IPerfResult
	// remove iperf warning line if present
	if strings.Contains(string(jsonResult), "warning") {
		index := strings.Index(string(jsonResult), "\n")
		jsonResult = jsonResult[index+1:]
	}

	err := json.Unmarshal(jsonResult, &result)
	s.AssertNil(err)

	if result.Start.Details.Protocol == "TCP" {
		result.End.TcpSent.MbitsPerSecond = result.End.TcpSent.MbitsPerSecond / 1000000
		result.End.TcpSent.MBytes = result.End.TcpSent.MBytes / 1000000
		result.End.TcpReceived.MbitsPerSecond = result.End.TcpReceived.MbitsPerSecond / 1000000
		result.End.TcpReceived.MBytes = result.End.TcpReceived.MBytes / 1000000
	} else {
		result.End.Udp.MBytes = result.End.Udp.MBytes / 1000000
		result.End.Udp.MbitsPerSecond = result.End.Udp.MbitsPerSecond / 1000000
	}

	return result
}

func (s *HstCommon) LogJsonIperfOutput(result IPerfResult) {
	s.Log("\n*******************************************\n"+
		"%s\n"+
		"[%s] %s:%d connected to %s:%d\n"+
		"Started:  %s\n",
		result.Start.Version,
		result.Start.Details.Protocol,
		result.Start.Connected[0].LocalHost, result.Start.Connected[0].LocalPort,
		result.Start.Connected[0].RemoteHost, result.Start.Connected[0].RemotePort,
		result.Start.Timestamp.Time)

	if result.Start.Details.Protocol == "TCP" {
		s.Log("Transfer (sent):     %.2f MBytes\n"+
			"Bitrate  (sent):     %.2f Mbits/sec\n"+
			"Transfer (received): %.2f MBytes\n"+
			"Bitrate  (received): %.2f Mbits/sec",
			result.End.TcpSent.MBytes,
			result.End.TcpSent.MbitsPerSecond,
			result.End.TcpReceived.MBytes,
			result.End.TcpReceived.MbitsPerSecond)
	} else {
		s.Log("Transfer:     %.2f MBytes\n"+
			"Bitrate:      %.2f Mbits/sec\n"+
			"Jitter:       %.3f ms\n"+
			"Packets:      %d\n"+
			"Packets lost: %d\n"+
			"Percent lost: %.2f%%",
			result.End.Udp.MBytes,
			result.End.Udp.MbitsPerSecond,
			result.End.Udp.JitterMs,
			result.End.Udp.Packets,
			result.End.Udp.LostPackets,
			result.End.Udp.LostPercent)
	}
	s.Log("*******************************************\n")
}
