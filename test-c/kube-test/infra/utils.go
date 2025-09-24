package kube_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

func boolPtr(b bool) *bool {
	return &b
}

func int64Ptr(integer int64) *int64 {
	return &integer
}

func GetTestFilename() string {
	_, filename, _, _ := runtime.Caller(2)
	return filepath.Base(filename)
}

var testCounter uint16
var startTime time.Time = time.Now()

func TestCounterFunc() {
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

func (s *BaseSuite) ParseJsonIperfOutput(jsonResult []byte) IPerfResult {
	var result IPerfResult

	// VCL/LDP debugging can pollute output so find the first occurrence of a curly brace to locate the start of JSON data
	jsonStart := -1
	jsonEnd := len(jsonResult)
	braceCount := 0
	for i := 0; i < len(jsonResult); i++ {
		if jsonResult[i] == '{' {
			if jsonStart == -1 {
				jsonStart = i
			}
			braceCount++
		} else if jsonResult[i] == '}' {
			braceCount--
			if braceCount == 0 {
				jsonEnd = i + 1
				break
			}
		}
	}
	jsonResult = jsonResult[jsonStart:jsonEnd]

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

func (s *BaseSuite) LogJsonIperfOutput(result IPerfResult) {
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

func (s *BaseSuite) handleExistingVarsFile(fileValues map[string]string) error {
	varsToWatch := []string{"CALICOVPP_VERSION", "CALICOVPP_INTERFACE"}
	needsWrite := false

	for _, key := range varsToWatch {
		envValue := os.Getenv(key)
		if envValue != "" {
			if fileValue, ok := fileValues[key]; !ok || fileValue != envValue {
				s.Log("Updating '%s'. New value: '%s'", key, envValue)
				fileValues[key] = envValue
				needsWrite = true
			}
		}
	}

	if needsWrite {
		if err := godotenv.Write(fileValues, EnvVarsFile); err != nil {
			return err
		}
		s.Log("File %s updated", EnvVarsFile)
	} else {
		s.Log("%s OK", EnvVarsFile)
	}
	return nil
}

func (s *BaseSuite) handleNewVarsFile() error {
	iface := os.Getenv("CALICOVPP_INTERFACE")
	version := os.Getenv("CALICOVPP_VERSION")

	if iface != "" && version != "" {
		newFileValues := map[string]string{
			"CALICOVPP_INTERFACE": iface,
			"CALICOVPP_VERSION":   version,
		}

		s.Log("\nCreating '%s' from environment variables\n", EnvVarsFile)
		if err := godotenv.Write(newFileValues, EnvVarsFile); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("Error: '%s' not found and env vars are not set. "+
			"To create it, please set both CALICOVPP_INTERFACE and CALICOVPP_VERSION env vars", EnvVarsFile)
	}
	return nil
}
