package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	. "fd.io/hs-test/infra"
)

func init() {
	RegisterH2Tests(
		Http2TlsListenerSegmentManagerTest,
		Http2TlsConnectSegmentManagerTest,
		Http2TlsTransportSegmentManagerSegmentsTest,
		Http2ConnectTransportSegmentManagerSegmentsTest,
	)
	RegisterH3Tests(
		Http3ListenerSegmentManagerTest,
		Http3ConnectSegmentManagerTest,
		Http3TransportSegmentManagerSegmentsTest,
		Http3ConnectTransportSegmentManagerSegmentsTest,
	)
}

type clientProtoEntry struct {
	line    string
	appName string
	smIndex int
}

func getSegmentManagerCount(vpp *VppInstance) int {
	o := vpp.Vppctl("show segment-manager")
	fields := strings.Fields(o)
	AssertNotEqual(0, len(fields), "unexpected show segment-manager output")
	if len(fields) == 0 {
		return -1
	}

	count, err := strconv.Atoi(fields[0])
	AssertNil(err, fmt.Sprintf("failed to parse segment manager count: %v", err))
	if err != nil {
		return -1
	}

	return count
}

func getAppListenerSegmentManagers(vpp *VppInstance, appName string) []int {
	o := vpp.Vppctl("show app listeners verbose")
	seen := map[int]struct{}{}
	var sms []int

	for _, line := range strings.Split(o, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		appMatched := false
		for _, field := range fields {
			if field == appName {
				appMatched = true
				break
			}
		}
		if !appMatched {
			continue
		}

		sm, err := strconv.Atoi(fields[len(fields)-1])
		if err == nil {
			if _, ok := seen[sm]; !ok {
				seen[sm] = struct{}{}
				sms = append(sms, sm)
			}
		}
	}

	return sms
}

func waitForAppListenerSegmentManagers(vpp *VppInstance, appName string, timeoutSeconds int) []int {
	for range timeoutSeconds {
		sms := getAppListenerSegmentManagers(vpp, appName)
		if len(sms) > 0 {
			return sms
		}
		time.Sleep(time.Second)
	}

	AssertEqual(true, false, "listener sm not found for app %s", appName)
	return nil
}

func waitForNoAppListener(vpp *VppInstance, appName string, timeoutSeconds int) {
	for range timeoutSeconds {
		if len(getAppListenerSegmentManagers(vpp, appName)) == 0 {
			return
		}
		time.Sleep(time.Second)
	}

	AssertEqual(true, false, "listener for app %s still present", appName)
}

func waitForSegmentManagerCount(vpp *VppInstance, want, timeoutSeconds int) {
	for range timeoutSeconds {
		if getSegmentManagerCount(vpp) == want {
			return
		}
		time.Sleep(time.Second)
	}

	AssertEqual(true, false, "segment-manager count did not return to %d", want)
}

func getConnectSegmentManagers(vpp *VppInstance, appName string) []int {
	o := vpp.Vppctl("show segment-manager verbose")
	var sms []int

	for _, line := range strings.Split(o, "\n") {
		if !strings.HasPrefix(line, "[") {
			continue
		}
		if !strings.Contains(line, "] "+appName+" app-wrk:") {
			continue
		}
		if !strings.Contains(line, "connects") {
			continue
		}

		end := strings.Index(line, "]")
		if end <= 1 {
			continue
		}
		sm, err := strconv.Atoi(line[1:end])
		if err == nil {
			sms = append(sms, sm)
		}
	}

	return sms
}

func hasSegmentManagerSegmentsApp(output string, appName string) bool {
	return strings.Contains(output, "] "+appName+" app-wrk:")
}

func waitForSegmentManagerSegmentsApp(vpp *VppInstance, appName string, timeoutSeconds int) string {
	var lastOutput string
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	for time.Now().Before(deadline) {
		o := vpp.Vppctl("show segment-manager segments")
		lastOutput = o
		if hasSegmentManagerSegmentsApp(o, appName) {
			Log(o)
			return o
		}
		time.Sleep(100 * time.Millisecond)
	}

	Log(lastOutput)
	AssertEqual(true, false,
		"segment manager not found for app %s in show segment-manager segments", appName)
	return ""
}

func waitForNoSegmentManagerSegmentsApp(vpp *VppInstance, appName string, timeoutSeconds int) {
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	for time.Now().Before(deadline) {
		o := vpp.Vppctl("show segment-manager segments")
		if !hasSegmentManagerSegmentsApp(o, appName) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}

	AssertEqual(true, false,
		"segment manager for app %s still present in show segment-manager segments", appName)
}

func getClientProtoEntriesFromOutput(output string, proto string) []clientProtoEntry {
	var entries []clientProtoEntry

	for _, line := range strings.Split(output, "\n") {
		if !strings.Contains(line, proto) {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		sm, err := strconv.Atoi(fields[len(fields)-1])
		if err != nil {
			continue
		}

		entries = append(entries, clientProtoEntry{
			line:    line,
			appName: fields[len(fields)-3],
			smIndex: sm,
		})
	}

	return entries
}

func waitForClientProtoSnapshot(vpp *VppInstance, protos []string, timeoutSeconds int) map[string][]clientProtoEntry {
	var lastOutput string
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	for time.Now().Before(deadline) {
		o := vpp.Vppctl("show app client verbose")
		lastOutput = o
		entriesByProto := make(map[string][]clientProtoEntry, len(protos))
		allFound := true

		for _, proto := range protos {
			entries := getClientProtoEntriesFromOutput(o, proto)
			if len(entries) == 0 {
				allFound = false
				break
			}
			entriesByProto[proto] = entries
		}

		if allFound {
			Log(o)
			return entriesByProto
		}

		time.Sleep(100 * time.Millisecond)
	}

	Log(lastOutput)
	AssertEqual(true, false, "client entries not found for %v", protos)
	return nil
}

func waitForNoClientProtoEntries(vpp *VppInstance, protos []string, timeoutSeconds int) {
	deadline := time.Now().Add(time.Duration(timeoutSeconds) * time.Second)
	for time.Now().Before(deadline) {
		o := vpp.Vppctl("show app client verbose")
		anyFound := false

		for _, proto := range protos {
			if len(getClientProtoEntriesFromOutput(o, proto)) > 0 {
				anyFound = true
				break
			}
		}

		if !anyFound {
			return
		}

		time.Sleep(100 * time.Millisecond)
	}

	AssertEqual(true, false, "client entries still present for %v", protos)
}

func assertSegmentManagerOwner(vpp *VppInstance, smIndex int, appName string) {
	o := vpp.Vppctl("show segment-manager index %d", smIndex)
	Log(o)
	AssertContains(o, "] "+appName+" app-wrk:")
}

func assertAllSegmentManagersEqual(sms []int, want int, msg string) {
	for _, sm := range sms {
		AssertEqual(want, sm, msg+" (all sms: %v)", sms)
	}
}

func assertClientProtoEntriesUseApp(entries []clientProtoEntry, appName string, wantSm int, msg string) {
	for _, entry := range entries {
		AssertEqual(appName, entry.appName, "%s line: %s", msg, entry.line)
		AssertEqual(wantSm, entry.smIndex, "%s line: %s", msg, entry.line)
	}
}

func assertNoSegmentManagerSegmentsForApps(output string, appNames ...string) {
	for _, appName := range appNames {
		AssertNotContains(output, "] "+appName+" app-wrk:")
	}
}
