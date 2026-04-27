package main

import (
	"flag"
	"fmt"
	"log"

	"go.fd.io/govpp"
	"go.fd.io/govpp/adapter"
	"go.fd.io/govpp/adapter/statsclient"
	"go.fd.io/govpp/api"
	interfaces "go.fd.io/govpp/binapi/interface"
	"go.fd.io/govpp/binapi/vpe"
	"go.fd.io/govpp/core"
)

//////////////////////////////////////
/////////   Data structs   ///////////
//////////////////////////////////////

const defaultStatsSocketPath = "/run/vpp/stats.sock"
const defaultShmPrefix = ""

type interfaceStats struct {
	TxBytes   uint64
	TxPackets uint64
	TxErrors  uint64
	RxBytes   uint64
	RxPackets uint64
	RxErrors  uint64
	Drops     uint64
	Punts     uint64
}

type vppInterface struct {
	interfaces.SwInterfaceDetails
	Stats interfaceStats
}

type vppConnector struct {
	statsSocketPath string
	shmPrefix       string

	conn  *core.Connection
	api   api.Channel
	stats adapter.StatsAPI

	VppDetails vpe.ShowVersionReply
	Interfaces []*vppInterface
}

//////////////////////////////////////
/////////   VPP workflow   ///////////
//////////////////////////////////////

func (v *vppConnector) getVppVersion() error {
	if err := v.api.SendRequest(&vpe.ShowVersion{}).ReceiveReply(&v.VppDetails); err != nil {
		return fmt.Errorf("failed to fetch vpp version: %v", err)
	}
	return nil
}

func (v *vppConnector) getInterfaces() error {
	ifCtx := v.api.SendMultiRequest(&interfaces.SwInterfaceDump{})
	for {
		ifDetails := interfaces.SwInterfaceDetails{}
		stop, err := ifCtx.ReceiveReply(&ifDetails)
		if err != nil {
			return fmt.Errorf("failed to fetch vpp interface: %v", err)
		}
		if stop {
			break
		}

		v.Interfaces = append(v.Interfaces, &vppInterface{SwInterfaceDetails: ifDetails})
	}
	return nil
}

func (v *vppConnector) connect() (err error) {
	if v.conn, err = govpp.Connect(v.shmPrefix); err != nil {
		return fmt.Errorf("failed to connect to vpp: %v", err)
	}

	if v.api, err = v.conn.NewAPIChannel(); err != nil {
		return fmt.Errorf("failed to create api channel: %v", err)
	}

	v.stats = statsclient.NewStatsClient(v.statsSocketPath)
	if err = v.stats.Connect(); err != nil {
		return fmt.Errorf("failed to connect to Stats adapter: %v", err)
	}

	return
}

func (v *vppConnector) disconnect() {
	if v.stats != nil {
		err := v.stats.Disconnect()
		if err != nil {
			panic(err)
		}
	}
	if v.conn != nil {
		v.conn.Disconnect()
	}
}

func (v *vppConnector) reduceCombinedCounters(stat *adapter.StatEntry) *[]adapter.CombinedCounter {
	counters := stat.Data.(adapter.CombinedCounterStat)
	stats := make([]adapter.CombinedCounter, len(v.Interfaces))
	for _, workerStats := range counters {
		for i := 0; i < len(v.Interfaces); i++ {
			stats[i][0] += workerStats[i][0] // Packets
			stats[i][1] += workerStats[i][1] // Bytes
		}
	}
	return &stats
}

func (v *vppConnector) reduceSimpleCounters(stat *adapter.StatEntry) *[]adapter.Counter {
	counters := stat.Data.(adapter.SimpleCounterStat)
	stats := make([]adapter.Counter, len(v.Interfaces))
	for _, workerStats := range counters {
		for i := 0; i < len(v.Interfaces); i++ {
			stats[i] += workerStats[i]
		}
	}
	return &stats
}

func (v *vppConnector) getStatsForAllInterfaces() error {
	statsDump, err := v.stats.DumpStats("/if")
	if err != nil {
		return fmt.Errorf("failed to dump vpp Stats: %v", err)
	}

	stats := func(i int) *interfaceStats {
		return &v.Interfaces[uint32(i)].Stats
	}

	for _, stat := range statsDump {
		switch string(stat.Name) {
		case "/if/tx":
			for i, counter := range *v.reduceCombinedCounters(&stat) {
				stats(i).TxBytes = counter.Bytes()
				stats(i).TxPackets = counter.Packets()
			}
		case "/if/rx":
			for i, counter := range *v.reduceCombinedCounters(&stat) {
				stats(i).RxBytes = counter.Bytes()
				stats(i).RxPackets = counter.Packets()
			}
		case "/if/tx-error":
			for i, counter := range *v.reduceSimpleCounters(&stat) {
				stats(i).TxErrors = uint64(counter)
			}
		case "/if/rx-error":
			for i, counter := range *v.reduceSimpleCounters(&stat) {
				stats(i).RxErrors = uint64(counter)
			}
		case "/if/drops":
			for i, counter := range *v.reduceSimpleCounters(&stat) {
				stats(i).Drops = uint64(counter)
			}
		case "/if/punt":
			for i, counter := range *v.reduceSimpleCounters(&stat) {
				stats(i).Punts = uint64(counter)
			}
		}
	}
	return nil
}

//////////////////////////////////////

func main() {
	statsSocketPathPtr := flag.String("stats_socket_path", defaultStatsSocketPath, "Path to vpp stats socket")
	shmPrefixPtr := flag.String("shm_prefix", defaultShmPrefix, "Shared memory prefix (advanced)")
	flag.Parse()

	vppConn := &vppConnector{
		statsSocketPath: *statsSocketPathPtr,
		shmPrefix:       *shmPrefixPtr,
	}
	defer vppConn.disconnect()

	if err := vppConn.connect(); err != nil {
		log.Fatalln(err)
	}

	if err := vppConn.getVppVersion(); err != nil {
		log.Fatalln(err)
	}

	if err := vppConn.getInterfaces(); err != nil {
		log.Fatalln(err)
	}

	if err := vppConn.getStatsForAllInterfaces(); err != nil {
		log.Fatalln(err)
	}

	jsonString, err := dumpToJSONString(vppConn)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(jsonString)
}
