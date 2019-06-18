package main

import (
	"fmt"
	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter"
	"git.fd.io/govpp.git/adapter/socketclient"
	"git.fd.io/govpp.git/adapter/vppapiclient"
	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/core"
	"git.fd.io/govpp.git/examples/binapi/interfaces"
	"git.fd.io/govpp.git/examples/binapi/vpe"
)

const (
	DefaultShmPrefix         = ""
	DefaultAPISocketPath     = "/run/vpp/api.sock"
	DefaultStatsSocketPath   = "/run/vpp/stats.sock"
)

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

type VppConnector struct {
	APISocketPath   string
	StatsSocketPath string
	ShmPrefix       string

	conn  *core.Connection
	api   api.Channel
	stats adapter.StatsAPI

	VppDetails vpe.ShowVersionReply
	Interfaces map[uint32]*vppInterface
}

func NewVppConnector(apiSocketPath string, statsSocketPath string, shmPrefix string) *VppConnector {
	return &VppConnector{
		APISocketPath:   apiSocketPath,
		StatsSocketPath: statsSocketPath,
		ShmPrefix:       shmPrefix,
	}
}

func (v *VppConnector) GetVppVersion() error {
	Logger.Debug("Fetching VPP details")
	if err := v.api.SendRequest(&vpe.ShowVersion{}).ReceiveReply(&v.VppDetails); err != nil {
		return fmt.Errorf("failed to fetch VPP version: %v", err)
	}
	Logger.Debug("Fetched VPP details")
	return nil
}

func (v *VppConnector) GetInterfaces() error {
	Logger.Debug("Fetching interfaces")
	v.Interfaces = make(map[uint32]*vppInterface)
	ifCtx := v.api.SendMultiRequest(&interfaces.SwInterfaceDump{})
	Logger.Debug("Request to fetch interfaces sent")
	for {
		ifDetails := interfaces.SwInterfaceDetails{}
		stop, err := ifCtx.ReceiveReply(&ifDetails)
		if err != nil {
			return fmt.Errorf("failed to fetch VPP interface: %v", err)
		}
		if stop {
			break
		}

		v.Interfaces[ifDetails.SwIfIndex] = &vppInterface{SwInterfaceDetails: ifDetails}
	}
	Logger.Debugf("Interfaces fetched successfully, total fetched: %v", len(v.Interfaces))
	return nil
}

func (v *VppConnector) Connect() (err error) {
	Logger.Infof("Connecting to VPP using API socket (%v)", v.APISocketPath)
	govpp.SetVppAdapter(socketclient.NewVppClient(v.APISocketPath))

	if v.conn, err = govpp.Connect(v.ShmPrefix); err != nil {
		return fmt.Errorf("failed to connect to VPP: %v", err)
	}

	Logger.Info("Creating VPP API channel")
	if v.api, err = v.conn.NewAPIChannel(); err != nil {
		return fmt.Errorf("failed to create api channel: %v", err)
	}

	Logger.Infof("Connecting to stats socket (path: %v)", v.StatsSocketPath)
	v.stats = vppapiclient.NewStatClient(v.StatsSocketPath)
	if err = v.stats.Connect(); err != nil {
		return fmt.Errorf("failed to connect to Stats adapter: %v", err)
	}
	Logger.Info("Connection to VPP successful")

	return
}

func (v *VppConnector) Disconnect() error {
	Logger.Info("Disconnecting from VPP")
	if v.conn != nil {
		v.conn.Disconnect()
	}
	if v.stats != nil {
		return v.stats.Disconnect()
	}
	return nil
}

func (v *VppConnector) reduceCombinedCounters(statEntry *adapter.StatEntry) map[uint32]*adapter.CombinedCounter {
	counters := statEntry.Data.(adapter.CombinedCounterStat)
	stats := make(map[uint32]*adapter.CombinedCounter)
	for _, vIf := range v.Interfaces {
		stats[vIf.SwIfIndex] = &adapter.CombinedCounter{}
		for _, workerStats := range counters {
			stats[vIf.SwIfIndex].Bytes += workerStats[vIf.SwIfIndex].Bytes
			stats[vIf.SwIfIndex].Packets += workerStats[vIf.SwIfIndex].Packets
		}
	}
	return stats
}

func (v *VppConnector) reduceSimpleCounters(stat *adapter.StatEntry) map[uint32]adapter.Counter {
	counters := stat.Data.(adapter.SimpleCounterStat)
	stats := make(map[uint32]adapter.Counter)
	for _, vIf := range v.Interfaces {
		for _, workerStats := range counters {
			stats[vIf.SwIfIndex] += workerStats[vIf.SwIfIndex]
		}
	}
	return stats
}

func (v *VppConnector) GetStatsForAllInterfaces() error {
	Logger.Debug("Dumping interfaces stats")
	statsDump, err := v.stats.DumpStats("/if")
	if err != nil {
		return fmt.Errorf("failed to dump VPP Stats: %v", err)
	}
	Logger.Debug("Stats dumped successfully")

	stats := func(i uint32) *interfaceStats { return &v.Interfaces[uint32(i)].Stats }

	for _, stat := range statsDump {
		switch stat.Name {
		case "/if/tx":
			{
				for i, counter := range v.reduceCombinedCounters(stat) {
					stats(i).TxBytes = uint64(counter.Bytes)
					stats(i).TxPackets = uint64(counter.Packets)
				}
			}
		case "/if/rx":
			{
				for i, counter := range v.reduceCombinedCounters(stat) {
					stats(i).RxBytes = uint64(counter.Bytes)
					stats(i).RxPackets = uint64(counter.Packets)
				}
			}
		case "/if/tx-error":
			{
				for i, counter := range v.reduceSimpleCounters(stat) {
					stats(i).TxErrors = uint64(counter)
				}
			}
		case "/if/rx-error":
			{
				for i, counter := range v.reduceSimpleCounters(stat) {
					stats(i).RxErrors = uint64(counter)
				}
			}
		case "/if/drops":
			{
				for i, counter := range v.reduceSimpleCounters(stat) {
					stats(i).Drops = uint64(counter)
				}
			}
		case "/if/punt":
			{
				for i, counter := range v.reduceSimpleCounters(stat) {
					stats(i).Punts = uint64(counter)
				}
			}
		}
	}
	return nil
}
