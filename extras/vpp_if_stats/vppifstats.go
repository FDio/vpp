package vppifstats

import (
	"bytes"
	"fmt"
	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter"
	"git.fd.io/govpp.git/adapter/vppapiclient"
	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/core"
	"git.fd.io/govpp.git/examples/bin_api/interfaces"
	"git.fd.io/govpp.git/examples/bin_api/vpe"
	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/plugins/inputs"
)

const measurementKey = "vppifstats"

type InterfaceStats struct {
	TxBytes   uint64
	TxPackets uint64
	TxErrors  uint64
	RxBytes   uint64
	RxPackets uint64
	RxErrors  uint64
	Drops     uint64
	Punts     uint64
}

type VppInterface struct {
	interfaces.SwInterfaceDetails
	Stats InterfaceStats
}

type VppIfStats struct {
	StatsSocketPath string `toml:"stats_socket_path"`

	conn  *core.Connection
	api   api.Channel
	stats adapter.StatsAPI

	VppDetails vpe.ShowVersionReply
	Interfaces map[uint32]*VppInterface
}

var sampleConfig = `
	## VPP Stats socket path
	stats_socket_path = "/run/vpp/stats.sock"
`

func (v *VppIfStats) Description() string {
	return "VPP interface Stats"
}

func (v *VppIfStats) SampleConfig() string {
	return sampleConfig
}

func (v *VppIfStats) GetVppVersion() error {
	if err := v.api.SendRequest(&vpe.ShowVersion{}).ReceiveReply(&v.VppDetails); err != nil {
		return fmt.Errorf("failed to fetch vpp version: %v", err)
	}
	return nil
}

func (v *VppIfStats) GetInterfaces() error {
	v.Interfaces = make(map[uint32]*VppInterface)
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

		v.Interfaces[ifDetails.SwIfIndex] = &VppInterface{SwInterfaceDetails: ifDetails}
	}
	return nil
}

func (v *VppIfStats) Connect() (err error) {
	if v.conn, err = govpp.Connect(""); err != nil {
		return fmt.Errorf("failed to connect to vpp: %v", err)
	}

	if v.api, err = v.conn.NewAPIChannel(); err != nil {
		return fmt.Errorf("failed to create api channel: %v", err)
	}

	v.stats = vppapiclient.NewStatClient(v.StatsSocketPath)
	if err = v.stats.Connect(); err != nil {
		return fmt.Errorf("failed to connect to Stats adapter: %v", err)
	}

	return
}

func (v *VppIfStats) Disconnect() {
	if v.stats != nil {
		v.stats.Disconnect()
	}
	if v.conn != nil {
		v.conn.Disconnect()
	}
}

func (v *VppIfStats) reduceCombinedCounters(stat *adapter.StatEntry) *[]adapter.CombinedCounter {
	counters := stat.Data.(adapter.CombinedCounterStat)
	stats := make([]adapter.CombinedCounter, len(v.Interfaces))
	for _, workerStats := range counters {
		for i, interfaceStats := range workerStats {
			stats[i].Bytes += interfaceStats.Bytes
			stats[i].Packets += interfaceStats.Packets
		}
	}
	return &stats
}

func (v *VppIfStats) reduceSimpleCounters(stat *adapter.StatEntry) *[]adapter.Counter {
	counters := stat.Data.(adapter.SimpleCounterStat)
	stats := make([]adapter.Counter, len(v.Interfaces))
	for _, workerStats := range counters {
		for i, interfaceStats := range workerStats {
			stats[i] += interfaceStats
		}
	}
	return &stats
}

func (v *VppIfStats) GetStatsForAllInterfaces() error {
	statsDump, err := v.stats.DumpStats("/if")
	if err != nil {
		return fmt.Errorf("failed to dump vpp Stats: %v", err)
	}

	stats := func(i int) *InterfaceStats {return &v.Interfaces[uint32(i)].Stats}

	for _, stat := range statsDump {
		switch stat.Name {
		case "/if/tx":
			{
				for i, counter := range *v.reduceCombinedCounters(stat) {
					stats(i).TxBytes = uint64(counter.Bytes)
					stats(i).TxPackets = uint64(counter.Packets)
				}
			}
		case "/if/rx":
			{
				for i, counter := range *v.reduceCombinedCounters(stat) {
					stats(i).RxBytes = uint64(counter.Bytes)
					stats(i).RxPackets = uint64(counter.Packets)
				}
			}
		case "/if/tx-error":
			{
				for i, counter := range *v.reduceSimpleCounters(stat) {
					stats(i).TxErrors = uint64(counter)
				}
			}
		case "/if/rx-error":
			{
				for i, counter := range *v.reduceSimpleCounters(stat) {
					stats(i).RxErrors = uint64(counter)
				}
			}
		case "/if/drops":
			{
				for i, counter := range *v.reduceSimpleCounters(stat) {
					stats(i).Drops = uint64(counter)
				}
			}
		case "/if/punt":
			{
				for i, counter := range *v.reduceSimpleCounters(stat) {
					stats(i).Punts = uint64(counter)
				}
			}
		}
	}
	return nil
}

func ParseMacAddress(l2Address []byte, l2AddressLength uint32) string {
	var mac string
	for i := uint32(0); i < l2AddressLength; i++ {
		mac += fmt.Sprintf("%02x", l2Address[i])
		if i < l2AddressLength-1 {
			mac += ":"
		}
	}
	return mac
}

func (v *VppIfStats) buildMetrics(acc telegraf.Accumulator) {
	for _, vppIf := range v.Interfaces {
		stats := &vppIf.Stats
		metrics := map[string]interface{}{
			"if_admin_state": vppIf.AdminUpDown,
			"if_link_state":  vppIf.LinkUpDown,
			"if_drops":       stats.Drops,
			"if_punts":       stats.Punts,
			"if_rx_bytes":    stats.RxBytes,
			"if_rx_errors":   stats.RxErrors,
			"if_rx_packets":  stats.RxPackets,
			"if_tx_bytes":    stats.TxBytes,
			"if_tx_errors":   stats.TxErrors,
			"if_tx_packets":  stats.RxPackets,
		}

		tags := map[string]string{
			"if_mac":  ParseMacAddress(vppIf.L2Address, vppIf.L2AddressLength),
			"if_name": string(bytes.Trim(vppIf.InterfaceName, "\x00")),
			"if_tag":  string(bytes.Trim(vppIf.Tag, "\x00")),
		}

		acc.AddFields(measurementKey, metrics, tags)
	}
}

func (v *VppIfStats) Gather(acc telegraf.Accumulator) error {
	defer v.Disconnect()

	if err := v.Connect(); err != nil {
		return err
	}

	if err := v.GetVppVersion(); err != nil {
		return err
	}

	if err := v.GetInterfaces(); err != nil {
		return err
	}

	if err := v.GetStatsForAllInterfaces(); err != nil {
		return err
	}

	v.buildMetrics(acc)

	return nil
}

func init() {
	inputs.Add("vppifstats", func() telegraf.Input { return &VppIfStats{} })
}
