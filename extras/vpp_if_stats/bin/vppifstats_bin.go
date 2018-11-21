package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"git.fd.io/govpp.git"
	"git.fd.io/govpp.git/adapter"
	"git.fd.io/govpp.git/adapter/vppapiclient"
	"git.fd.io/govpp.git/api"
	"git.fd.io/govpp.git/core"
	"git.fd.io/govpp.git/examples/bin_api/interfaces"
	"git.fd.io/govpp.git/examples/bin_api/vpe"
	"log"
	"net/http"
)

//////////////////////////////////////
/////////   JSON structs   ///////////
//////////////////////////////////////

type jsonVppDetails struct {
	Program        string `json:"program"`
	Version        string `json:"version"`
	BuildDate      string `json:"build_date"`
	BuildDirectory string `json:"build_directory"`
}

type jsonVppInterface struct {
	Index      uint32 `json:"if_index"`
	Name       string `json:"if_name"`
	Tag        string `json:"if_tag"`
	MacAddress string `json:"if_mac"`
	AdminState uint8  `json:"if_admin_state"`
	LinkState  uint8  `json:"if_link_state"`
	LinkMTU    uint16 `json:"if_link_mtu"`
	SubDot1ad  uint8  `json:"if_sub_dot1ad"`
	SubID      uint32 `json:"if_sub_id"`

	TxBytes   uint64 `json:"if_tx_bytes"`
	TxPackets uint64 `json:"if_tx_packets"`
	TxErrors  uint64 `json:"if_tx_errors"`
	RxBytes   uint64 `json:"if_rx_bytes"`
	RxPackets uint64 `json:"if_rx_packets"`
	RxErrors  uint64 `json:"if_rx_errors"`
	Drops     uint64 `json:"if_drops"`
	Punts     uint64 `json:"if_punts"`
}

type jsonVppPayload struct {
	*jsonVppDetails `json:"vpp_details"`
	Interfaces      map[uint32]*jsonVppInterface `json:"interfaces"`
}

func bytesToString(b []byte) string {
	return string(bytes.Split(b, []byte{0})[0])
}

func toJsonVppDetails(svReply *vpe.ShowVersionReply) *jsonVppDetails {
	return &jsonVppDetails{
		Program:        bytesToString(svReply.Program),
		Version:        bytesToString(svReply.Version),
		BuildDate:      bytesToString(svReply.BuildDate),
		BuildDirectory: bytesToString(svReply.BuildDirectory),
	}
}

func toJsonVppInterface(vppIf *vppInterface) *jsonVppInterface {
	return &jsonVppInterface{
		Index:      vppIf.SwIfIndex,
		Name:       bytesToString(vppIf.InterfaceName),
		Tag:        bytesToString(vppIf.Tag),
		MacAddress: parseMacAddress(vppIf.L2Address, vppIf.L2AddressLength),
		AdminState: vppIf.AdminUpDown,
		LinkState:  vppIf.LinkUpDown,
		LinkMTU:    vppIf.LinkMtu,
		SubDot1ad:  vppIf.SubDot1ad,
		SubID:      vppIf.SubID,
		TxBytes:    vppIf.Stats.TxBytes,
		TxPackets:  vppIf.Stats.TxPackets,
		TxErrors:   vppIf.Stats.TxErrors,
		RxBytes:    vppIf.Stats.RxBytes,
		RxPackets:  vppIf.Stats.RxPackets,
		RxErrors:   vppIf.Stats.RxErrors,
		Drops:      vppIf.Stats.Drops,
		Punts:      vppIf.Stats.Punts,
	}
}

func toJsonVppPayload(svReply *vpe.ShowVersionReply, vppIfs map[uint32]*vppInterface) *jsonVppPayload {
	p := &jsonVppPayload{jsonVppDetails: toJsonVppDetails(svReply), Interfaces: make(map[uint32]*jsonVppInterface)}
	for index, vppIf := range vppIfs {
		p.Interfaces[index] = toJsonVppInterface(vppIf)
	}
	return p
}

func dumpToJson(v *vppConnector) ([]byte, error) {
	payload := toJsonVppPayload(&v.VppDetails, v.Interfaces)
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to dump to json: %v", err)
	}
	return jsonBytes, nil
}

//////////////////////////////////////
/////////   Data structs   ///////////
//////////////////////////////////////

const defaultPort = 7670
const defaultStatsSocketPath = "/run/vpp/stats.sock"
const defaultShmPrefix = ""

func parseMacAddress(l2Address []byte, l2AddressLength uint32) string {
	var mac string
	for i := uint32(0); i < l2AddressLength; i++ {
		mac += fmt.Sprintf("%02x", l2Address[i])
		if i < l2AddressLength-1 {
			mac += ":"
		}
	}
	return mac
}

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
	shmPrefix string

	conn  *core.Connection
	api   api.Channel
	stats adapter.StatsAPI

	VppDetails vpe.ShowVersionReply
	Interfaces map[uint32]*vppInterface
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
	v.Interfaces = make(map[uint32]*vppInterface)
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

		v.Interfaces[ifDetails.SwIfIndex] = &vppInterface{SwInterfaceDetails: ifDetails}
	}
	return nil
}

func (v *vppConnector) connect() (err error) {
	log.Printf("Connecting to VPP (shm prefix: '%v')\n", v.shmPrefix)
	if v.conn, err = govpp.Connect(v.shmPrefix); err != nil {
		return fmt.Errorf("failed to connect to vpp: %v", err)
	}

	log.Println("Creating VPP API channel")
	if v.api, err = v.conn.NewAPIChannel(); err != nil {
		return fmt.Errorf("failed to create api channel: %v", err)
	}

	log.Printf("Connecting to stats socket (path: %v)\n", v.statsSocketPath)
	v.stats = vppapiclient.NewStatClient(v.statsSocketPath)
	if err = v.stats.Connect(); err != nil {
		return fmt.Errorf("failed to connect to Stats adapter: %v", err)
	}
	log.Println("Connection to VPP successful")

	return
}

func (v *vppConnector) disconnect() {
	log.Println("Disconnecting from VPP")
	if v.stats != nil {
		v.stats.Disconnect()
	}
	if v.conn != nil {
		v.conn.Disconnect()
	}
}

func (v *vppConnector) reduceCombinedCounters(stat *adapter.StatEntry) *[]adapter.CombinedCounter {
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

func (v *vppConnector) reduceSimpleCounters(stat *adapter.StatEntry) *[]adapter.Counter {
	counters := stat.Data.(adapter.SimpleCounterStat)
	stats := make([]adapter.Counter, len(v.Interfaces))
	for _, workerStats := range counters {
		for i, interfaceStats := range workerStats {
			stats[i] += interfaceStats
		}
	}
	return &stats
}

func (v *vppConnector) getStatsForAllInterfaces() error {
	statsDump, err := v.stats.DumpStats("/if")
	if err != nil {
		return fmt.Errorf("failed to dump vpp Stats: %v", err)
	}

	stats := func(i int) *interfaceStats {return &v.Interfaces[uint32(i)].Stats}

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

//////////////////////////////////////

var vppConn *vppConnector

func scrapeHandler(w http.ResponseWriter, r *http.Request) {
	if err := vppConn.getInterfaces(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if err := vppConn.getStatsForAllInterfaces(); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	jsonString, err := dumpToJson(vppConn)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonString)
	log.Printf("%v %v --- %v %v\n", r.Method, r.URL, http.StatusOK, http.StatusText(http.StatusOK))
}

func main() {
	portPtr := flag.Int("port", defaultPort, "Port to listen")
	statsSocketPathPtr := flag.String("stats_socket_path", defaultStatsSocketPath, "Path to vpp stats socket")
	shmPrefixPtr := flag.String("shm_prefix", defaultShmPrefix, "Shared memory prefix (advanced)")
	flag.Parse()

	vppConn = &vppConnector{statsSocketPath: *statsSocketPathPtr, shmPrefix: *shmPrefixPtr}
	defer vppConn.disconnect()

	if err := vppConn.connect(); err != nil {
		log.Fatalln(err)
	}

	if err := vppConn.getVppVersion(); err != nil {
		log.Fatalln(err)
	}

	http.HandleFunc("/", scrapeHandler)

	address := fmt.Sprintf("localhost:%v", *portPtr)
	log.Printf("Listening on %v\n", address)
	log.Fatalln(http.ListenAndServe(address, nil))
}
