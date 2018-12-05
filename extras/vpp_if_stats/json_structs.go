package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"git.fd.io/govpp.git/examples/bin_api/vpe"
)

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
	Interfaces      []*jsonVppInterface `json:"interfaces"`
}

func bytesToString(b []byte) string {
	return string(bytes.Split(b, []byte{0})[0])
}

func toJSONVppDetails(svReply *vpe.ShowVersionReply) *jsonVppDetails {
	return &jsonVppDetails{
		Program:        bytesToString(svReply.Program),
		Version:        bytesToString(svReply.Version),
		BuildDate:      bytesToString(svReply.BuildDate),
		BuildDirectory: bytesToString(svReply.BuildDirectory),
	}
}

func toJSONVppInterface(vppIf *vppInterface) *jsonVppInterface {
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

func toJSONVppPayload(svReply *vpe.ShowVersionReply, vppIfs []*vppInterface) *jsonVppPayload {
	p := &jsonVppPayload{jsonVppDetails: toJSONVppDetails(svReply), Interfaces: make([]*jsonVppInterface, len(vppIfs))}
	for index, vppIf := range vppIfs {
		p.Interfaces[index] = toJSONVppInterface(vppIf)
	}
	return p
}

func dumpToJSONString(v *vppConnector) (string, error) {
	payload := toJSONVppPayload(&v.VppDetails, v.Interfaces)
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to dump to json: %v", err)
	}
	return string(jsonBytes), nil
}
