package main

import (
	"encoding/json"
	"fmt"
	"net"

	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/vpe"
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
	AdminState bool   `json:"if_admin_state"`
	LinkState  bool   `json:"if_link_state"`
	LinkMTU    uint16 `json:"if_link_mtu"`
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

	func toJSONVppDetails(svReply *vpe.ShowVersionReply) *jsonVppDetails {
	return &jsonVppDetails{
		Program:        svReply.Program,
		Version:        svReply.Version,
		BuildDate:      svReply.BuildDate,
		BuildDirectory: svReply.BuildDirectory,
	}
}

func toJSONVppInterface(vppIf *vppInterface) *jsonVppInterface {
	return &jsonVppInterface{
		Index:      uint32(vppIf.SwIfIndex),
		Name:       vppIf.InterfaceName,
		Tag:        vppIf.Tag,
		MacAddress: net.HardwareAddr(vppIf.L2Address[:]).String(),
		AdminState: vppIf.Flags&interface_types.IF_STATUS_API_FLAG_ADMIN_UP != 0,
		LinkState:  vppIf.Flags&interface_types.IF_STATUS_API_FLAG_LINK_UP != 0,
		LinkMTU:    vppIf.LinkMtu,
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
	p := &jsonVppPayload{
		jsonVppDetails: toJSONVppDetails(svReply),
		Interfaces:     make([]*jsonVppInterface, len(vppIfs)),
	}
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
