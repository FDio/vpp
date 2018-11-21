package vppifstats

import (
	"bytes"
	"git.fd.io/govpp.git/examples/bin_api/vpe"
)

type JsonVppDetails struct {
	Program        string `json:"program"`
	Version        string `json:"version"`
	BuildDate      string `json:"build_date"`
	BuildDirectory string `json:"build_directory"`
}

type JsonVppInterface struct {
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

type JsonVppPayload struct {
	*JsonVppDetails `json:"vpp_details"`
	Interfaces      map[uint32]*JsonVppInterface `json:"if_details"`
}

func BytesToString(b []byte) string {
	return string(bytes.Split(b, []byte{0})[0])
}

func ToJsonVppDetails(svReply *vpe.ShowVersionReply) *JsonVppDetails {
	return &JsonVppDetails{
		Program:        BytesToString(svReply.Program),
		Version:        BytesToString(svReply.Version),
		BuildDate:      BytesToString(svReply.BuildDate),
		BuildDirectory: BytesToString(svReply.BuildDirectory),
	}
}

func ToJsonVppInterface(vppIf *VppInterface) *JsonVppInterface {
	return &JsonVppInterface{
		Index:      vppIf.SwIfIndex,
		Name:       BytesToString(vppIf.InterfaceName),
		Tag:        BytesToString(vppIf.Tag),
		MacAddress: ParseMacAddress(vppIf.L2Address, vppIf.L2AddressLength),
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

func ToJsonVppPayload(svReply *vpe.ShowVersionReply, vppIfs map[uint32]*VppInterface) *JsonVppPayload {
	p := &JsonVppPayload{JsonVppDetails: ToJsonVppDetails(svReply), Interfaces: make(map[uint32]*JsonVppInterface)}
	for index, vppIf := range vppIfs {
		p.Interfaces[index] = ToJsonVppInterface(vppIf)
	}
	return p
}
