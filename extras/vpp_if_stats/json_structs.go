package main

import (
	"encoding/json"
	"fmt"
	"git.fd.io/govpp.git/examples/binapi/vpe"
	"regexp"
)

type jsonVppInterface struct {
	UUID           string `json:"if_uuid"`
	Index          uint32 `json:"if_index"`
	Name           string `json:"if_name"`
	Type           string `json:"if_type"`
	Tag            string `json:"if_tag"`
	Port           uint64 `json:"-"`
	MacAddress     string `json:"if_mac"`
	AdminState     uint8  `json:"if_admin_state"`
	LinkState      uint8  `json:"if_link_state"`
	LinkMTU        uint16 `json:"if_link_mtu"`
	LinkMTURequest uint16 `json:"-"`
	Function       string `json:"if_func"`
	SubDot1ad      uint8  `json:"if_sub_dot1ad"`
	SubID          uint32 `json:"if_sub_id"`

	TxBytes   uint64 `json:"if_tx_bytes"`
	TxPackets uint64 `json:"if_tx_packets"`
	TxErrors  uint64 `json:"if_tx_errors"`
	RxBytes   uint64 `json:"if_rx_bytes"`
	RxPackets uint64 `json:"if_rx_packets"`
	RxErrors  uint64 `json:"if_rx_errors"`
	Drops     uint64 `json:"if_drops"`
	Punts     uint64 `json:"if_punts"`
}

type jsonVppDetails struct {
	Program        string `json:"program"`
	Version        string `json:"version"`
	BuildDate      string `json:"build_date"`
	BuildDirectory string `json:"build_directory"`
}

type jsonVppPayload struct {
	*jsonVppDetails `json:"vpp_details"`
	Interfaces      []*jsonVppInterface `json:"interfaces"`
}

func toJsonVppDetails(svReply *vpe.ShowVersionReply) *jsonVppDetails {
	return &jsonVppDetails{
		Program:        svReply.Program,
		Version:        svReply.Version,
		BuildDate:      svReply.BuildDate,
		BuildDirectory: svReply.BuildDirectory,
	}
}

const (
	physical = "physical"
	instance = "instance"
	vservice = "vservice"
)

var (
	uuidRegex     = regexp.MustCompile("([a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89aAbB][a-f0-9]{3}-[a-f0-9]{12})")
	physNameRegex = regexp.MustCompile("Gigabit|Bond")
	physnetRegex  = regexp.MustCompile("physnet")
	virtualRegex  = regexp.MustCompile("Virtual")
	vServiceRegex = regexp.MustCompile("tapcli")
)

func (v *vppInterface) getFunction() string {
	if physNameRegex.Match(v.InterfaceName) || physnetRegex.Match(v.Tag) {
		return physical
	} else if virtualRegex.Match(v.InterfaceName) {
		return instance
	} else if vServiceRegex.Match(v.InterfaceName) {
		return vservice
	}
	return ""
}

func (v *vppInterface) getUUID() string {
	uuidMatch := uuidRegex.FindSubmatch(v.Tag)
	if len(uuidMatch) > 1 {
		return string(uuidMatch[1])
	}
	return ""
}

func (v *vppInterface) getType() string {
	if virtualRegex.Match(v.InterfaceName) {
		return "internal"
	}
	return "external"
}

func (v *vppInterface) toJson() *jsonVppInterface {
	return &jsonVppInterface{
		Index:      v.SwIfIndex,
		Name:       bytesToString(v.InterfaceName),
		Tag:        bytesToString(v.Tag),
		MacAddress: parseMacAddress(v.L2Address, v.L2AddressLength),
		AdminState: v.AdminUpDown,
		LinkState:  v.LinkUpDown,
		LinkMTU:    v.LinkMtu,
		Function:   v.getFunction(),
		SubDot1ad:  v.SubDot1ad,
		SubID:      v.SubID,
		TxBytes:    v.Stats.TxBytes,
		TxPackets:  v.Stats.TxPackets,
		TxErrors:   v.Stats.TxErrors,
		RxBytes:    v.Stats.RxBytes,
		RxPackets:  v.Stats.RxPackets,
		RxErrors:   v.Stats.RxErrors,
		Drops:      v.Stats.Drops,
		Punts:      v.Stats.Punts,
		UUID:       v.getUUID(),
		Type:       v.getType(),
	}
}

func toJsonVppPayload(svReply *vpe.ShowVersionReply, vppIfs map[uint32]*vppInterface) *jsonVppPayload {
	p := &jsonVppPayload{jsonVppDetails: toJsonVppDetails(svReply), Interfaces: make([]*jsonVppInterface, 0)}
	for _, vppIf := range vppIfs {
		p.Interfaces = append(p.Interfaces, vppIf.toJson())
	}
	return p
}

func (v *VppConnector) DumpToJson() ([]byte, error) {
	payload := toJsonVppPayload(&v.VppDetails, v.Interfaces)
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to dump to json: %v", err)
	}
	return jsonBytes, nil
}
