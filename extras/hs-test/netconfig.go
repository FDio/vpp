package main

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"go.fd.io/govpp/binapi/ethernet_types"
	"go.fd.io/govpp/binapi/interface_types"
	"go.fd.io/govpp/binapi/ip_types"
)

type (
	MacAddress           = ethernet_types.MacAddress
	AddressWithPrefix    = ip_types.AddressWithPrefix
	IP4AddressWithPrefix = ip_types.IP4AddressWithPrefix
	InterfaceIndex       = interface_types.InterfaceIndex

	NetConfig interface {
		Configure() error
		Unconfigure()
		Name() string
		Type() string
	}

	NetConfigBase struct {
		name     string
		category string // what else to call this when `type` is reserved?
	}

	NetInterface interface {
		NetConfig
		SetAddress(string)
		AddressWithPrefix() AddressWithPrefix
		IP4AddressWithPrefix() IP4AddressWithPrefix
		IP4AddressString() string
		SetIndex(InterfaceIndex)
		Index() InterfaceIndex
		HwAddress() MacAddress
	}

	NetInterfaceBase struct {
		NetConfigBase
		addresser  *Addresser
		ip4Address string // this will have form 10.10.10.1/24
		index      InterfaceIndex
		hwAddress  MacAddress
	}

	NetworkInterfaceVeth struct {
		NetInterfaceBase
		peerNetworkNamespace string
		peerName             string
		peerNetworkNumber    int
		peerIp4Address       string
	}

	NetworkInterfaceTap struct {
		NetInterfaceBase
	}

	NetworkNamespace struct {
		NetConfigBase
	}

	NetworkBridge struct {
		NetConfigBase
		networkNamespace string
		interfaces       []string
	}
)

const (
	NetNs  string = "netns"
	Veth   string = "veth"
	Tap    string = "tap"
	Bridge string = "bridge"
)

func (b *NetConfigBase) Name() string {
	return b.name
}

func (b *NetConfigBase) Type() string {
	return b.category
}

func (b *NetInterfaceBase) SetAddress(address string) {
	b.ip4Address = address
}

func (b *NetInterfaceBase) SetIndex(index InterfaceIndex) {
	b.index = index
}

func (b *NetInterfaceBase) Index() InterfaceIndex {
	return b.index
}

func (b *NetInterfaceBase) AddressWithPrefix() AddressWithPrefix {
	address, _ := ip_types.ParseAddressWithPrefix(b.ip4Address)
	return address
}

func (b *NetInterfaceBase) IP4AddressWithPrefix() IP4AddressWithPrefix {
	IP4Prefix, _ := ip_types.ParseIP4Prefix(b.ip4Address)
	IP4AddressWithPrefix := ip_types.IP4AddressWithPrefix(IP4Prefix)
	return IP4AddressWithPrefix
}

func (b *NetInterfaceBase) IP4AddressString() string {
	return strings.Split(b.ip4Address, "/")[0]
}

func (b *NetInterfaceBase) HwAddress() MacAddress {
	return b.hwAddress
}

func NewVeth(cfg NetDevConfig, a *Addresser) (NetworkInterfaceVeth, error) {
	var veth NetworkInterfaceVeth
	var err error
	veth.addresser = a
	veth.name = cfg["name"].(string)
	veth.category = "veth"
	veth.peerNetworkNumber = defaultNetworkNumber

	if cfg["preset-hw-address"] != nil {
		veth.hwAddress, err = ethernet_types.ParseMacAddress(cfg["preset-hw-address"].(string))
		if err != nil {
			return NetworkInterfaceVeth{}, err
		}
	}

	peer := cfg["peer"].(NetDevConfig)

	veth.peerName = peer["name"].(string)

	if peer["netns"] != nil {
		veth.peerNetworkNamespace = peer["netns"].(string)
	}

	if peerIp, ok := peer["ip4"]; ok {
		if n, ok := peerIp.(NetDevConfig)["network"]; ok {
			veth.peerNetworkNumber = n.(int)
		}
		veth.peerIp4Address, err = veth.addresser.NewIp4Address(veth.peerNetworkNumber)
		if err != nil {
			return NetworkInterfaceVeth{}, err
		}
	}

	return veth, nil
}

func (iface *NetworkInterfaceVeth) Configure() error {
	err := AddVethPair(iface.name, iface.peerName)
	if err != nil {
		return err
	}

	if iface.peerNetworkNamespace != "" {
		err := LinkSetNetns(iface.peerName, iface.peerNetworkNamespace)
		if err != nil {
			return err
		}
	}

	if iface.ip4Address != "" {
		err = AddAddress(iface.Name(), iface.ip4Address, "")
	}

	if iface.peerIp4Address != "" {
		err = AddAddress(iface.peerName, iface.peerIp4Address, iface.peerNetworkNamespace)
		if err != nil {
			return fmt.Errorf("failed to add configure address for %s: %v", iface.peerName, err)
		}
	}
	return nil
}

func (iface *NetworkInterfaceVeth) Unconfigure() {
	DelLink(iface.name)
}

func (iface *NetworkInterfaceVeth) PeerIp4AddressString() string {
	return strings.Split(iface.peerIp4Address, "/")[0]
}

func NewTap(cfg NetDevConfig, a *Addresser) (NetworkInterfaceTap, error) {
	var tap NetworkInterfaceTap
	tap.addresser = a
	tap.name = cfg["name"].(string)
	tap.category = "tap"
	ip4Address, err := tap.addresser.NewIp4Address()
	if err != nil {
		return NetworkInterfaceTap{}, err
	}
	tap.SetAddress(ip4Address)
	return tap, nil
}

func (iface *NetworkInterfaceTap) Configure() error {
	err := AddTap(iface.name, iface.IP4AddressString())
	if err != nil {
		return err
	}
	return nil
}

func (iface *NetworkInterfaceTap) Unconfigure() {
	DelLink(iface.name)
}

func NewNetNamespace(cfg NetDevConfig) (NetworkNamespace, error) {
	var networkNamespace NetworkNamespace
	networkNamespace.name = cfg["name"].(string)
	networkNamespace.category = "netns"
	return networkNamespace, nil
}

func (ns *NetworkNamespace) Configure() error {
	return addDelNetns(ns.name, true)
}

func (ns *NetworkNamespace) Unconfigure() {
	addDelNetns(ns.name, false)
}

func NewBridge(cfg NetDevConfig) (NetworkBridge, error) {
	var bridge NetworkBridge
	bridge.name = cfg["name"].(string)
	bridge.category = "bridge"
	for _, v := range cfg["interfaces"].([]interface{}) {
		bridge.interfaces = append(bridge.interfaces, v.(string))
	}

	bridge.networkNamespace = ""
	if netns, ok := cfg["netns"]; ok {
		bridge.networkNamespace = netns.(string)
	}
	return bridge, nil
}

func (b *NetworkBridge) Configure() error {
	return AddBridge(b.name, b.interfaces, b.networkNamespace)
}

func (b *NetworkBridge) Unconfigure() {
	DelBridge(b.name, b.networkNamespace)
}

func DelBridge(brName, ns string) error {
	err := SetDevDown(brName, ns)
	if err != err {
		return err
	}

	err = addDelBridge(brName, ns, false)
	if err != nil {
		return err
	}

	return nil
}

func configureBridge(dev NetDevConfig) error {
	var ifs []string
	for _, v := range dev["interfaces"].([]interface{}) {
		ifs = append(ifs, v.(string))
	}
	return AddBridge(dev["name"].(string), ifs, dev["netns"].(string))
}

func configureTap(dev NetDevConfig) error {
	return AddTap(dev["name"].(string), dev["ip4"].(string))
}

func SetDevUp(dev, ns string) error {
	return setDevUpDown(dev, ns, true)
}

func SetDevDown(dev, ns string) error {
	return setDevUpDown(dev, ns, false)
}

func AddTap(ifName, ifAddress string) error {
	cmd := exec.Command("ip", "tuntap", "add", ifName, "mode", "tap")
	o, err := cmd.CombinedOutput()
	if err != nil {
		s := fmt.Sprintf("error creating tap %s: %v: %s", ifName, err, string(o))
		return errors.New(s)
	}

	cmd = exec.Command("ip", "addr", "add", ifAddress, "dev", ifName)
	err = cmd.Run()
	if err != nil {
		DelLink(ifName)
		s := fmt.Sprintf("error setting addr for tap %s: %v", ifName, err)
		return errors.New(s)
	}

	err = SetDevUp(ifName, "")
	if err != nil {
		DelLink(ifName)
		return err
	}
	return nil
}

func DelLink(ifName string) {
	cmd := exec.Command("ip", "link", "del", ifName)
	cmd.Run()
}

func setDevUpDown(dev, ns string, isUp bool) error {
	var op string
	if isUp {
		op = "up"
	} else {
		op = "down"
	}
	c := []string{"ip", "link", "set", "dev", dev, op}
	cmd := appendNetns(c, ns)
	err := cmd.Run()
	if err != nil {
		s := fmt.Sprintf("error bringing %s device %s!", dev, op)
		return errors.New(s)
	}
	return nil
}

func AddVethPair(ifName, peerName string) error {
	cmd := exec.Command("ip", "link", "add", ifName, "type", "veth", "peer", "name", peerName)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("creating veth pair '%v/%v' failed: %v", ifName, peerName, err)
	}
	err = SetDevUp(ifName, "")
	if err != nil {
		return fmt.Errorf("set link up failed: %v", err)
	}
	err = SetDevUp(peerName, "")
	if err != nil {
		return fmt.Errorf("set link up failed: %v", err)
	}
	return nil
}

func addDelNetns(name string, isAdd bool) error {
	var op string
	if isAdd {
		op = "add"
	} else {
		op = "del"
	}
	cmd := exec.Command("ip", "netns", op, name)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return errors.New("add/del netns failed")
	}
	return nil
}

func AddNetns(nsName string) error {
	return addDelNetns(nsName, true)
}

func DelNetns(nsName string) error {
	return addDelNetns(nsName, false)
}

func LinkSetNetns(ifName, ns string) error {
	cmd := exec.Command("ip", "link", "set", "dev", ifName, "up", "netns", ns)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error setting device '%s' to netns '%s: %v", ifName, ns, err)
	}
	return nil
}

func NewCommand(s []string, ns string) *exec.Cmd {
	return appendNetns(s, ns)
}

func appendNetns(s []string, ns string) *exec.Cmd {
	var cmd *exec.Cmd
	if ns == "" {
		// use default namespace
		cmd = exec.Command(s[0], s[1:]...)
	} else {
		var args = []string{"netns", "exec", ns}
		args = append(args, s[:]...)
		cmd = exec.Command("ip", args...)
	}
	return cmd
}

func addDelBridge(brName, ns string, isAdd bool) error {
	var op string
	if isAdd {
		op = "addbr"
	} else {
		op = "delbr"
	}
	var c = []string{"brctl", op, brName}
	cmd := appendNetns(c, ns)
	err := cmd.Run()
	if err != nil {
		s := fmt.Sprintf("%s %s failed!", op, brName)
		return errors.New(s)
	}
	return nil
}

func AddBridge(brName string, ifs []string, ns string) error {
	err := addDelBridge(brName, ns, true)
	if err != nil {
		return err
	}

	for _, v := range ifs {
		c := []string{"brctl", "addif", brName, v}
		cmd := appendNetns(c, ns)
		err = cmd.Run()
		if err != nil {
			s := fmt.Sprintf("error adding %s to bridge %s: %v", v, brName, err)
			return errors.New(s)
		}
	}
	err = SetDevUp(brName, ns)
	if err != nil {
		return err
	}
	return nil
}
