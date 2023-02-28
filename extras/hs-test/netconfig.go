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
	Cmd                  = exec.Cmd
	MacAddress           = ethernet_types.MacAddress
	AddressWithPrefix    = ip_types.AddressWithPrefix
	IP4AddressWithPrefix = ip_types.IP4AddressWithPrefix
	InterfaceIndex       = interface_types.InterfaceIndex

	NetConfig interface {
		configure() error
		unconfigure()
		getName() string
		getType() string
	}

	NetConfigBase struct {
		name     string
		category string // what else to call this when `type` is reserved?
	}

	NetInterface struct {
		NetConfigBase
		addresser        *Addresser
		ip4Address       string // this will have form 10.10.10.1/24
		index            InterfaceIndex
		hwAddress        MacAddress
		networkNamespace string
		networkNumber    int
		peer             *NetInterface
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

type InterfaceAdder func(n *NetInterface) *Cmd

var (
	ipCommandMap = map[string]InterfaceAdder{
		Veth: func(n *NetInterface) *Cmd {
			return exec.Command("ip", "link", "add", n.name, "type", "veth", "peer", "name", n.peer.name)
		},
		Tap: func(n *NetInterface) *Cmd {
			return exec.Command("ip", "tuntap", "add", n.name, "mode", "tap")
		},
	}
)

func newNetworkInterface(cfg NetDevConfig, a *Addresser) (*NetInterface, error) {
	var newInterface *NetInterface = &NetInterface{}
	var err error
	newInterface.addresser = a
	newInterface.name = cfg["name"].(string)
	newInterface.networkNumber = defaultNetworkNumber

	if interfaceType, ok := cfg["type"]; ok {
		newInterface.category = interfaceType.(string)
	}

	if presetHwAddress, ok := cfg["preset-hw-address"]; ok {
		newInterface.hwAddress, err = ethernet_types.ParseMacAddress(presetHwAddress.(string))
		if err != nil {
			return &NetInterface{}, err
		}
	}

	if netns, ok := cfg["netns"]; ok {
		newInterface.networkNamespace = netns.(string)
	}

	if ip, ok := cfg["ip4"]; ok {
		if n, ok := ip.(NetDevConfig)["network"]; ok {
			newInterface.networkNumber = n.(int)
		}
		newInterface.ip4Address, err = newInterface.addresser.newIp4Address(
			newInterface.networkNumber,
		)
		if err != nil {
			return &NetInterface{}, err
		}
	}

	if _, ok := cfg["peer"]; !ok {
		return newInterface, nil
	}

	peer := cfg["peer"].(NetDevConfig)

	if newInterface.peer, err = newNetworkInterface(peer, a); err != nil {
		return &NetInterface{}, err
	}

	return newInterface, nil
}

func (n *NetInterface) configureUpState() error {
	err := setDevUp(n.getName(), "")
	if err != nil {
		return fmt.Errorf("set link up failed: %v", err)
	}
	return nil
}

func (n *NetInterface) configureNetworkNamespace() error {
	if n.networkNamespace != "" {
		err := linkSetNetns(n.name, n.networkNamespace)
		if err != nil {
			return err
		}
	}
	return nil
}

func (n *NetInterface) configureAddress() error {
	if n.ip4Address != "" {
		if err := addAddress(
			n.getName(),
			n.ip4Address,
			n.networkNamespace,
		); err != nil {
			return err
		}

	}
	return nil
}

func (n *NetInterface) configure() error {
	cmd := ipCommandMap[n.getType()](n)
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("creating interface '%v' failed: %v", n.getName(), err)
	}

	if err := n.configureUpState(); err != nil {
		return err
	}

	if err := n.configureNetworkNamespace(); err != nil {
		return err
	}

	if err := n.configureAddress(); err != nil {
		return err
	}

	if n.peer != nil && n.peer.name != "" {
		if err := n.getPeer().configureUpState(); err != nil {
			return err
		}

		if err := n.getPeer().configureNetworkNamespace(); err != nil {
			return err
		}

		if err := n.getPeer().configureAddress(); err != nil {
			return err
		}
	}

	return nil
}

func (n *NetInterface) unconfigure() {
	delLink(n.name)
}

func (n *NetInterface) getName() string {
	return n.name
}

func (n *NetInterface) getType() string {
	return n.category
}

func (n *NetInterface) setAddress(address string) {
	n.ip4Address = address
}

func (n *NetInterface) setIndex(index InterfaceIndex) {
	n.index = index
}

func (n *NetInterface) getIndex() InterfaceIndex {
	return n.index
}

func (n *NetInterface) addressWithPrefix() AddressWithPrefix {
	address, _ := ip_types.ParseAddressWithPrefix(n.ip4Address)
	return address
}

func (n *NetInterface) ip4AddressWithPrefix() IP4AddressWithPrefix {
	ip4Prefix, _ := ip_types.ParseIP4Prefix(n.ip4Address)
	ip4AddressWithPrefix := ip_types.IP4AddressWithPrefix(ip4Prefix)
	return ip4AddressWithPrefix
}

func (n *NetInterface) ip4AddressString() string {
	return strings.Split(n.ip4Address, "/")[0]
}

func (n *NetInterface) getHwAddress() MacAddress {
	return n.hwAddress
}

func (n *NetInterface) getPeer() *NetInterface {
	return n.peer
}

func (b *NetConfigBase) getName() string {
	return b.name
}

func (b *NetConfigBase) getType() string {
	return b.category
}

func newNetNamespace(cfg NetDevConfig) (NetworkNamespace, error) {
	var networkNamespace NetworkNamespace
	networkNamespace.name = cfg["name"].(string)
	networkNamespace.category = NetNs
	return networkNamespace, nil
}

func (ns *NetworkNamespace) configure() error {
	return addDelNetns(ns.name, true)
}

func (ns *NetworkNamespace) unconfigure() {
	addDelNetns(ns.name, false)
}

func newBridge(cfg NetDevConfig) (NetworkBridge, error) {
	var bridge NetworkBridge
	bridge.name = cfg["name"].(string)
	bridge.category = Bridge
	for _, v := range cfg["interfaces"].([]interface{}) {
		bridge.interfaces = append(bridge.interfaces, v.(string))
	}

	bridge.networkNamespace = ""
	if netns, ok := cfg["netns"]; ok {
		bridge.networkNamespace = netns.(string)
	}
	return bridge, nil
}

func (b *NetworkBridge) configure() error {
	return addBridge(b.name, b.interfaces, b.networkNamespace)
}

func (b *NetworkBridge) unconfigure() {
	delBridge(b.name, b.networkNamespace)
}

func delBridge(brName, ns string) error {
	err := setDevDown(brName, ns)
	if err != err {
		return err
	}

	err = addDelBridge(brName, ns, false)
	if err != nil {
		return err
	}

	return nil
}

func setDevUp(dev, ns string) error {
	return setDevUpDown(dev, ns, true)
}

func setDevDown(dev, ns string) error {
	return setDevUpDown(dev, ns, false)
}

func delLink(ifName string) {
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

func linkSetNetns(ifName, ns string) error {
	cmd := exec.Command("ip", "link", "set", "dev", ifName, "up", "netns", ns)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error setting device '%s' to netns '%s: %v", ifName, ns, err)
	}
	return nil
}

func newCommand(s []string, ns string) *exec.Cmd {
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

func addBridge(brName string, ifs []string, ns string) error {
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
	err = setDevUp(brName, ns)
	if err != nil {
		return err
	}
	return nil
}
