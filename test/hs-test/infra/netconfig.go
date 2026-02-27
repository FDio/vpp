package hst

import (
	"errors"
	"fmt"
	"net"
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
	IP6AddressWithPrefix = ip_types.IP6AddressWithPrefix
	InterfaceIndex       = interface_types.InterfaceIndex

	NetConfig interface {
		configure() error
		unconfigure() error
		Name() string
		Type() string
	}

	NetConfigBase struct {
		name     string
		category string // what else to call this when `type` is reserved?
	}

	NetInterface struct {
		NetConfigBase
		Ip4AddrAllocator *Ip4AddressAllocator
		Ip4Address       string
		Ip6AddrAllocator *Ip6AddressAllocator
		Ip6Address       string
		Index            InterfaceIndex
		HwAddress        MacAddress
		NetworkNamespace string
		NetworkNumber    int
		Host             *NetInterface
		vppName          string
	}

	NetworkNamespace struct {
		NetConfigBase
	}

	NetworkBridge struct {
		NetConfigBase
		NetworkNamespace string
		Interfaces       []string
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
			return exec.Command("ip", "link", "add", n.name, "type", "veth", "peer", "name", n.Host.name)
		},
		Tap: func(n *NetInterface) *Cmd {
			return exec.Command("ip", "tuntap", "add", n.name, "mode", "tap")
		},
	}
)

func newNetworkInterface(cfg NetDevConfig, a *Ip4AddressAllocator) (*NetInterface, error) {
	var newInterface *NetInterface = &NetInterface{}
	var err error
	newInterface.Ip4AddrAllocator = a
	newInterface.name = cfg["name"].(string)
	newInterface.NetworkNumber = DEFAULT_NETWORK_NUM

	if interfaceType, ok := cfg["type"]; ok {
		newInterface.category = interfaceType.(string)
	}

	if presetHwAddress, ok := cfg["preset-hw-address"]; ok {
		newInterface.HwAddress, err = ethernet_types.ParseMacAddress(presetHwAddress.(string))
		if err != nil {
			return &NetInterface{}, err
		}
	}

	if netns, ok := cfg["netns"]; ok {
		newInterface.NetworkNamespace = netns.(string)
	}

	if ip, ok := cfg["ip4"]; ok {
		if n, ok := ip.(NetDevConfig)["network"]; ok {
			newInterface.NetworkNumber = n.(int)
		}
		newInterface.Ip4Address, err = newInterface.Ip4AddrAllocator.NewIp4InterfaceAddress(
			newInterface.NetworkNumber,
		)
		if err != nil {
			return &NetInterface{}, err
		}
	}

	if _, ok := cfg["peer"]; !ok {
		return newInterface, nil
	}

	peer := cfg["peer"].(NetDevConfig)

	if newInterface.Host, err = newNetworkInterface(peer, a); err != nil {
		return &NetInterface{}, err
	}

	return newInterface, nil
}

func newNetworkInterface6(cfg NetDevConfig, a *Ip6AddressAllocator) (*NetInterface, error) {
	var newInterface *NetInterface = &NetInterface{}
	var err error
	newInterface.Ip6AddrAllocator = a
	newInterface.name = cfg["name"].(string)
	newInterface.NetworkNumber = DEFAULT_NETWORK_NUM

	if interfaceType, ok := cfg["type"]; ok {
		newInterface.category = interfaceType.(string)
	}

	if presetHwAddress, ok := cfg["preset-hw-address"]; ok {
		newInterface.HwAddress, err = ethernet_types.ParseMacAddress(presetHwAddress.(string))
		if err != nil {
			return &NetInterface{}, err
		}
	}

	if netns, ok := cfg["netns"]; ok {
		newInterface.NetworkNamespace = netns.(string)
	}

	if ip, ok := cfg["ip6"]; ok {
		if n, ok := ip.(NetDevConfig)["network"]; ok {
			newInterface.NetworkNumber = n.(int)
		}
		newInterface.Ip6Address, err = newInterface.Ip6AddrAllocator.NewIp6InterfaceAddress(
			newInterface.NetworkNumber,
		)
		if err != nil {
			return &NetInterface{}, err
		}
	}

	if _, ok := cfg["peer"]; !ok {
		return newInterface, nil
	}

	peer := cfg["peer"].(NetDevConfig)

	if newInterface.Host, err = newNetworkInterface6(peer, a); err != nil {
		return &NetInterface{}, err
	}

	return newInterface, nil
}

func (n *NetInterface) configureUpState() error {
	err := setDevUp(n.Name(), "")
	if err != nil {
		return fmt.Errorf("set link up failed: %v", err)
	}
	return nil
}

func (n *NetInterface) configureMultiQueue() error {
	// TODO multiqueue for tap
	if n.Type() != Veth {
		return nil
	}
	err := linkSetMultiQueue(n.Name())
	if err != nil {
		return fmt.Errorf("set multiqueue failed: %v", err)
	}
	return nil
}

func (n *NetInterface) configureNetworkNamespace() error {
	if n.NetworkNamespace != "" {
		err := linkSetNetns(n.name, n.NetworkNamespace)
		if err != nil {
			return err
		}
	}
	return nil
}

func (n *NetInterface) configureAddress() error {
	if n.Ip4Address != "" {
		if err := addAddress(
			n.Name(),
			n.Ip4Address,
			n.NetworkNamespace,
		); err != nil {
			return err
		}

	}
	return nil
}

func (n *NetInterface) configure() error {
	// n.configureUpState() has to be first, otherwise errors might occur
	cmd := ipCommandMap[n.Type()](n)
	Log(cmd.String())
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("creating interface '%v' failed: %v", n.Name(), err)
	}

	if err := n.configureUpState(); err != nil {
		return err
	}

	if err := n.configureMultiQueue(); err != nil {
		return err
	}

	if err := n.configureNetworkNamespace(); err != nil {
		return err
	}

	if err := n.configureAddress(); err != nil {
		return err
	}

	if n.Host != nil && n.Host.name != "" {
		netIntf, err := net.InterfaceByName(n.Host.name)
		if err == nil {
			n.Host.HwAddress, _ = ethernet_types.ParseMacAddress(netIntf.HardwareAddr.String())
		}

		if err := n.Host.configureUpState(); err != nil {
			return err
		}

		if err := n.Host.configureNetworkNamespace(); err != nil {
			return err
		}

		if err := n.Host.configureAddress(); err != nil {
			return err
		}
	}

	return nil
}

func (n *NetInterface) unconfigure() error {
	// Taps are non-persistent - they are *usually* deleted when VPP exits.
	// Try to delete them anyways and ignore the error if deletion by HST fails.
	if n.Type() == Tap {
		delLink(n.name)
		return nil
	}
	return delLink(n.name)
}

func (n *NetInterface) Name() string {
	return n.name
}

func (n *NetInterface) VppName() string {
	return n.vppName
}

func (n *NetInterface) Type() string {
	return n.category
}

func (n *NetInterface) AddressWithPrefix(IPv6 bool) AddressWithPrefix {
	var address ip_types.AddressWithPrefix
	if IPv6 {
		address, _ = ip_types.ParseAddressWithPrefix(n.Ip6Address)
	} else {
		address, _ = ip_types.ParseAddressWithPrefix(n.Ip4Address)
	}
	return address
}

func (n *NetInterface) Ip4AddressWithPrefix() IP4AddressWithPrefix {
	ip4Prefix, _ := ip_types.ParseIP4Prefix(n.Ip4Address)
	Ip4AddressWithPrefix := ip_types.IP4AddressWithPrefix(ip4Prefix)
	return Ip4AddressWithPrefix
}

func (n *NetInterface) Ip6AddressWithPrefix() IP6AddressWithPrefix {
	ip6Prefix, _ := ip_types.ParseIP6Prefix(n.Ip6Address)
	Ip6AddressWithPrefix := ip_types.IP6AddressWithPrefix(ip6Prefix)
	return Ip6AddressWithPrefix
}

func (n *NetInterface) Ip4AddressString() string {
	return strings.Split(n.Ip4Address, "/")[0]
}

func (n *NetInterface) Ip6AddressString() string {
	return strings.Split(n.Ip6Address, "/")[0]
}

func (b *NetConfigBase) Name() string {
	return b.name
}

func (b *NetConfigBase) Type() string {
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

func (ns *NetworkNamespace) unconfigure() error {
	return addDelNetns(ns.name, false)
}

func newBridge(cfg NetDevConfig) (NetworkBridge, error) {
	var bridge NetworkBridge
	bridge.name = cfg["name"].(string)
	bridge.category = Bridge
	for _, v := range cfg["interfaces"].([]interface{}) {
		bridge.Interfaces = append(bridge.Interfaces, v.(string))
	}

	bridge.NetworkNamespace = ""
	if netns, ok := cfg["netns"]; ok {
		bridge.NetworkNamespace = netns.(string)
	}
	return bridge, nil
}

func (b *NetworkBridge) configure() error {
	return addBridge(b.name, b.Interfaces, b.NetworkNamespace)
}

func (b *NetworkBridge) unconfigure() error {
	return delBridge(b.name, b.NetworkNamespace)
}

func delBridge(brName, ns string) error {
	err := setDevDown(brName, ns)
	if err != nil {
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

func delLink(ifName string) error {
	cmd := exec.Command("ip", "link", "del", ifName)
	Log(cmd.String())
	return cmd.Run()
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
	Log(cmd.String())
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error bringing %s device %s! (cmd: '%s')", dev, op, cmd)
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
	Log(cmd.String())
	_, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("add/del netns failed (cmd: '%s')", cmd)
	}
	return nil
}

func linkSetNetns(ifName, ns string) error {
	cmd := exec.Command("ip", "link", "set", "dev", ifName, "up", "netns", ns)
	Log(cmd.String())
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error setting device '%s' to netns '%s: %v", ifName, ns, err)
	}
	return nil
}

func linkSetMultiQueue(ifName string) error {
	cmd := exec.Command("ethtool", "-L", ifName, "rx", "4", "tx", "4")
	Log("configuring multiqueue for interface: %s", cmd.String())
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error configuring multiqueue '%s: %v", ifName, err)
	}
	return nil
}

func CommandInNetns(s []string, ns string) *exec.Cmd {
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
	Log(cmd.String())
	err := cmd.Run()
	if err != nil {
		s := fmt.Sprintf("%s %s failed! err: '%s'", op, brName, err)
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
		Log(cmd.String())
		err = cmd.Run()
		if err != nil {
			return fmt.Errorf("error adding %s to bridge %s: %s", v, brName, err)
		}
	}
	err = setDevUp(brName, ns)
	if err != nil {
		return err
	}
	return nil
}
