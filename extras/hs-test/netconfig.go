package main

import (
	"errors"
	"fmt"
	"os/exec"

	"go.fd.io/govpp/binapi/interface_types"
)

type NetType string

const (
	NetNs NetType = "netns"
	Veth  string  = "veth"
	Tap   string  = "tap"
)

type NetConfigBase struct {
	name     string
	category string // what else to call this when `type` is reserved?
}

func (b NetConfigBase) GetName() string {
	return b.name
}

func (b NetConfigBase) GetType() string {
	return b.category
}

type NetConfig interface {
	Configure() error
	Unconfigure()
	GetName() string
	GetType() string
}

type NetConfigConstructor func(cfg NetDevConfig) (NetConfig, error)

var netConfigConstructors = map[string]NetConfigConstructor{
	"netns":  NewNetNamespace,
	"bridge": NewBridge,
	"veth":   NewVeth,
	"tap":    NewTap,
}

type NetworkInterfaceVeth struct {
	NetConfigBase
	index                interface_types.InterfaceIndex
	peerNetworkNamespace string
	peerName             string
	peerIp4Address       string
	ip4Address           string
	hwAddress            string
}

func (iface NetworkInterfaceVeth) Configure() error {
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

	if iface.peerIp4Address != "" {
		err = AddAddress(iface.peerName, iface.peerIp4Address, iface.peerNetworkNamespace)
		if err != nil {
			return fmt.Errorf("failed to add configure address for %s: %v", iface.peerName, err)
		}
	}
	return nil
}

func (iface NetworkInterfaceVeth) Unconfigure() {
	DelLink(iface.name)
}

type NetworkInterfaceTap struct {
	NetConfigBase
	index      interface_types.InterfaceIndex
	ip4Address string
}

func (iface NetworkInterfaceTap) Configure() error {
	err := AddTap(iface.name, iface.ip4Address)
	if err != nil {
		return nil
	}
	return nil
}

func (iface NetworkInterfaceTap) Unconfigure() {
	DelLink(iface.name)
}

type NetworkNamespace struct {
	NetConfigBase
}

func (ns NetworkNamespace) Configure() error {
	return addDelNetns(ns.name, true)
}

func (ns NetworkNamespace) Unconfigure() {
	addDelNetns(ns.name, false)
}

type NetworkBridge struct {
	NetConfigBase
	networkNamespace string
	interfaces       []string
}

func (b NetworkBridge) Configure() error {
	return AddBridge(b.name, b.interfaces, b.networkNamespace)
}

func (b NetworkBridge) Unconfigure() {
	DelBridge(b.name, b.networkNamespace)
}

type NetTopology []NetConfig

func (t *NetTopology) Configure() error {
	for _, c := range *t {
		err := c.Configure()
		if err != nil {
			return err
		}
	}
	return nil
}

func (t *NetTopology) Unconfigure() {
	for _, c := range *t {
		c.Unconfigure()
	}
}

func newConfigFn(cfg NetDevConfig) func() error {
	t := cfg["type"]
	if t == "netns" {
		return func() error { return AddNetns(cfg["name"].(string)) }
	} else if t == "veth" {
		return func() error {
			var peerNs string
			peer := cfg["peer"].(NetDevConfig)
			peerName := peer["name"].(string)
			err := AddVethPair(cfg["name"].(string), peerName)
			if err != nil {
				return err
			}

			if peer["netns"] != nil {
				peerNs = peer["netns"].(string)
				if peerNs != "" {
					err := LinkSetNetns(peerName, peerNs)
					if err != nil {
						return err
					}
				}
			}
			if peer["ip4"] != nil {
				err = AddAddress(peerName, peer["ip4"].(string), peerNs)
				if err != nil {
					return fmt.Errorf("failed to add configure address for %s: %v", peerName, err)
				}
			}
			return nil
		}
	} else if t == "bridge" {
		return func() error { return configureBridge(cfg) }
	} else if t == "tap" {
		return func() error { return configureTap(cfg) }
	}
	return nil
}

func newUnconfigFn(cfg NetDevConfig) func() {
	t := cfg["type"]
	name := cfg["name"].(string)

	if t == "tap" {
		return func() { DelLink(name) }
	} else if t == "netns" {
		return func() { DelNetns(name) }
	} else if t == "veth" {
		return func() { DelLink(name) }
	} else if t == "bridge" {
		return func() { DelBridge(name, cfg["netns"].(string)) }
	}
	return nil
}

func NewNetNamespace(cfg NetDevConfig) (NetConfig, error) {
	var networkNamespace NetworkNamespace
	networkNamespace.name = cfg["name"].(string)
	networkNamespace.category = "netns"
	return networkNamespace, nil
}

func NewBridge(cfg NetDevConfig) (NetConfig, error) {
	var bridge NetworkBridge
	bridge.name = cfg["name"].(string)
	bridge.category = "bridge"
	for _, v := range cfg["interfaces"].([]interface{}) {
		bridge.interfaces = append(bridge.interfaces, v.(string))
	}
	bridge.networkNamespace = cfg["netns"].(string)
	return bridge, nil
}

func NewVeth(cfg NetDevConfig) (NetConfig, error) {
	var veth NetworkInterfaceVeth
	veth.name = cfg["name"].(string)
	veth.category = "veth"

	if cfg["preset-ip4-address"] != nil {
		veth.ip4Address = cfg["preset-ip4-address"].(string)
	}

	if cfg["preset-hw-address"] != nil {
		veth.hwAddress = cfg["preset-hw-address"].(string)
	}

	peer := cfg["peer"].(NetDevConfig)

	veth.peerName = peer["name"].(string)

	if peer["netns"] != nil {
		veth.peerNetworkNamespace = peer["netns"].(string)
	}

	if peer["ip4"] != nil {
		veth.peerIp4Address = peer["ip4"].(string)
	}

	return veth, nil
}

func NewTap(cfg NetDevConfig) (NetConfig, error) {
	var tap NetworkInterfaceVeth
	tap.name = cfg["name"].(string)
	tap.category = "tap"
	tap.ip4Address = cfg["ip4"].(string)
	return tap, nil
}

func NewNetConfig(cfg NetDevConfig) (NetConfig, error) {
	// TODO check first if type is known in the map
	constructor := netConfigConstructors[cfg["type"].(string)]

	// nc.Configure = newConfigFn(cfg)
	// nc.Unconfigure = newUnconfigFn(cfg)

	return constructor(cfg)
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
		return fmt.Errorf("creating veth pair failed: %v", err)
	}
	err = SetDevUp(ifName, "")
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
