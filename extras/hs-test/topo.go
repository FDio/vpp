package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"gopkg.in/yaml.v3"
)

type Item map[string]interface{}

type TopoBase struct {
	data map[string]*Topo
}

type Topo struct {
	Devices []interface{} `yaml:"devices"`
}

type Device struct {
	Name  string
	Type  string
	Netns string
}

type Veth struct {
	Device
	Peer Device
}

type Bridge struct {
	Device
	Interfaces []string
}

func (c *Topo) Parse(data []byte) error {
	return yaml.Unmarshal(data, c)
}

func configureBridge(dev Item) error {
	var ifs []string
	for _, v := range dev["interfaces"].([]interface{}) {
		ifs = append(ifs, v.(string))
	}
	return AddBridge(dev["name"].(string), ifs, dev["netns"].(string))
}

func configureTap(dev Item) error {
	return AddTap(dev["name"].(string), dev["ip4"].(string))
}

func AddAddress(device, address, ns string) error {
	c := []string{"ip", "addr", "add", address, "dev", device}
	cmd := appendNetns(c, ns)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("failed to set ip address for %s: %v", device, err)
	}
	return nil
}

func configureDevice(dev Item) error {
	var peerNs string

	t := dev["type"]
	if t == "netns" {
		return AddNetns(dev["name"].(string))
	} else if t == "veth" {
		peer := dev["peer"].(map[string]interface{})
		peerName := peer["name"].(string)
		err := AddVethPair(dev["name"].(string), peerName)
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
	} else if t == "bridge" {
		return configureBridge(dev)
	} else if t == "tap" {
		return configureTap(dev)
	}
	return fmt.Errorf("unknown device type %s", t)
}

func (t *Topo) Configure() error {
	for _, dev := range t.Devices {
		d := dev.(map[string]interface{})
		err := configureDevice(d)
		if err != nil {
			return fmt.Errorf("error while configuring device '%s': %v", d["name"], err)
		}
	}
	return nil
}

func removeDevice(dev Item) {
	t := dev["type"]
	name := dev["name"].(string)

	if t == "tap" {
		DelLink(name)
	} else if t == "netns" {
		DelNetns(name)
	} else if t == "veth" {
		DelLink(name)
	} else if t == "bridge" {
		DelBridge(name, dev["netns"].(string))
	}
}

func (t *Topo) RemoveConfig() {
	for i := len(t.Devices) - 1; i >= 0; i-- {
		removeDevice(t.Devices[i].(map[string]interface{}))
	}
}

func (t *TopoBase) FindTopoByName(name string) *Topo {
	return t.data[name]
}

func (t *TopoBase) LoadTopologies(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()

	files, err := dir.Readdir(0)
	if err != nil {
		return err
	}

	t.data = make(map[string]*Topo)
	for i := range files {
		file := files[i]
		fileName := file.Name()

		// read topologies from directory
		topo, err := loadTopoFile(path + fileName)
		if err != nil {
			fmt.Println("failed to read topo file ", fileName)
			return err
		}
		// cut off file extension
		key := strings.Split(fileName, ".")[0]

		t.data[key] = topo
	}
	return nil
}

func loadTopoFile(topoName string) (*Topo, error) {
	var config Topo

	data, err := ioutil.ReadFile(topoName)
	if err != nil {
		return nil, fmt.Errorf("read error: %v", err)
	}

	if err := config.Parse(data); err != nil {
		return nil, fmt.Errorf("error parsing topology data: %v", err)
	}
	return &config, nil
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

func SetDevUp(dev, ns string) error {
	return setDevUpDown(dev, ns, true)
}

func SetDevDown(dev, ns string) error {
	return setDevUpDown(dev, ns, false)
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
