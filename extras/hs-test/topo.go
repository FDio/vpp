package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type NetDevConfig map[string]interface{}

type YamlTopology struct {
	Devices []NetDevConfig `yaml:"devices"`
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

func configureDevice(dev NetDevConfig) error {
	var peerNs string

	t := dev["type"]
	if t == "netns" {
		return AddNetns(dev["name"].(string))
	} else if t == "veth" {
		peer := dev["peer"].(NetDevConfig)
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

/*
func (t *YamlTopology) Unconfigure() {
	for i := len(t.Devices) - 1; i >= 0; i-- {
		removeDevice(t.Devices[i])
	}
}

func (t *YamlTopology) Configure() error {
	for _, dev := range t.Devices {
		err := dev.Configure()
		// err := configureDevice(dev)
		if err != nil {
			return fmt.Errorf("error while configuring device '%s': %v", dev["name"], err)
		}
	}
	return nil
}
*/

func convertToNetConfig(t *YamlTopology) (*NetTopology, error) {
	var topology NetTopology
	for _, dev := range t.Devices {
		topology = append(topology, NewNetConfig(dev))
	}
	return &topology, nil
}

func loadTopoFile(topoName string) (*NetTopology, error) {
	var yamlTopo YamlTopology

	data, err := ioutil.ReadFile(topoName)
	if err != nil {
		return nil, fmt.Errorf("read error: %v", err)
	}

	err = yaml.Unmarshal(data, &yamlTopo)
	if err != nil {
		return nil, fmt.Errorf("error parsing topology data: %v", err)
	}

	return convertToNetConfig(&yamlTopo)
}

func LoadTopology(path, topoName string) (*NetTopology, error) {
	dir, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	files, err := dir.Readdir(0)
	if err != nil {
		return nil, err
	}

	for i := range files {
		file := files[i]
		fileName := file.Name()

		// cut off file extension
		f := strings.Split(fileName, ".")[0]
		if f == topoName {
			return loadTopoFile(path + fileName)
		}
	}
	return nil, fmt.Errorf("topology '%s' not found", topoName)
}
