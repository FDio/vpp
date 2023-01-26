package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type NetDevConfig map[string]interface{}
type ContainerConfig map[string]interface{}
type VolumeConfig map[string]interface{}

type YamlTopology struct {
	Devices    []NetDevConfig    `yaml:"devices"`
	Containers []ContainerConfig `yaml:"containers"`
	Volumes    []VolumeConfig    `yaml:"volumes"`
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

func convertToNetConfig(t *YamlTopology) (*NetTopology, error) {
	var topology NetTopology
	// 	for _, dev := range t.Devices {
	// 		//topology = append(topology, NewNetConfig(dev)) // TODO fix this by removing it
	// 	}
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
