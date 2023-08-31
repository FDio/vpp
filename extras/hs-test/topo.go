package main

import (
	"fmt"
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
