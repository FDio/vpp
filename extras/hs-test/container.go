package main

import (
	"fmt"

	"github.com/edwarnicke/exechelper"
)

type Volume struct {
	name string
	path string
}

type Container struct {
	name    string
	volumes []*Volume
}

func (c *Container) run() error {
	if c.name == "" {
		return fmt.Errorf("create volume failed: container name is blank")
	}

	exechelper.Run(fmt.Sprintf("mkdir -p /tmp/%s/sync", c.name))
	syncPath := fmt.Sprintf("-v /tmp/%s/sync:/tmp/sync", c.name)
	cmd := "docker run --cap-add=all -d --privileged --network host --rm "
	cmd += syncPath
	cmd += c.getVolumes() 
	cmd += " --name " + c.name + " hs-test/vpp"
	fmt.Println(cmd)
	err := exechelper.Run(cmd)
	if err != nil {
		return fmt.Errorf("create volume failed: %s", err)
	}

	return nil
}

func (c *Container) addVolume(name string, containerPath string) {
	c.volumes = append(c.volumes, &Volume{name, containerPath})
}

func (c *Container) getVolumes() string {
	dockerOption := ""

	if len(c.volumes) > 0 {
		for _, volume := range c.volumes {
			dockerOption += fmt.Sprintf(" -v %s:%s", volume.name, volume.path)
		}
	}

	return dockerOption
}

func (c *Container) stop() error {
	return exechelper.Run("docker stop " + c.name)
}
