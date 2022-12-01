package main

import (
	"fmt"

	"github.com/edwarnicke/exechelper"
)

type Container struct {
	name string
}

func (c *Container) start() error {
	if c.name == "" {
		return fmt.Errorf("create volume failed: container name is blank")
	}

	exechelper.Run(fmt.Sprintf("mkdir -p /tmp/%s/sync", c.name))
	syncPath := fmt.Sprintf("-v /tmp/%s/sync:/tmp/sync", c.name)
	cmd := "docker run --cap-add=all -d --privileged --network host --rm "
	cmd += syncPath
	cmd += " --name " + c.name + " hs-test/vpp"
	fmt.Println(cmd)
	err := exechelper.Run(cmd)
	if err != nil {
		return fmt.Errorf("create volume failed: %s", err)
	}

	return nil
}

