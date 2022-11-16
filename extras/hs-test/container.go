package main

import (
	"fmt"

	"github.com/edwarnicke/exechelper"
)

type Container struct {
	name string
}

func (c *Container) getName() string {
	return c.name
}

func (c *Container) start() error {
	if c.getName() == "" {
		return fmt.Errorf("create volume failed: container name is blank")
	}

	exechelper.Run(fmt.Sprintf("mkdir -p /tmp/%s/sync", c.getName()))
	syncPath := fmt.Sprintf("-v /tmp/%s/sync:/tmp/sync", c.getName())
	cmd := "docker run --cap-add=all -d --privileged --network host --rm "
	cmd += syncPath
	cmd += " --name " + c.getName() + " hs-test/vpp"
	fmt.Println(cmd)
	err := exechelper.Run(cmd)
	if err != nil {
		return fmt.Errorf("create volume failed: %s", err)
	}

	return nil
}

