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

func (c *Container) createVolume() {
	// TODO add assert that name is not nil
	fmt.Println("Create volume named: ", c.name)
}

func (c *Container) start() {
	fmt.Println("Start container: ", c.getName())

	exechelper.Run(fmt.Sprintf("mkdir -p /tmp/%s/sync", c.getName()))
	syncPath := fmt.Sprintf("-v /tmp/%s/sync:/tmp/sync", c.getName())
	cmd := "docker run --cap-add=all -d --privileged --network host --rm "
	cmd += syncPath
	// cmd += " " + args // TODO add ability to set based on other Container fields
	cmd += " --name " + c.getName() + " hs-test/vpp"
	fmt.Println(cmd)
	exechelper.Run(cmd)// TODO return error (even if blank)
}

//TODO add `setPersist`
