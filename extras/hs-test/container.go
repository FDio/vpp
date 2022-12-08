package main

import (
	"fmt"
	"os"

	"github.com/edwarnicke/exechelper"
)

type Container struct {
	name    string
	volume  string
}

func (c *Container) run() error {
	if c.name == "" {
		return fmt.Errorf("create volume failed: container name is blank")
	}

	exechelper.Run(fmt.Sprintf("mkdir -p /tmp/%s/sync", c.name))
	syncPath := fmt.Sprintf(" -v /tmp/%s/sync:/tmp/sync", c.name)
	cmd := "docker run --cap-add=all -d --privileged --network host --rm"
	cmd += syncPath
	cmd += c.getVolumeAsCliOption()
	cmd += " --name " + c.name + " hs-test/vpp"
	fmt.Println(cmd)
	err := exechelper.Run(cmd)
	if err != nil {
		return fmt.Errorf("create volume failed: %s", err)
	}

	return nil
}

func (c *Container) setVolume(name string) {
	c.volume = name
}

func (c *Container) getVolumeAsCliOption() string {
	cliOption := ""

	if len(c.volume) > 0 {
		cliOption = fmt.Sprintf(" -v %s:%s", c.volume, c.getWorkDir())
	}

	return cliOption
}

func (c *Container) getWorkDir() string {
	return "/tmp/" + c.name
}

func (c *Container) stop() error {
	return exechelper.Run("docker stop " + c.name)
}

func (c *Container) hstExec(args string) (string, error) {
	syncFile := fmt.Sprintf("/tmp/%s/sync/rc", c.name)
	os.Remove(syncFile)

	cmd := fmt.Sprintf(
		"docker exec -d --workdir=\"%s\" %s hs-test %s",
		c.getWorkDir(),
		c.name,
		args)
	err := exechelper.Run(cmd)
	if err != nil {
		return "", err
	}

	res, err := waitForSyncFile(syncFile)

	if err != nil {
		return "", fmt.Errorf("failed to read sync file while executing 'hs-test %s': %v", args, err)
	}

	o := res.StdOutput + res.ErrOutput
	if res.Code != 0 {
		return o, fmt.Errorf("cmd resulted in non-zero value %d: %s", res.Code, res.Desc)
	}
	return o, err
}
