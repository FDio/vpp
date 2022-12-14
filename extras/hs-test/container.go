package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/edwarnicke/exechelper"
)

type Volume struct {
	hostDir      string
	containerDir string
}

type Container struct {
	isOptional bool
	name       string
	image      string
	workDir    string
	volumes    map[string]Volume
	envVars    map[string]string
}

func NewContainer(yamlInput ContainerConfig) (*Container, error) {
	containerName := yamlInput["name"].(string)
	if len(containerName) == 0 {
		err := fmt.Errorf("container name must not be blank")
		return nil, err
	}

	var container = new(Container)
	container.volumes = make(map[string]Volume)
	container.envVars = make(map[string]string)
	container.name = containerName

	if image, ok := yamlInput["image"]; ok {
		container.image = image.(string)
	} else {
		container.image = "hs-test/vpp"
	}

	if isOptional, ok := yamlInput["is-optional"]; ok {
		container.isOptional = isOptional.(bool)
	} else {
		container.isOptional = false
	}

	if _, ok := yamlInput["volumes"]; ok {
		r:= strings.NewReplacer("$HST_DIR", workDir)
		for _, volu := range yamlInput["volumes"].([]interface{}) {
			volumeMap := volu.(ContainerConfig)
			hostDir := r.Replace(volumeMap["host-dir"].(string))
			containerDir := volumeMap["container-dir"].(string)
			container.addVolume(hostDir, containerDir)

			if isDefaultWorkDir, ok := volumeMap["is-default-work-dir"]; ok &&
			isDefaultWorkDir.(bool) &&
			len(container.workDir) == 0 {
				container.workDir = containerDir
			}

		}
	}

	if _, ok := yamlInput["vars"]; ok {
		for _, envVar := range yamlInput["vars"].([]interface{}) {
			container.addEnvVar(envVar)
		}
	}
	return container, nil
}

func (c *Container) run() error {
	if c.name == "" {
		return fmt.Errorf("create volume failed: container name is blank")
	}

	exechelper.Run(fmt.Sprintf("mkdir -p /tmp/%s/sync", c.name))
	syncPath := fmt.Sprintf(" -v %s:/tmp/sync", c.getSyncPath())
	cmd := "docker run --cap-add=all -d --privileged --network host --rm"
	cmd += syncPath
	cmd += c.getVolumesAsCliOption()
	cmd += c.getEnvVarsAsCliOption()
	cmd += " --name " + c.name + " " + c.image
	fmt.Println(cmd)
	err := exechelper.Run(cmd)
	if err != nil {
		return fmt.Errorf("container run failed: %s", err)
	}

	return nil
}

func (c *Container) addVolume(hostDir string, containerDir string) {
	var volume Volume
	volume.hostDir = hostDir
	volume.containerDir = containerDir
	c.volumes[hostDir] = volume
}

func (c *Container) getVolumeByHostDir(hostDir string) Volume {
	return c.volumes[hostDir]
}

func (c *Container) getVolumesAsCliOption() string {
	cliOption := ""

	if len(c.volumes) > 0 {
		for _, volume := range c.volumes {
			cliOption += fmt.Sprintf(" -v %s:%s", volume.hostDir, volume.containerDir)
		}
	}

	return cliOption
}

func (c *Container) getWorkDirAsCliOption() string {
	if len(c.workDir) == 0 {
		return ""
	}
	return fmt.Sprintf(" --workdir=\"%s\"", c.workDir)
}

func (c *Container) addEnvVar(envVar interface{}) {
	envVarMap := envVar.(ContainerConfig)
	name := envVarMap["name"].(string)
	value := envVarMap["value"].(string)
	c.envVars[name] = value
}

func (c *Container) getEnvVarsAsCliOption() string {
	cliOption := ""
	if len(c.envVars) == 0 {
		return cliOption
	}

	for name, value := range c.envVars {
		cliOption += fmt.Sprintf(" -e %s=%s", name, value)
	}
	return cliOption
}

func (c *Container) getSyncPath() string {
	return fmt.Sprintf("/tmp/%s/sync", c.name)
}

func (c *Container) exec(command string) (string, error) {
	cliCommand := "docker exec -d " + c.name + " " + command
	byteOutput, err := exechelper.CombinedOutput(cliCommand)
	return string(byteOutput), err
}

func (c *Container) execAction(args string) (string, error) {
	syncFile := c.getSyncPath() + "/rc"
	os.Remove(syncFile)

	workDir := c.getWorkDirAsCliOption()
	cmd := fmt.Sprintf("docker exec -d %s %s hs-test %s",
		workDir,
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

func (c *Container) stop() error {
	return exechelper.Run("docker stop " + c.name)
}
