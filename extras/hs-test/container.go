package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/edwarnicke/exechelper"
)

type Volume struct {
	hostDir          string
	containerDir     string
	isDefaultWorkDir bool
}

type Container struct {
	isOptional       bool
	name             string
	image            string
	extraRunningArgs string
	volumes          map[string]Volume
	envVars          map[string]string
	vppInstance      *VppInstance
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

	if args, ok := yamlInput["extra-args"]; ok {
		container.extraRunningArgs = args.(string)
	} else {
		container.extraRunningArgs = ""
	}

	if isOptional, ok := yamlInput["is-optional"]; ok {
		container.isOptional = isOptional.(bool)
	} else {
		container.isOptional = false
	}

	if _, ok := yamlInput["volumes"]; ok {
		r := strings.NewReplacer("$HST_DIR", workDir)
		for _, volu := range yamlInput["volumes"].([]interface{}) {
			volumeMap := volu.(ContainerConfig)
			hostDir := r.Replace(volumeMap["host-dir"].(string))
			containerDir := volumeMap["container-dir"].(string)
			isDefaultWorkDir := false

			if isDefault, ok := volumeMap["is-default-work-dir"]; ok {
				isDefaultWorkDir = isDefault.(bool)
			}

			container.addVolume(hostDir, containerDir, isDefaultWorkDir)

		}
	}

	if _, ok := yamlInput["vars"]; ok {
		for _, envVar := range yamlInput["vars"].([]interface{}) {
			container.addEnvVar(envVar)
		}
	}
	return container, nil
}

func (c *Container) getWorkDirVolume() (res Volume, exists bool) {
	for _, v := range c.volumes {
		if v.isDefaultWorkDir {
			res = v
			exists = true
			return
		}
	}
	return
}

func (c *Container) GetHostWorkDir() (res string) {
	if v, ok := c.getWorkDirVolume(); ok {
		res = v.hostDir
	}
	return
}

func (c *Container) GetContainerWorkDir() (res string) {
	if v, ok := c.getWorkDirVolume(); ok {
		res = v.containerDir
	}
	return
}

func (c *Container) getRunCommand() string {
	syncPath := fmt.Sprintf(" -v %s:/tmp/sync", c.getSyncPath())
	cmd := "docker run --cap-add=all -d --privileged --network host --rm"
	cmd += syncPath
	cmd += c.getVolumesAsCliOption()
	cmd += c.getEnvVarsAsCliOption()
	cmd += " --name " + c.name + " " + c.image + " " + c.extraRunningArgs
	return cmd
}

func (c *Container) run() error {
	if c.name == "" {
		return fmt.Errorf("run container failed: name is blank")
	}

	exechelper.Run(fmt.Sprintf("mkdir -p /tmp/%s/sync", c.name))
	cmd := c.getRunCommand()
	err := exechelper.Run(cmd)
	if err != nil {
		return fmt.Errorf("container run failed: %s", err)
	}

	return nil
}

func (c *Container) addVolume(hostDir string, containerDir string, isDefaultWorkDir bool) { // TODO make a constructor and pass existing object instead of parameters
	var volume Volume
	volume.hostDir = hostDir
	volume.containerDir = containerDir
	volume.isDefaultWorkDir = isDefaultWorkDir
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
	if _, ok := c.getWorkDirVolume(); ok {
		return fmt.Sprintf(" --workdir=\"%s\"", c.GetContainerWorkDir())
	}
	return ""
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

func (c *Container) newVppInstance(additionalConfig ...Stanza) (*VppInstance, error) {
	vppConfig := new(VppConfig)
	vppConfig.cliSocketFilePath = defaultCliSocketFilePath
	if len(additionalConfig) > 0 {
		vppConfig.additionalConfig = additionalConfig[0]
	}

	vpp := new(VppInstance)
	vpp.container = c
	vpp.config = vppConfig

	c.vppInstance = vpp

	return vpp, nil
}

func (c *Container) copy(sourceFileName string, targetFileName string) error {
	cmd := exec.Command("docker", "cp", sourceFileName, c.name+":"+targetFileName)
	err := cmd.Run()
	if err != nil {
		return err
	}
	return nil
}

// TODO does CombinedOutput contain anything if `docker exec` is executed as detached?
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
	fmt.Println("Stopping container:", c.name)
	if c.vppInstance != nil {
		fmt.Printf("VPP instance address: %p\n", c.vppInstance)
		fmt.Printf("Channel address: %p\n", &c.vppInstance.apiChannel)
		if c.vppInstance.apiChannel != nil {
			c.vppInstance.disconnect()
		}
	}
	// TODO remove volumes after all VPPs are disconnected
	//	for _, volume := range c.volumes {
	//		fmt.Println("Deleting volume:", volume.hostDir)
	//		os.RemoveAll(volume.hostDir)
	//	}
	return exechelper.Run("docker stop " + c.name + " -t 0")
}
