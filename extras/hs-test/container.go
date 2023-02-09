package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/edwarnicke/exechelper"
)

const (
	logDir string = "/tmp/hs-test/"
)

var (
	workDir, _ = os.Getwd()
)

type Volume struct {
	hostDir          string
	containerDir     string
	isDefaultWorkDir bool
}

type Container struct {
	suite            *HstSuite
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
			envVarMap := envVar.(ContainerConfig)
			name := envVarMap["name"].(string)
			value := envVarMap["value"].(string)
			container.addEnvVar(name, value)
		}
	}
	return container, nil
}

func (c *Container) Suite() *HstSuite {
	return c.suite
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

func (c *Container) getContainerArguments() string {
	args := "--cap-add=all --privileged --network host --rm"
	args += c.getVolumesAsCliOption()
	args += c.getEnvVarsAsCliOption()
	args += " --name " + c.name + " " + c.image
	return args
}

func (c *Container) create() {
	cmd := "docker create " + c.getContainerArguments()
	c.Suite().log(cmd)
	exechelper.Run(cmd)
}

func (c *Container) start() {
	cmd := "docker start " + c.name
	c.Suite().log(cmd)
	exechelper.Run(cmd)
}

func (c *Container) run() error {
	if c.name == "" {
		return fmt.Errorf("run container failed: name is blank")
	}

	cmd := "docker run -d " + c.getContainerArguments() + " " + c.extraRunningArgs
	c.Suite().log(cmd)
	err := exechelper.Run(cmd)
	if err != nil {
		return fmt.Errorf("container run failed: %s", err)
	}

	return nil
}

func (c *Container) addVolume(hostDir string, containerDir string, isDefaultWorkDir bool) {
	var volume Volume
	volume.hostDir = hostDir
	volume.containerDir = containerDir
	volume.isDefaultWorkDir = isDefaultWorkDir
	c.volumes[hostDir] = volume
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

func (c *Container) addEnvVar(name string, value string) {
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

func (c *Container) newVppInstance(additionalConfig ...Stanza) (*VppInstance, error) {
	vpp := new(VppInstance)
	vpp.container = c

	if len(additionalConfig) > 0 {
		vpp.additionalConfig = additionalConfig[0]
	}

	c.vppInstance = vpp

	return vpp, nil
}

func (c *Container) copy(sourceFileName string, targetFileName string) error {
	cmd := exec.Command("docker", "cp", sourceFileName, c.name+":"+targetFileName)
	c.Suite().log(cmd.String())
	return cmd.Run()
}

func (c *Container) createFile(destFileName string, content string) error {
	f, err := os.CreateTemp("/tmp", "hst-config")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())

	if _, err := f.Write([]byte(content)); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	c.copy(f.Name(), destFileName)
	return nil
}

/*
 * Executes in detached mode so that the started application can continue to run
 * without blocking execution of test
 */
func (c *Container) execServer(command string, arguments ...any) {
	serverCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := "docker exec -d" + c.getEnvVarsAsCliOption() +
		" " + c.name + " " + serverCommand
	c.Suite().T().Helper()
	c.Suite().log(containerExecCommand)
	c.Suite().assertNil(exechelper.Run(containerExecCommand))
}

func (c *Container) exec(command string, arguments ...any) string {
	cliCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := "docker exec" + c.getEnvVarsAsCliOption() +
		" " + c.name + " " + cliCommand
	c.Suite().T().Helper()
	c.Suite().log(containerExecCommand)
	byteOutput, err := exechelper.CombinedOutput(containerExecCommand)
	c.Suite().assertNil(err)
	return string(byteOutput)
}

func (c *Container) getLogDirPath() string {
	testId := c.Suite().getTestId()
	testName := c.Suite().T().Name()
	logDirPath := logDir + testName + "/" + testId + "/"

	cmd := exec.Command("mkdir", "-p", logDirPath)
	if err := cmd.Run(); err != nil {
		c.Suite().T().Fatalf("mkdir error: %v", err)
	}

	return logDirPath
}

func (c *Container) saveLogs() {
	cmd := exec.Command("docker", "inspect", "--format='{{.State.Status}}'", c.name)
	if output, _ := cmd.CombinedOutput(); !strings.Contains(string(output), "running") {
		return
	}

	testLogFilePath := c.getLogDirPath() + "container-" + c.name + ".log"

	cmd = exec.Command("docker", "logs", "--details", "-t", c.name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.Suite().T().Fatalf("fetching logs error: %v", err)
	}

	f, err := os.Create(testLogFilePath)
	if err != nil {
		c.Suite().T().Fatalf("file create error: %v", err)
	}
	fmt.Fprintf(f, string(output))
	f.Close()
}

func (c *Container) log() string {
	cmd := "docker logs " + c.name
	c.Suite().log(cmd)
	o, err := exechelper.CombinedOutput(cmd)
	c.Suite().assertNil(err)
	return string(o)
}

func (c *Container) stop() error {
	if c.vppInstance != nil && c.vppInstance.apiChannel != nil {
		c.vppInstance.saveLogs()
		c.vppInstance.disconnect()
	}
	c.vppInstance = nil
	c.saveLogs()
	return exechelper.Run("docker stop " + c.name + " -t 0")
}
