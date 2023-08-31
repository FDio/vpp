package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"

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
	runDetached      bool
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

	if runDetached, ok := yamlInput["run-detached"]; ok {
		container.runDetached = runDetached.(bool)
	} else {
		container.runDetached = true
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

			container.AddVolume(hostDir, containerDir, isDefaultWorkDir)

		}
	}

	if _, ok := yamlInput["vars"]; ok {
		for _, envVar := range yamlInput["vars"].([]interface{}) {
			envVarMap := envVar.(ContainerConfig)
			name := envVarMap["name"].(string)
			value := envVarMap["value"].(string)
			container.AddEnvVar(name, value)
		}
	}
	return container, nil
}

func (c *Container) GetWorkDirVolume() (res Volume, exists bool) {
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
	if v, ok := c.GetWorkDirVolume(); ok {
		res = v.hostDir
	}
	return
}

func (c *Container) GetContainerWorkDir() (res string) {
	if v, ok := c.GetWorkDirVolume(); ok {
		res = v.containerDir
	}
	return
}

func (c *Container) GetContainerArguments() string {
	args := "--ulimit nofile=90000:90000 --cap-add=all --privileged --network host --rm"
	args += c.GetVolumesAsCliOption()
	args += c.GetEnvVarsAsCliOption()
	args += " --name " + c.name + " " + c.image
	args += " " + c.extraRunningArgs
	return args
}

func (c *Container) Create() error {
	cmd := "docker create " + c.GetContainerArguments()
	c.suite.Log(cmd)
	return exechelper.Run(cmd)
}

func (c *Container) Start() error {
	cmd := "docker start " + c.name
	c.suite.Log(cmd)
	return exechelper.Run(cmd)
}

func (c *Container) PrepareCommand() (string, error) {
	if c.name == "" {
		return "", fmt.Errorf("run container failed: name is blank")
	}

	cmd := "docker run "
	if c.runDetached {
		cmd += " -d"
	}
	cmd += " " + c.GetContainerArguments()

	c.suite.Log(cmd)
	return cmd, nil
}

func (c *Container) CombinedOutput() (string, error) {
	cmd, err := c.PrepareCommand()
	if err != nil {
		return "", err
	}

	byteOutput, err := exechelper.CombinedOutput(cmd)
	return string(byteOutput), err
}

func (c *Container) Run() error {
	cmd, err := c.PrepareCommand()
	if err != nil {
		return err
	}

	return exechelper.Run(cmd)
}

func (c *Container) AddVolume(hostDir string, containerDir string, isDefaultWorkDir bool) {
	var volume Volume
	volume.hostDir = hostDir
	volume.containerDir = containerDir
	volume.isDefaultWorkDir = isDefaultWorkDir
	c.volumes[hostDir] = volume
}

func (c *Container) GetVolumesAsCliOption() string {
	cliOption := ""

	if len(c.volumes) > 0 {
		for _, volume := range c.volumes {
			cliOption += fmt.Sprintf(" -v %s:%s", volume.hostDir, volume.containerDir)
		}
	}

	return cliOption
}

func (c *Container) AddEnvVar(name string, value string) {
	c.envVars[name] = value
}

func (c *Container) GetEnvVarsAsCliOption() string {
	cliOption := ""
	if len(c.envVars) == 0 {
		return cliOption
	}

	for name, value := range c.envVars {
		cliOption += fmt.Sprintf(" -e %s=%s", name, value)
	}
	return cliOption
}

func (c *Container) NewVppInstance(cpus []int, additionalConfigs ...Stanza) (*VppInstance, error) {
	vpp := new(VppInstance)
	vpp.container = c
	vpp.cpus = cpus
	vpp.additionalConfig = append(vpp.additionalConfig, additionalConfigs...)
	c.vppInstance = vpp
	return vpp, nil
}

func (c *Container) Copy(sourceFileName string, targetFileName string) error {
	cmd := exec.Command("docker", "cp", sourceFileName, c.name+":"+targetFileName)
	return cmd.Run()
}

func (c *Container) CreateFile(destFileName string, content string) error {
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
	c.Copy(f.Name(), destFileName)
	return nil
}

/*
 * Executes in detached mode so that the started application can continue to run
 * without blocking execution of test
 */
func (c *Container) ExecServer(command string, arguments ...any) {
	serverCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := "docker exec -d" + c.GetEnvVarsAsCliOption() +
		" " + c.name + " " + serverCommand
	c.suite.T().Helper()
	c.suite.Log(containerExecCommand)
	c.suite.AssertNil(exechelper.Run(containerExecCommand))
}

func (c *Container) Exec(command string, arguments ...any) string {
	cliCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := "docker exec" + c.GetEnvVarsAsCliOption() +
		" " + c.name + " " + cliCommand
	c.suite.T().Helper()
	c.suite.Log(containerExecCommand)
	byteOutput, err := exechelper.CombinedOutput(containerExecCommand)
	c.suite.AssertNil(err)
	return string(byteOutput)
}

func (c *Container) GetLogDirPath() string {
	testId := c.suite.GetTestId()
	testName := c.suite.T().Name()
	logDirPath := logDir + testName + "/" + testId + "/"

	cmd := exec.Command("mkdir", "-p", logDirPath)
	if err := cmd.Run(); err != nil {
		c.suite.T().Fatalf("mkdir error: %v", err)
	}

	return logDirPath
}

func (c *Container) SaveLogs() {
	cmd := exec.Command("docker", "inspect", "--format='{{.State.Status}}'", c.name)
	if output, _ := cmd.CombinedOutput(); !strings.Contains(string(output), "running") {
		return
	}

	testLogFilePath := c.GetLogDirPath() + "container-" + c.name + ".log"

	cmd = exec.Command("docker", "logs", "--details", "-t", c.name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.suite.T().Fatalf("fetching logs error: %v", err)
	}

	f, err := os.Create(testLogFilePath)
	if err != nil {
		c.suite.T().Fatalf("file create error: %v", err)
	}
	fmt.Fprint(f, string(output))
	f.Close()
}

func (c *Container) Log() string {
	cmd := "docker logs " + c.name
	c.suite.Log(cmd)
	o, err := exechelper.CombinedOutput(cmd)
	c.suite.AssertNil(err)
	return string(o)
}

func (c *Container) Stop() error {
	if c.vppInstance != nil && c.vppInstance.apiChannel != nil {
		c.vppInstance.SaveLogs()
		c.vppInstance.Disconnect()
	}
	c.vppInstance = nil
	c.SaveLogs()
	return exechelper.Run("docker stop " + c.name + " -t 0")
}

func (c *Container) CreateConfig(targetConfigName string, templateName string, values any) {
	template := template.Must(template.ParseFiles(templateName))

	f, err := os.CreateTemp("/tmp/hs-test/", "hst-config")
	c.suite.AssertNil(err)
	defer os.Remove(f.Name())

	err = template.Execute(f, values)
	c.suite.AssertNil(err)

	err = f.Close()
	c.suite.AssertNil(err)

	c.Copy(f.Name(), targetConfigName)
}

func init() {
	cmd := exec.Command("mkdir", "-p", logDir)
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}
