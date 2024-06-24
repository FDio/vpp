package hst

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"
	"time"

	"github.com/edwarnicke/exechelper"
	. "github.com/onsi/ginkgo/v2"
)

const (
	logDir    string = "/tmp/hs-test/"
	volumeDir string = "/volumes"
)

var (
	workDir, _ = os.Getwd()
)

type Volume struct {
	HostDir          string
	ContainerDir     string
	IsDefaultWorkDir bool
}

type Container struct {
	Suite            *HstSuite
	IsOptional       bool
	RunDetached      bool
	Name             string
	Image            string
	ExtraRunningArgs string
	Volumes          map[string]Volume
	EnvVars          map[string]string
	VppInstance      *VppInstance
	AllocatedCpus    []int
}

func newContainer(suite *HstSuite, yamlInput ContainerConfig) (*Container, error) {
	containerName := yamlInput["name"].(string)
	if len(containerName) == 0 {
		err := fmt.Errorf("container name must not be blank")
		return nil, err
	}

	var container = new(Container)
	container.Volumes = make(map[string]Volume)
	container.EnvVars = make(map[string]string)
	container.Name = containerName
	container.Suite = suite

	if Image, ok := yamlInput["image"]; ok {
		container.Image = Image.(string)
	} else {
		container.Image = "hs-test/vpp"
	}

	if args, ok := yamlInput["extra-args"]; ok {
		container.ExtraRunningArgs = args.(string)
	} else {
		container.ExtraRunningArgs = ""
	}

	if isOptional, ok := yamlInput["is-optional"]; ok {
		container.IsOptional = isOptional.(bool)
	} else {
		container.IsOptional = false
	}

	if runDetached, ok := yamlInput["run-detached"]; ok {
		container.RunDetached = runDetached.(bool)
	} else {
		container.RunDetached = true
	}

	if _, ok := yamlInput["volumes"]; ok {
		workingVolumeDir := logDir + suite.GetCurrentTestName() + volumeDir
		workDirReplacer := strings.NewReplacer("$HST_DIR", workDir)
		volDirReplacer := strings.NewReplacer("$HST_VOLUME_DIR", workingVolumeDir)
		for _, volu := range yamlInput["volumes"].([]interface{}) {
			volumeMap := volu.(ContainerConfig)
			hostDir := workDirReplacer.Replace(volumeMap["host-dir"].(string))
			hostDir = volDirReplacer.Replace(hostDir)
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
			container.AddEnvVar(name, value)
		}
	}
	return container, nil
}

func (c *Container) getWorkDirVolume() (res Volume, exists bool) {
	for _, v := range c.Volumes {
		if v.IsDefaultWorkDir {
			res = v
			exists = true
			return
		}
	}
	return
}

func (c *Container) GetHostWorkDir() (res string) {
	if v, ok := c.getWorkDirVolume(); ok {
		res = v.HostDir
	}
	return
}

func (c *Container) GetContainerWorkDir() (res string) {
	if v, ok := c.getWorkDirVolume(); ok {
		res = v.ContainerDir
	}
	return
}

func (c *Container) getContainerArguments() string {
	args := "--ulimit nofile=90000:90000 --cap-add=all --privileged --network host"
	c.allocateCpus()
	args += fmt.Sprintf(" --cpuset-cpus=\"%d-%d\"", c.AllocatedCpus[0], c.AllocatedCpus[len(c.AllocatedCpus)-1])
	args += c.getVolumesAsCliOption()
	args += c.getEnvVarsAsCliOption()
	if *VppSourceFileDir != "" {
		args += fmt.Sprintf(" -v %s:%s", *VppSourceFileDir, *VppSourceFileDir)
	}
	args += " --name " + c.Name + " " + c.Image
	args += " " + c.ExtraRunningArgs
	return args
}

func (c *Container) runWithRetry(cmd string) error {
	nTries := 5
	for i := 0; i < nTries; i++ {
		err := exechelper.Run(cmd)
		if err == nil {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("failed to run container command")
}

func (c *Container) Create() error {
	cmd := "docker create " + c.getContainerArguments()
	c.Suite.Log(cmd)
	return exechelper.Run(cmd)
}

func (c *Container) allocateCpus() {
	c.Suite.StartedContainers = append(c.Suite.StartedContainers, c)
	c.AllocatedCpus = c.Suite.AllocateCpus()
	c.Suite.Log("Allocated CPUs " + fmt.Sprint(c.AllocatedCpus) + " to container " + c.Name)
}

func (c *Container) Start() error {
	cmd := "docker start " + c.Name
	c.Suite.Log(cmd)
	return c.runWithRetry(cmd)
}

func (c *Container) prepareCommand() (string, error) {
	if c.Name == "" {
		return "", fmt.Errorf("run container failed: name is blank")
	}

	cmd := "docker run "
	if c.RunDetached {
		cmd += " -d"
	}

	cmd += " " + c.getContainerArguments()

	c.Suite.Log(cmd)
	return cmd, nil
}

func (c *Container) CombinedOutput() (string, error) {
	cmd, err := c.prepareCommand()
	if err != nil {
		return "", err
	}

	byteOutput, err := exechelper.CombinedOutput(cmd)
	return string(byteOutput), err
}

func (c *Container) Run() error {
	cmd, err := c.prepareCommand()
	if err != nil {
		return err
	}
	return c.runWithRetry(cmd)
}

func (c *Container) addVolume(hostDir string, containerDir string, isDefaultWorkDir bool) {
	var volume Volume
	volume.HostDir = hostDir
	volume.ContainerDir = containerDir
	volume.IsDefaultWorkDir = isDefaultWorkDir
	c.Volumes[hostDir] = volume
}

func (c *Container) getVolumesAsCliOption() string {
	cliOption := ""

	if len(c.Volumes) > 0 {
		for _, volume := range c.Volumes {
			cliOption += fmt.Sprintf(" -v %s:%s", volume.HostDir, volume.ContainerDir)
		}
	}

	return cliOption
}

func (c *Container) AddEnvVar(name string, value string) {
	c.EnvVars[name] = value
}

func (c *Container) getEnvVarsAsCliOption() string {
	cliOption := ""
	if len(c.EnvVars) == 0 {
		return cliOption
	}

	for name, value := range c.EnvVars {
		cliOption += fmt.Sprintf(" -e %s=%s", name, value)
	}
	return cliOption
}

func (c *Container) newVppInstance(cpus []int, additionalConfigs ...Stanza) (*VppInstance, error) {
	vpp := new(VppInstance)
	vpp.Container = c
	vpp.Cpus = cpus
	vpp.setDefaultCpuConfig()
	vpp.AdditionalConfig = append(vpp.AdditionalConfig, additionalConfigs...)
	c.VppInstance = vpp
	return vpp, nil
}

func (c *Container) copy(sourceFileName string, targetFileName string) error {
	cmd := exec.Command("docker", "cp", sourceFileName, c.Name+":"+targetFileName)
	return cmd.Run()
}

func (c *Container) CreateFile(destFileName string, content string) error {
	f, err := os.CreateTemp("/tmp", "hst-config"+c.Suite.Ppid)
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
func (c *Container) ExecServer(command string, arguments ...any) {
	serverCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := "docker exec -d" + c.getEnvVarsAsCliOption() +
		" " + c.Name + " " + serverCommand
	GinkgoHelper()
	c.Suite.Log(containerExecCommand)
	c.Suite.AssertNil(exechelper.Run(containerExecCommand))
}

func (c *Container) Exec(command string, arguments ...any) string {
	cliCommand := fmt.Sprintf(command, arguments...)
	containerExecCommand := "docker exec" + c.getEnvVarsAsCliOption() +
		" " + c.Name + " " + cliCommand
	GinkgoHelper()
	c.Suite.Log(containerExecCommand)
	byteOutput, err := exechelper.CombinedOutput(containerExecCommand)
	c.Suite.AssertNil(err, fmt.Sprint(err))
	return string(byteOutput)
}

func (c *Container) getLogDirPath() string {
	testId := c.Suite.GetTestId()
	testName := c.Suite.GetCurrentTestName()
	logDirPath := logDir + testName + "/" + testId + "/"

	cmd := exec.Command("mkdir", "-p", logDirPath)
	if err := cmd.Run(); err != nil {
		Fail("mkdir error: " + fmt.Sprint(err))
	}

	return logDirPath
}

func (c *Container) saveLogs() {
	testLogFilePath := c.getLogDirPath() + "container-" + c.Name + ".log"

	cmd := exec.Command("docker", "logs", "--details", "-t", c.Name)
	c.Suite.Log(cmd)
	output, err := cmd.CombinedOutput()
	if err != nil {
		c.Suite.Log(err)
	}

	f, err := os.Create(testLogFilePath)
	if err != nil {
		Fail("file create error: " + fmt.Sprint(err))
	}
	fmt.Fprint(f, string(output))
	f.Close()
}

// Outputs logs from docker containers. Set 'maxLines' to 0 to output the full log.
func (c *Container) log(maxLines int) (string, error) {
	var cmd string
	if maxLines == 0 {
		cmd = "docker logs " + c.Name
	} else {
		cmd = fmt.Sprintf("docker logs --tail %d %s", maxLines, c.Name)
	}

	c.Suite.Log(cmd)
	o, err := exechelper.CombinedOutput(cmd)
	return string(o), err
}

func (c *Container) stop() error {
	if c.VppInstance != nil && c.VppInstance.ApiStream != nil {
		c.VppInstance.saveLogs()
		c.VppInstance.Disconnect()
	}
	c.VppInstance = nil
	c.saveLogs()
	c.Suite.Log("docker stop " + c.Name + " -t 0")
	return exechelper.Run("docker stop " + c.Name + " -t 0")
}

func (c *Container) CreateConfig(targetConfigName string, templateName string, values any) {
	template := template.Must(template.ParseFiles(templateName))

	f, err := os.CreateTemp(logDir, "hst-config")
	c.Suite.AssertNil(err, err)
	defer os.Remove(f.Name())

	err = template.Execute(f, values)
	c.Suite.AssertNil(err, err)

	err = f.Close()
	c.Suite.AssertNil(err, err)

	c.copy(f.Name(), targetConfigName)
}

func init() {
	cmd := exec.Command("mkdir", "-p", logDir)
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}
