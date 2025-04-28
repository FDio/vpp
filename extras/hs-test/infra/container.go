package hst

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/docker/go-units"

	"github.com/cilium/cilium/pkg/sysctl"
	containerTypes "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/pkg/stdcopy"
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
	ID               string
	Image            string
	ExtraRunningArgs string
	Volumes          map[string]Volume
	EnvVars          map[string]string
	VppInstance      *VppInstance
	AllocatedCpus    []int
	ctx              context.Context
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
	container.ctx = context.Background()

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
	args += c.getVolumesAsCliOption()
	args += c.getEnvVarsAsCliOption()
	if *VppSourceFileDir != "" {
		args += fmt.Sprintf(" -v %s:%s", *VppSourceFileDir, *VppSourceFileDir)
	}
	args += " --name " + c.Name + " " + c.Image
	args += " " + c.ExtraRunningArgs
	return args
}

func (c *Container) PullDockerImage(name string, ctx context.Context) {
	// "func (*Client) ImagePull" doesn't work, returns "No such image"
	c.Suite.Log("Pulling image: " + name)
	_, err := exechelper.CombinedOutput("docker pull " + name)
	c.Suite.AssertNil(err)
}

// Creates a container
func (c *Container) Create() error {
	var sliceOfImageNames []string
	images, err := c.Suite.Docker.ImageList(c.ctx, image.ListOptions{})
	c.Suite.AssertNil(err)

	for _, image := range images {
		if len(image.RepoTags) == 0 {
			continue
		}
		sliceOfImageNames = append(sliceOfImageNames, strings.Split(image.RepoTags[0], ":")[0])
	}
	if !slices.Contains(sliceOfImageNames, c.Image) {
		c.PullDockerImage(c.Image, c.ctx)
	}

	c.allocateCpus()
	cpuSet := fmt.Sprintf("%d-%d", c.AllocatedCpus[0], c.AllocatedCpus[len(c.AllocatedCpus)-1])
	resp, err := c.Suite.Docker.ContainerCreate(
		c.ctx,
		&containerTypes.Config{
			Hostname: c.Name,
			Image:    c.Image,
			Env:      c.getEnvVars(),
			Cmd:      strings.Split(c.ExtraRunningArgs, " "),
		},
		&containerTypes.HostConfig{
			Resources: containerTypes.Resources{
				Ulimits: []*units.Ulimit{
					{
						Name: "nofile",
						Soft: 90000,
						Hard: 90000,
					},
				},
				CpusetCpus: cpuSet,
			},
			CapAdd:      []string{"ALL"},
			Privileged:  true,
			NetworkMode: "host",
			Binds:       c.getVolumesAsSlice(),
		},
		nil,
		nil,
		c.Name,
	)
	c.ID = resp.ID
	return err
}

func (c *Container) allocateCpus() {
	c.Suite.StartedContainers = append(c.Suite.StartedContainers, c)
	c.AllocatedCpus = c.Suite.AllocateCpus(c.Name)
	c.Suite.Log("Allocated CPUs " + fmt.Sprint(c.AllocatedCpus) + " to container " + c.Name)
}

// Starts a container
func (c *Container) Start() error {
	var err error
	var nTries int

	for nTries = 0; nTries < 5; nTries++ {
		err = c.Suite.Docker.ContainerStart(c.ctx, c.ID, containerTypes.StartOptions{})
		if err == nil {
			continue
		}
		c.Suite.Log("Error while starting " + c.Name + ". Retrying...")
		time.Sleep(1 * time.Second)
	}
	if nTries >= 5 {
		return err
	}

	// wait for container to start
	time.Sleep(1 * time.Second)

	// check if container exited right after startup
	containers, err := c.Suite.Docker.ContainerList(c.ctx, containerTypes.ListOptions{
		All:     true,
		Filters: filters.NewArgs(filters.Arg("name", c.Name)),
	})
	if err != nil {
		return err
	}
	if containers[0].State == "exited" {
		c.Suite.Log("Container details: " + fmt.Sprint(containers[0]))
		return fmt.Errorf("Container %s exited: '%s'", c.Name, containers[0].Status)
	}

	return err
}

func (c *Container) GetOutput() (string, string) {
	// Wait for the container to finish executing
	statusCh, errCh := c.Suite.Docker.ContainerWait(c.ctx, c.ID, containerTypes.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		c.Suite.AssertNil(err)
	case <-statusCh:
	}

	// Get the logs from the container
	logOptions := containerTypes.LogsOptions{ShowStdout: true, ShowStderr: true}
	logReader, err := c.Suite.Docker.ContainerLogs(c.ctx, c.ID, logOptions)
	c.Suite.AssertNil(err)
	defer logReader.Close()

	var stdoutBuf, stderrBuf bytes.Buffer

	// Use stdcopy.StdCopy to demultiplex the multiplexed stream
	_, err = stdcopy.StdCopy(&stdoutBuf, &stderrBuf, logReader)
	c.Suite.AssertNil(err)

	stdout := stdoutBuf.String()
	stderr := stderrBuf.String()
	return stdout, stderr
}

func (c *Container) prepareCommand() (string, error) {
	if c.Name == "" {
		return "", fmt.Errorf("run container failed: name is blank")
	}

	cmd := "docker exec "
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

// Creates and starts a container
func (c *Container) Run() {
	c.Suite.AssertNil(c.Create())
	c.Suite.AssertNil(c.Start())
}

func (c *Container) addVolume(hostDir string, containerDir string, isDefaultWorkDir bool) {
	var volume Volume
	volume.HostDir = strings.Replace(hostDir, "volumes", c.Suite.GetTestId()+"/"+"volumes", 1)
	volume.ContainerDir = containerDir
	volume.IsDefaultWorkDir = isDefaultWorkDir
	c.Volumes[hostDir] = volume
}

func (c *Container) getVolumesAsSlice() []string {
	var volumeSlice []string

	if *VppSourceFileDir != "" {
		volumeSlice = append(volumeSlice, fmt.Sprintf("%s:%s", *VppSourceFileDir, *VppSourceFileDir))
	}

	core_pattern, err := sysctl.Read("kernel.core_pattern")
	if err == nil {
		if len(core_pattern) > 0 && core_pattern[0] != '|' {
			index := strings.LastIndex(core_pattern, "/")
			if index == -1 {
				c.Suite.Log("'core_pattern' isn't set to an absolute path. Core dump check will not work.")
			} else {
				core_pattern = core_pattern[:index]
				volumeSlice = append(volumeSlice, c.Suite.getLogDirPath()+":"+core_pattern)
			}
		} else {
			c.Suite.Log(fmt.Sprintf("core_pattern \"%s\" starts with pipe, ignoring", core_pattern))
		}
	} else {
		c.Suite.Log(err)
	}

	if len(c.Volumes) > 0 {
		for _, volume := range c.Volumes {
			volumeSlice = append(volumeSlice, fmt.Sprintf("%s:%s", volume.HostDir, volume.ContainerDir))
		}
	}
	return volumeSlice
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

func (c *Container) getEnvVars() []string {
	var envVars []string
	if len(c.EnvVars) == 0 {
		return envVars
	}

	for name, value := range c.EnvVars {
		envVars = append(envVars, fmt.Sprintf("%s=%s", name, value))
	}
	return envVars
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

func (c *Container) CreateFileInWorkDir(fileName string, contents string) error {
	file, err := os.Create(c.GetHostWorkDir() + "/" + fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write([]byte(contents))
	if err != nil {
		return err
	}
	return nil
}

func (c *Container) GetFile(sourceFileName, targetFileName string) error {
	cmd := exec.Command("docker", "cp", c.Name+":"+sourceFileName, targetFileName)
	return cmd.Run()
}

/*
 * Executes in detached mode so that the started application can continue to run
 * without blocking execution of test
 */
func (c *Container) ExecServer(useEnvVars bool, command string, arguments ...any) {
	var envVars string
	serverCommand := fmt.Sprintf(command, arguments...)
	if useEnvVars {
		envVars = c.getEnvVarsAsCliOption()
	} else {
		envVars = ""
	}
	containerExecCommand := fmt.Sprintf("docker exec -d %s %s %s", envVars, c.Name, serverCommand)
	GinkgoHelper()
	c.Suite.Log(containerExecCommand)
	c.Suite.AssertNil(exechelper.Run(containerExecCommand))
}

func (c *Container) Exec(useEnvVars bool, command string, arguments ...any) (string, error) {
	var envVars string
	serverCommand := fmt.Sprintf(command, arguments...)
	if useEnvVars {
		envVars = c.getEnvVarsAsCliOption()
	} else {
		envVars = ""
	}
	containerExecCommand := fmt.Sprintf("docker exec %s %s %s", envVars, c.Name, serverCommand)
	GinkgoHelper()
	c.Suite.Log(containerExecCommand)
	byteOutput, err := exechelper.CombinedOutput(containerExecCommand)
	return string(byteOutput), err
}

func (c *Container) saveLogs() {
	testLogFilePath := c.Suite.getLogDirPath() + "container-" + c.Name + ".log"

	logs, err := c.log(0)
	if err != nil {
		c.Suite.Log(err)
		return
	}

	f, err := os.Create(testLogFilePath)
	if err != nil {
		c.Suite.Log(err)
		return
	}
	defer f.Close()
	fmt.Fprint(f, logs)
}

// Returns logs from docker containers. Set 'maxLines' to 0 to output the full log.
func (c *Container) log(maxLines int) (string, error) {
	var logOptions containerTypes.LogsOptions
	if maxLines == 0 {
		logOptions = containerTypes.LogsOptions{ShowStdout: true, ShowStderr: true, Details: true, Timestamps: true}
	} else {
		logOptions = containerTypes.LogsOptions{ShowStdout: true, ShowStderr: true, Details: true, Tail: strconv.Itoa(maxLines)}
	}

	out, err := c.Suite.Docker.ContainerLogs(c.ctx, c.ID, logOptions)
	if err != nil {
		c.Suite.Log(err)
		return "", err
	}
	defer out.Close()

	var stdoutBuf, stderrBuf bytes.Buffer

	_, err = stdcopy.StdCopy(&stdoutBuf, &stderrBuf, out)
	if err != nil {
		c.Suite.Log(err)
	}

	stdout := stdoutBuf.String()
	stderr := stderrBuf.String()

	re := regexp.MustCompile("(?m)^.*==> /dev/null <==.*$[\r\n]+")
	stdout = re.ReplaceAllString(stdout, "")

	re = regexp.MustCompile("(?m)^.*tail: cannot open '' for reading: No such file or directory.*$[\r\n]+")
	stderr = re.ReplaceAllString(stderr, "")

	return stdout + stderr, err
}

func (c *Container) stop() error {
	if c.VppInstance != nil && c.VppInstance.ApiStream != nil {
		c.VppInstance.saveLogs()
		c.VppInstance.Disconnect()
		c.VppInstance.Stop()
	}
	timeout := 0
	c.VppInstance = nil
	c.saveLogs()
	c.Suite.Log("Stopping container " + c.Name)
	if c.Suite.CoverageRun {
		timeout = 3
	}
	if err := c.Suite.Docker.ContainerStop(c.ctx, c.ID, containerTypes.StopOptions{Timeout: &timeout}); err != nil {
		return err
	}
	return nil
}

func (c *Container) CreateConfigFromTemplate(targetConfigName string, templateName string, values any) {
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
